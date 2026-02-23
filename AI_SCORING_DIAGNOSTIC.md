# AI Match Score Not Generating - Root Cause Analysis

## Issue Summary
AI Match Score does not generate on application submission despite code being in place.

## Root Cause Analysis

### 1. Code Flow is Correct ✅
The application submission flow is properly implemented:
- `apply()` route at line 3613 receives applications
- Line 3699 calls `_rebuild_ai_summary_and_tags(s, cand, doc=doc, job=job, appn=appn)`
- This function (line 1414) extracts CV text, generates AI summary, and **calls AI scoring when job is provided**
- Line 3699 **DOES pass the job parameter** correctly

### 2. AI Scoring Function Exists ✅
The `ai_score_with_explanation()` function is fully implemented:
- Located at line 1751
- Blends GPT-4o-mini scoring with heuristic analysis
- Returns score, explanation, and bullets

### 3. THE ACTUAL PROBLEM ❌
**The OpenAI API key is not configured in Railway environment variables!**

Evidence:
```python
# Line 46 in app.py
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# Line 155 in app.py - Returns None if key is missing
if not OPENAI_API_KEY or OPENAI_API_KEY.startswith("sk-your-") or OPENAI_API_KEY == "your_openai_api_key_here":
    return None
```

When `get_openai_client()` returns `None`:
- `_gpt_score_and_rationale()` returns `(0, [])` (line 1711)
- AI scoring fails silently
- Only heuristic scoring is used
- No AI explanation is generated

### 4. Verification Steps

Check if OPENAI_API_KEY is set in Railway:
1. Go to Railway Dashboard
2. Select your project → web service
3. Click "Variables" tab
4. Look for `OPENAI_API_KEY`

## Solution

### Option 1: Add OpenAI API Key to Railway (Recommended)

**Step-by-step:**

1. **Get your OpenAI API key:**
   - Go to https://platform.openai.com/api-keys
   - Create a new secret key
   - Copy it immediately (you won't see it again)

2. **Add to Railway environment:**
   - Railway Dashboard → Your Project → web service
   - Click "Variables" tab
   - Click "+ New Variable"
   - Name: `OPENAI_API_KEY`
   - Value: `sk-proj-...` (your actual key)
   - Click "Add"

3. **Railway will auto-redeploy** - wait 2-3 minutes

4. **Test:**
   - Submit a new application
   - Check the application details
   - AI Match Score should now appear

### Option 2: Add Fallback Behavior (Quick Fix)

If you don't have an OpenAI API key yet, we can make the system more graceful:

```python
# In _rebuild_ai_summary_and_tags(), around line 1540
if job and target_app:
    client = get_openai_client()
    if client:
        try:
            result = ai_score_with_explanation(job.description or "", cv_text or cand.skills or "")
            target_app.ai_score = result["final"]
            target_app.ai_explanation = result["explanation"][:7999]
        except Exception as e:
            current_app.logger.exception("AI scoring failed: %s", e)
            # Fallback: Use only heuristic scoring
            heur = _heuristic_components(job.description or "", cv_text or cand.skills or "")
            target_app.ai_score = heur["score"]
            target_app.ai_explanation = f"Score based on keyword matching. Top matches: {', '.join(heur['overlap'][:5])}"
    else:
        # No OpenAI client - use heuristic only
        current_app.logger.warning("OpenAI API key not configured - using heuristic scoring only")
        heur = _heuristic_components(job.description or "", cv_text or cand.skills or "")
        target_app.ai_score = heur["score"]
        target_app.ai_explanation = f"Score based on keyword matching. Configure OPENAI_API_KEY for AI-powered scoring."
```

### Option 3: Add Diagnostic Logging

Add logging to see what's happening:

```python
# At the start of _rebuild_ai_summary_and_tags()
current_app.logger.info(f"🔍 Starting AI rebuild for candidate {cand.id}, job: {job.id if job else 'None'}")

# Before AI scoring
if job and target_app:
    client = get_openai_client()
    current_app.logger.info(f"🤖 OpenAI client available: {client is not None}")
    if client:
        current_app.logger.info(f"📊 Computing AI score for job {job.id}")
        # ... scoring code
    else:
        current_app.logger.warning("❌ OpenAI API key not configured - skipping AI scoring")
```

## Testing Plan

After adding the API key:

1. **Verify environment variable:**
   ```bash
   # Railway logs should show (in Deploy Logs):
   # "OpenAI client initialized successfully"
   ```

2. **Submit a test application:**
   - Use the public job application form
   - Upload a CV
   - Submit

3. **Check the application:**
   - Go to the job's applications list
   - Click on the new application
   - Verify "AI Match Score" is populated
   - Verify "AI Explanation" shows GPT-generated bullets

4. **Check Railway logs:**
   - Look for scoring-related log messages
   - Verify no OpenAI API errors

## Current Status

- ✅ Code implementation is correct
- ✅ Function calls are properly chained
- ✅ Job parameter is passed correctly
- ❌ **OpenAI API key is missing in Railway environment**
- ❌ AI scoring silently fails
- ⚠️ No user-visible error message

## Recommended Action

**Immediate:** Add `OPENAI_API_KEY` to Railway environment variables

**Follow-up:** Add better error handling and logging so this issue is visible in the future

## Cost Considerations

OpenAI API usage for this app:
- Model: `gpt-4o-mini` (cheapest GPT-4 variant)
- Cost: ~$0.15 per 1M input tokens, ~$0.60 per 1M output tokens
- Per application: ~500 input tokens + ~150 output tokens ≈ $0.00015 per application
- 1000 applications ≈ $0.15

Very affordable for production use.
