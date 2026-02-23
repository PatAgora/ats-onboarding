# Quick Summary: Why AI Match Score Isn't Working

## The Problem
AI Match Score doesn't generate because **OpenAI API key is missing**.

## The Fix (3 Easy Steps)

### 1. Get an OpenAI API Key
- Go to: https://platform.openai.com/api-keys
- Click "Create new secret key"
- Copy the key (starts with `sk-proj-...`)

### 2. Add to Railway
- Railway Dashboard → Your Project → web service
- Click "Variables" tab
- Add new variable: `OPENAI_API_KEY` = your key
- Railway will auto-redeploy

### 3. Test
- Visit: https://web-production-5a931.up.railway.app/system/status
- Should show: `"configured": true`
- Submit a test application
- AI Match Score should now appear!

## Cost
~$0.15 per 1,000 applications (very cheap!)

## What I've Done
✅ Added error handling so AI scoring fails gracefully  
✅ Added fallback to keyword matching when OpenAI unavailable  
✅ Added diagnostics page at `/admin/system-diagnostics`  
✅ Added system status API at `/system/status`  
✅ Added detailed logging for debugging  
❌ **Code committed locally but not pushed to GitHub** (auth issue)

## What You Need to Do
1. **Push code to GitHub:** 
   ```bash
   cd /home/user/ats-demo
   git push origin main
   ```
   (Or pull and push from your local machine)

2. **Add OpenAI API key to Railway** (see Step 2 above)

3. **Test that it works** (see Step 3 above)

## Current Behavior
- **Without API key:** Uses simple keyword matching (works but not smart)
- **With API key:** Uses GPT-4o-mini + heuristic blend (smart!)

## Documentation
- Full guide: `AI_SCORING_FIX_GUIDE.md`
- Technical details: `AI_SCORING_DIAGNOSTIC.md`
- Both files in repo root

---

**TL;DR:** Just add `OPENAI_API_KEY` to Railway environment variables and everything will work!
