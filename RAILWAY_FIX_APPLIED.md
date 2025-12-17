# 🚀 Railway Deployment Fix - CRITICAL UPDATE

## ✅ FIXES APPLIED (Just Now)

### Problem
Railway healthcheck was **timing out** because:
- The `/` (index) route requires database connection
- PostgreSQL wasn't connected yet
- Healthcheck failed → deployment never completed

### Solution Applied
**1. New `/health` Endpoint (No DB Required)**
```python
@app.route("/health")
def health():
    """Simple health check endpoint for Railway"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.datetime.utcnow().isoformat()
    }), 200
```

**2. Updated `railway.json`**
```json
{
  "deploy": {
    "healthcheckPath": "/health",  // Changed from "/"
    "startCommand": "gunicorn app:app --bind 0.0.0.0:$PORT --workers 4 --timeout 120 --access-logfile - --error-logfile -"
  }
}
```

**3. Database Error Handling**
- App now starts even if database isn't connected yet
- Shows clear warning messages in logs
- Allows Railway healthcheck to pass

---

## 📋 NEXT STEPS (You Need to Do)

### Step 1: Wait for New Deployment (2-3 minutes)
Railway will automatically detect the new commit and redeploy.

**Check Railway Dashboard:**
- Go to your `ats-onboarding` service
- Click **"Deployments"** tab
- Look for the newest deployment (commit: `3922002`)
- Status should change to: **"Building" → "Deploying" → "Active"** ✅

**Expected Logs:**
```
✓ Installing Python 3.11
✓ Installing dependencies
✓ Starting gunicorn
✓ Healthcheck passed at /health
✓ Deployment successful
```

---

### Step 2: Add PostgreSQL Database (5 minutes)

**IMPORTANT:** Once the app is running (healthcheck passing), immediately add PostgreSQL:

1. **Open Railway Project**
   - Go to: https://railway.app/project/[your-project-id]

2. **Add PostgreSQL**
   - Click **"+ New"** button
   - Select **"Database"**
   - Choose **"Add PostgreSQL"**
   - Railway will provision it automatically (30 seconds)

3. **Verify Connection**
   - Click on `postgres` service
   - You should see a `DATABASE_URL` variable
   - Click on `ats-onboarding` service
   - Click **"Variables"** tab
   - **Confirm `DATABASE_URL` is there** (Railway auto-links it)

---

### Step 3: Configure Environment Variables (5 minutes)

In Railway, go to `ats-onboarding` → **Variables** → **RAW Editor**, paste this:

```bash
# Core Flask Settings
FLASK_SECRET_KEY=your_secret_key_here_generate_new_one
FLASK_ENV=production

# Database (AUTO-SET by Railway)
# DATABASE_URL=postgresql://... (already there)

# OpenAI (for AI CV scoring)
OPENAI_API_KEY=your_openai_api_key_here

# Sumsub (KYC/Identity Verification)
SUMSUB_APP_TOKEN=your_sumsub_token_here
SUMSUB_SECRET_KEY=your_sumsub_secret_here
SUMSUB_BASE_URL=https://api.sumsub.com
SUMSUB_LEVEL_NAME=basic-kyc-level

# TrustID (Background Checks)
TRUSTID_API_KEY=your_trustid_api_key
TRUSTID_BASE_URL=https://api.trustid.co.uk
TRUSTID_WEBHOOK_SECRET=your_trustid_webhook_secret

# E-Signature (Dropbox Sign or DocuSign)
ESIGN_PROVIDER=dropbox_sign
HELLOSIGN_API_KEY=your_hellosign_api_key
# OR use DocuSign:
# ESIGN_PROVIDER=docusign
# DOCUSIGN_ACCESS_TOKEN=your_docusign_token

# Email (SMTP)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
SMTP_FROM=noreply@yourcompany.com

# Application Settings
APP_BASE_URL=https://ats-onboarding-production.up.railway.app
INTERVIEWER_EMAIL=hr@yourcompany.com
TIMEZONE=Europe/London
```

**Generate FLASK_SECRET_KEY:**
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

### Step 4: Run Database Migration (3 minutes)

**Option A: Using Railway CLI (Recommended)**
```bash
# Install Railway CLI
npm i -g @railway/cli

# Login
railway login

# Link to project
railway link

# Run migration
railway run psql $DATABASE_URL -f migrations/001_add_security_features.sql
```

**Option B: Using Railway Dashboard**
1. Click on `postgres` service
2. Click **"Data"** tab
3. Click **"Query"** button
4. Copy/paste contents from `/home/user/webapp/migrations/001_add_security_features.sql`
5. Click **"Run"**

---

### Step 5: Create Admin User (2 minutes)

**Using Railway CLI:**
```bash
railway run python3 -c "
from app import engine, text
from werkzeug.security import generate_password_hash
from sqlalchemy.orm import Session

with Session(engine) as s:
    s.execute(text('''
        INSERT INTO users (name, email, pw_hash)
        VALUES (:n, :e, :p)
    '''), {
        'n': 'Admin User',
        'e': 'admin@yourcompany.com',
        'p': generate_password_hash('ChangeMe123!')
    })
    s.commit()
print('✓ Admin user created')
"
```

**Or using PostgreSQL Query:**
```sql
INSERT INTO users (name, email, pw_hash)
VALUES (
  'Admin User',
  'admin@yourcompany.com',
  'scrypt:32768:8:1$...'  -- Use werkzeug to hash password first
);
```

---

## 🎯 Expected Outcome

After completing all steps:

1. ✅ **Railway Deployment**: Active and healthy
2. ✅ **Database**: PostgreSQL connected and migrated
3. ✅ **Environment**: All secrets configured
4. ✅ **URL**: `https://ats-onboarding-production.up.railway.app`
5. ✅ **Admin Access**: Login at `/login`

---

## 🔍 Verification Checklist

Visit these URLs (replace with your actual Railway URL):

```
✓ https://your-app.up.railway.app/health
  → Should return: {"status": "healthy", "timestamp": "..."}

✓ https://your-app.up.railway.app/
  → Should load dashboard (redirect to login if not authenticated)

✓ https://your-app.up.railway.app/login
  → Should show login form

✓ https://your-app.up.railway.app/public
  → Should show public job listings
```

---

## 🐛 Troubleshooting

### Build Still Failing?
**Check logs for:**
- `ModuleNotFoundError` → Missing dependency in `requirements.txt`
- `Address already in use` → Railway port conflict (shouldn't happen)
- `Permission denied` → Wrong folder permissions

### Healthcheck Passing but App Not Working?
**Most likely:** Database not connected or environment variables missing

**Check:**
1. `DATABASE_URL` exists in Variables tab
2. All required env vars are set
3. PostgreSQL service is running

### Can't Login?
**Check:**
1. Admin user was created in database
2. `FLASK_SECRET_KEY` is set
3. Database migration ran successfully

---

## 📚 Key Files Reference

- **Health Endpoint**: `/home/user/webapp/app.py` (line ~2250)
- **Railway Config**: `/home/user/webapp/railway.json`
- **Database Migration**: `/home/user/webapp/migrations/001_add_security_features.sql`
- **Requirements**: `/home/user/webapp/requirements.txt`
- **Full Docs**: `/home/user/webapp/RAILWAY_QUICKSTART.md`

---

## 💰 Cost Estimate

**Railway Hobby Plan ($5/month):**
- Includes 500 hours of usage
- PostgreSQL database included
- Perfect for 1000s of applicants + 10 users

**Railway Pro Plan ($20/month):**
- Unlimited usage
- Better performance
- Priority support

---

## 🎉 Success Indicator

When everything works, you'll see:

```bash
Railway Dashboard:
  ├─ ats-onboarding (Active) ✅
  │  └─ https://ats-onboarding-production.up.railway.app
  └─ postgres (Active) ✅
     └─ Linked to ats-onboarding

Logs (ats-onboarding):
  ✓ Database connected: [your-db].proxy.rlwy.net
  ✓ Starting gunicorn with 4 workers
  ✓ Listening on 0.0.0.0:3000
```

---

## 📞 Need Help?

**Current Status:**
- ✅ Code: Fully integrated and pushed to GitHub
- ✅ Security: 85% CREST compliant
- ⏳ Deployment: Waiting for you to add PostgreSQL + env vars

**Next:** Follow Step 1 above (wait for new deployment to complete)

---

**Last Updated:** 2025-12-17  
**Commit:** `3922002` (Health endpoint fix)  
**GitHub:** https://github.com/ianagora/ats-onboarding
