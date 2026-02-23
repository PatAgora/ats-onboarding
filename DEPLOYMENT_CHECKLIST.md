# 🚀 Quick Deployment Checklist

Use this checklist to ensure a smooth demo deployment to Railway.

## ✅ Pre-Deployment (Do This First)

- [ ] **Create GitHub Repository**
  - Repository name: `ats-demo` (or your preferred name)
  - Visibility: Private (recommended for client demos)
  - Initialize: No (we have code ready)

- [ ] **Push Code to GitHub**
  ```bash
  cd /home/user/ats-demo
  git remote add origin https://github.com/YOUR_USERNAME/ats-demo.git
  git push -u origin main
  ```

## 🏗️ Railway Setup

- [ ] **Create Railway Project**
  - Go to: https://railway.app/dashboard
  - Click: "New Project"
  - Select: "Deploy from GitHub repo"
  - Choose: `ats-demo` repository

- [ ] **Add PostgreSQL Database**
  - In project, click: "New"
  - Select: "Database" → "Add PostgreSQL"
  - Wait for: Database provisioning (1-2 minutes)

- [ ] **Configure Environment Variables**
  - Go to: Your app service → "Variables" → "RAW Editor"
  - Copy/paste from below:
  ```
  DATABASE_URL=${{Postgres.DATABASE_URL}}
  FLASK_SECRET_KEY=N8UG-GrwnY0GOuNsylEfqDXpNes39yyphGXNfDfJ7PU
  FLASK_ENV=production
  ```
  - Click: "Update Variables"
  - Railway will auto-redeploy

## 🗄️ Database Setup

- [ ] **Run Migrations**
  - Option A: Via Railway PostgreSQL Query tab
    1. Click PostgreSQL service → "Query"
    2. Copy/paste `migrations/000_create_users_table.sql`
    3. Click "Run Query"
    4. Copy/paste `migrations/001_add_security_features.sql`
    5. Click "Run Query"
  
  - Option B: Via Railway CLI (if installed)
    ```bash
    railway link  # Link to your project
    railway run psql $DATABASE_URL -f migrations/000_create_users_table.sql
    railway run psql $DATABASE_URL -f migrations/001_add_security_features.sql
    ```

- [ ] **Load Demo Data**
  - In PostgreSQL Query tab:
  - Copy/paste `seed_demo_data.sql`
  - Click "Run Query"
  - Verify: Should create 5 candidates, 4 jobs, 3 engagements

## ✅ Verification

- [ ] **Check Deployment Logs**
  - Go to: App service → "Deployments"
  - Look for: "✓ Starting gunicorn"
  - Look for: "GET /health HTTP/1.1" 200
  - Look for: "[1/1] Healthcheck succeeded"

- [ ] **Test Application URL**
  - Get URL: App service → "Settings" → "Domains"
  - Visit: `https://your-app.up.railway.app`
  - Should see: Login page

- [ ] **Test Health Endpoint**
  - Visit: `https://your-app.up.railway.app/health`
  - Should return: `{"status":"healthy","timestamp":"..."}`

- [ ] **Test Demo Login**
  - Email: `admin@demo.example.com`
  - Password: `DemoAdmin2024!`
  - Should: Successfully log in to dashboard

## 🔒 Security Verification

- [ ] **Verify Production Mode**
  - In Railway Variables: `FLASK_ENV=production` ✓
  - Check logs: No debug messages

- [ ] **Verify Debug Routes Disabled**
  - Visit: `https://your-app.up.railway.app/__ping`
  - Should return: 404 Not Found ✓

  - Visit: `https://your-app.up.railway.app/__routes`
  - Should return: 404 Not Found ✓

- [ ] **Verify HTTPS**
  - URL starts with: `https://` ✓
  - Browser shows: Padlock icon ✓

- [ ] **Verify No Test Data**
  - Check: No real CVs in uploads/ ✓
  - Check: All candidates have `@demo.example.com` emails ✓

## 🎨 Optional: Custom Domain

- [ ] **Configure Custom Domain** (Recommended)
  - Go to: App service → "Settings" → "Domains"
  - Click: "Custom Domain"
  - Enter: `demo.yourcompany.com`
  - Configure DNS: CNAME record pointing to Railway domain
  - Wait: SSL certificate auto-provisioning (5-10 minutes)

## 🎯 Demo Preparation

- [ ] **Test All Key Features**
  - [ ] Dashboard loads
  - [ ] Jobs page works
  - [ ] Candidates page works
  - [ ] Applications page works
  - [ ] Kanban board works
  - [ ] Public job portal works

- [ ] **Prepare Demo Script**
  - [ ] Review demo data (5 candidates, 4 jobs)
  - [ ] Plan workflow demonstration
  - [ ] Prepare talking points for each feature
  - [ ] Note any optional features to highlight

- [ ] **Share with Client**
  - Demo URL: `https://your-demo-url.up.railway.app`
  - Demo Login: `admin@demo.example.com` / `DemoAdmin2024!`
  - Note: Consider changing password for extended use

## ⚠️ Final Checks Before Client Demo

- [ ] Application is responding (200 OK)
- [ ] Login works with demo credentials
- [ ] All pages load without errors
- [ ] Demo data is visible (candidates, jobs, etc.)
- [ ] No debug/test data exposed
- [ ] HTTPS is working properly
- [ ] Custom domain configured (if applicable)

---

## 🆘 Troubleshooting

### Deployment Failed
- Check Railway logs for error messages
- Verify Python dependencies in requirements.txt
- Ensure startup.sh is executable

### Database Connection Error
- Verify DATABASE_URL is set correctly
- Check PostgreSQL service is running
- Ensure migrations were run

### 404 on All Pages
- Check that application started successfully
- Verify Railway health check passed
- Review application logs for startup errors

### Login Doesn't Work
- Ensure seed_demo_data.sql was run
- Verify FLASK_SECRET_KEY is set
- Check password: `DemoAdmin2024!` (case-sensitive)

---

## 📞 Need Help?

Refer to:
- [`DEMO_DEPLOYMENT_GUIDE.md`](./DEMO_DEPLOYMENT_GUIDE.md) - Detailed instructions
- [`README.md`](./README.md) - Project overview and features
- Railway Logs - Check deployment logs for errors
- Railway Docs - https://docs.railway.app

---

**Status**: Ready for deployment! 🚀

**Time to deploy**: ~15-20 minutes (first time)

**Ready for client demo**: After completing all checks above
