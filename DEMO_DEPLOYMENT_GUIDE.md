# ATS Demo Deployment Guide

## 🎯 Overview

This is a **CLEAN, PRODUCTION-READY DEMO** environment of the ATS Onboarding application v7.4, specifically prepared for client demonstrations.

### Key Differences from Development Version:
- ✅ **No test data or real CVs** - Completely clean
- ✅ **Production security settings** - HSTS, proper CSP headers
- ✅ **Debug routes disabled** - No `/__ping` or `/__routes` endpoints
- ✅ **New secret keys** - Fresh cryptographic keys for demo
- ✅ **Sample fictional data** - Professional-looking demo data included
- ✅ **Privacy compliant** - No real PII or GDPR concerns

---

## 🚀 Quick Deployment to Railway

### Prerequisites:
1. Railway account (https://railway.app)
2. GitHub account
3. PostgreSQL database (Railway provides this)

### Step 1: Create GitHub Repository

```bash
# On GitHub, create a new repository named 'ats-demo'
# Then push this code:

cd /home/user/ats-demo
git remote remove origin  # if it exists
git remote add origin https://github.com/YOUR_USERNAME/ats-demo.git
git push -u origin main
```

### Step 2: Create Railway Project

1. Go to https://railway.app/dashboard
2. Click "New Project"
3. Select "Deploy from GitHub repo"
4. Choose `ats-demo` repository
5. Railway will auto-detect Python and start building

### Step 3: Add PostgreSQL Database

1. In your Railway project, click "New"
2. Select "Database" → "Add PostgreSQL"
3. Railway creates database and sets `DATABASE_URL` automatically

### Step 4: Configure Environment Variables

In Railway's "Variables" tab, add these (use RAW Editor):

```bash
# CRITICAL: Production secrets (COPY THESE FROM SECURE NOTE BELOW)
DATABASE_URL=${{Postgres.DATABASE_URL}}
FLASK_SECRET_KEY=N8UG-GrwnY0GOuNsylEfqDXpNes39yyphGXNfDfJ7PU
FLASK_ENV=production

# Optional: Third-party integrations (if you want to demo these features)
OPENAI_API_KEY=your_openai_api_key_here
SUMSUB_APP_TOKEN=your_sumsub_token_here
SUMSUB_SECRET_KEY=your_sumsub_secret_here
HELLOSIGN_API_KEY=your_hellosign_key_here

# Optional: SMTP for email features
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-specific-password
SMTP_FROM=demo@yourcompany.com
```

### Step 5: Run Database Migrations

After first deployment, run migrations in Railway's PostgreSQL service:

1. Click on PostgreSQL service
2. Go to "Query" tab
3. Run these SQL files in order:
   - `migrations/000_create_users_table.sql`
   - `migrations/001_add_security_features.sql`
   - `seed_demo_data.sql` (for demo data)

Or use Railway CLI:
```bash
railway link  # Link to your project
railway run psql $DATABASE_URL -f migrations/000_create_users_table.sql
railway run psql $DATABASE_URL -f migrations/001_add_security_features.sql
railway run psql $DATABASE_URL -f seed_demo_data.sql
```

### Step 6: Verify Deployment

1. Wait 3-4 minutes for deployment
2. Check Railway logs: Look for "Healthcheck succeeded"
3. Visit your app URL: `https://ats-demo-production-xxxx.up.railway.app`
4. Test `/health` endpoint: Should return `{"status":"healthy"}`

---

## 🔐 Demo Login Credentials

After running `seed_demo_data.sql`, you can log in with:

- **Email**: `admin@demo.example.com`
- **Password**: `DemoAdmin2024!`

**IMPORTANT**: Change this password after first login in production!

---

## 📊 Demo Data Included

The `seed_demo_data.sql` script creates:

- **1 Admin User**: `admin@demo.example.com`
- **3 Engagements**: Demo Tech Solutions, Demo Financial Services, Demo Healthcare
- **4 Jobs**: Full Stack Developer, DevOps Engineer, Compliance Manager, Clinical Analyst
- **5 Candidates**: Sarah Johnson, Michael Chen, Emma Williams, James Patel, Sophie Martinez
- **5 Applications**: Various stages (applied, screening, interview scheduled, shortlisted)
- **6 Skills**: React.js, Node.js, AWS, Docker, FCA Regulations, EPR Systems

All data is **completely fictional** and safe for client demonstrations.

---

## 🎨 Custom Domain (Optional but Recommended)

For a professional demo URL:

1. Go to Railway project → Settings → Domains
2. Click "Custom Domain"
3. Add your domain (e.g., `demo.yourcompany.com`)
4. Configure DNS CNAME record:
   ```
   demo.yourcompany.com → your-railway-domain.up.railway.app
   ```
5. Railway automatically provisions SSL certificate

---

## 🔒 Security Checklist

Before sharing with clients, verify:

- [ ] `FLASK_ENV=production` is set
- [ ] `FLASK_SECRET_KEY` is unique (not from docs)
- [ ] Database contains only demo data (no real PII)
- [ ] `/health` endpoint returns 200 OK
- [ ] Debug routes (`/__ping`, `/__routes`) return 404
- [ ] HTTPS is working (Railway handles this automatically)
- [ ] No uploaded test CVs in repository
- [ ] Environment variables are secure (not in .env file)

---

## 🧹 Resetting Demo Data

If you need to reset the demo environment:

```sql
-- In PostgreSQL Query tab
DELETE FROM applications;
DELETE FROM candidate_tags;
DELETE FROM candidates;
DELETE FROM jobs;
DELETE FROM engagements;
DELETE FROM users WHERE email = 'admin@demo.example.com';

-- Then re-run seed_demo_data.sql
```

---

## 🆘 Troubleshooting

### Deployment fails with "Healthcheck failed"
- Check logs: `railway logs`
- Verify `/health` endpoint returns 200
- Ensure `DATABASE_URL` is set correctly

### Database tables don't exist
- Run migrations in order (see Step 5)
- Check PostgreSQL Query tab for error messages

### Can't login with demo credentials
- Ensure `seed_demo_data.sql` was executed
- Check password: `DemoAdmin2024!` (case-sensitive)
- Verify `FLASK_SECRET_KEY` is set

### Pages load but show errors
- Check Railway logs for Python tracebacks
- Verify all environment variables are set
- Ensure PostgreSQL is running

---

## 📞 Support

For deployment issues:
1. Check Railway logs: `railway logs`
2. Review application logs in Railway dashboard
3. Verify all environment variables are set
4. Ensure migrations were run successfully

---

## 🔄 Updating the Demo

When you need to update the demo with new features:

```bash
# On your local machine
cd /home/user/ats-demo
git pull origin main
# Make your changes
git add .
git commit -m "Update demo: describe changes"
git push origin main
```

Railway will automatically redeploy within 3-4 minutes.

---

## 🎯 What to Show Clients

### Recommended Demo Flow:

1. **Dashboard** (`/`) - Overview of active engagements and candidates
2. **Opportunities** (`/opportunities`) - Manage client opportunities
3. **Jobs** - View and create job postings
4. **Candidates** (`/resource-pool`) - Browse candidate database
5. **Applications** - Review candidate applications
6. **Kanban Board** (`/kanban`) - Visual pipeline management
7. **Public Portal** (`/public/jobs`) - Candidate-facing job board

### Features to Highlight:

- ✨ **Multi-tenancy**: Separate engagements for different clients
- 🔍 **Smart Matching**: AI-powered candidate-job matching
- 📝 **Application Tracking**: Full lifecycle management
- 📊 **Reporting**: Engagement financials and KPIs
- 🔐 **Security**: CREST-compliant security features
- 🌐 **Public Portal**: Candidate self-service platform
- ✍️ **E-Signatures**: DocuSign/HelloSign integration

---

## ⚠️ Important Notes

1. **This is a DEMO environment** - Not for production use with real data
2. **Demo credentials are PUBLIC** - Change password if using for extended periods
3. **No real PII** - All data is fictional and safe to show
4. **Separate from production** - Keep this isolated from your main ATS deployment
5. **Reset regularly** - Clear old demo sessions and refresh data between client meetings

---

## 📋 Production Deployment (Separate from Demo)

When ready for actual production deployment:

1. Use the original `ats-onboarding` repository (not this demo)
2. Set up proper authentication and user management
3. Configure production-grade PostgreSQL (not Railway's free tier)
4. Enable proper logging and monitoring
5. Set up regular backups
6. Configure custom domain with SSL
7. Review and update all security settings

**Do NOT use this demo environment for real recruitment data!**

---

## 🏷️ Version Information

- **ATS Version**: v7.4
- **Demo Created**: December 2024
- **Python**: 3.11+
- **Database**: PostgreSQL 16
- **Framework**: Flask 3.0.3
- **Deployment**: Railway (Nixpacks)

---

## 📄 License & Usage

This demo environment is provided for **client demonstrations only**. 

- ✅ Safe to share with prospective clients
- ✅ No real PII or confidential data
- ✅ Fully GDPR compliant for demos
- ❌ Do not use for actual recruitment
- ❌ Do not store real candidate data

---

**Happy Demonstrating! 🎉**
