# 🔐 Security Integration Instructions

## ⚠️ IMPORTANT: Manual Integration Required

The security enhancements have been **prepared but NOT integrated** into app.py to avoid breaking your existing application. You need to manually integrate these components.

---

## 📋 Integration Checklist

### ✅ Phase 1: Already Complete
- [x] Security middleware created (`security.py`)
- [x] MFA templates created (`templates/mfa_*.html`)
- [x] Railway deployment files created
- [x] Dependencies updated (`requirements.txt`)
- [x] Documentation created

### 🔧 Phase 2: Manual Integration Required

#### Step 1: Add Security Imports to app.py

Add these imports after line 1 in `app.py`:

```python
# Security enhancements - CREST compliance
from security import (
    init_security, audit_log, require_mfa,
    generate_mfa_secret, generate_mfa_qr_code, verify_mfa_token,
    generate_magic_link_token, verify_magic_link_token,
    validate_file_upload, sanitize_filename,
    validate_password_strength, add_security_headers
)
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
```

#### Step 2: Initialize Security (After Line 205)

Add after `app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)`:

```python
# Initialize Sentry for error monitoring
sentry_dsn = os.getenv('SENTRY_DSN')
if sentry_dsn:
    sentry_sdk.init(
        dsn=sentry_dsn,
        integrations=[FlaskIntegration()],
        traces_sample_rate=0.1,
        environment=os.getenv('FLASK_ENV', 'production'),
    )

# Initialize security middleware
limiter = init_security(app)

# Add security headers to all responses
@app.after_request
def after_request(response):
    return add_security_headers(response)
```

#### Step 3: Add MFA Routes

Add these routes **before** the existing login routes (around line 6200):

**File**: Check `security_integration.py` for complete MFA_ROUTES code block

Key routes to add:
- `/mfa/setup` (GET, POST) - MFA setup with QR code
- `/mfa/verify` (GET, POST) - MFA verification
- `/mfa/disable` (POST) - Disable MFA

#### Step 4: Add Magic Link Routes

Add these routes **after** MFA routes:

**File**: Check `security_integration.py` for complete MAGIC_LINK_ROUTES code block

Key routes to add:
- `/candidate/send-magic-link` (POST) - Send magic link email
- `/candidate/login/<token>` (GET) - Authenticate via magic link
- Helper function: `send_magic_link_email()`

#### Step 5: Add Rate Limiting to Existing Routes

Update existing login route (around line 6216):

```python
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")  # ADD THIS LINE
def login():
    # existing code...
```

Update existing signup route:

```python
@app.route("/signup", methods=["GET", "POST"])
@limiter.limit("3 per minute")  # ADD THIS LINE
def signup():
    # existing code...
```

#### Step 6: Add Audit Logging

Add audit logging to critical operations:

```python
# In login route, after successful login:
audit_log("user_login", user_id=current_user.id)

# In logout route:
audit_log("user_logout", user_id=current_user.id)

# After failed login:
audit_log("login_failed", details={"email": email})
```

#### Step 7: Enhance File Upload Security

Update CV upload handler in `public.py` (around line 290):

```python
# Add validation before saving
cv_file = request.files.get("cv_file")
if cv_file:
    is_valid, error_msg = validate_file_upload(cv_file)
    if not is_valid:
        flash(error_msg, "danger")
        return redirect(url_for("public.job_apply", job_id=job_id))
    
    # Save with sanitized filename
    relpath = _save_cv(cv_file)
```

#### Step 8: Add MFA Requirement to Admin Routes

Update sensitive admin routes:

```python
@app.route("/admin/users")
@login_required
@require_mfa  # ADD THIS LINE
def admin_users():
    # existing code...
```

Apply `@require_mfa` to:
- User management routes
- Engagement creation/editing
- Configuration pages
- Financial reports
- Data export functions

#### Step 9: Database Migration

Run this SQL to add MFA support:

```sql
-- Add MFA columns to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled_at TIMESTAMP;

-- Create index for performance
CREATE INDEX IF NOT EXISTS idx_users_mfa ON users(mfa_secret) 
WHERE mfa_secret IS NOT NULL;

-- Create audit log table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id),
    ip_address TEXT,
    user_agent TEXT,
    details TEXT
);

-- Create indexes for audit log queries
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_event ON audit_logs(event_type);
```

---

## 🧪 Testing After Integration

### Test Checklist:

#### 1. Basic Functionality
```bash
# Start app
export FLASK_ENV=development
python app.py

# Test basic routes
curl http://localhost:5000/
curl http://localhost:5000/login
```

#### 2. MFA Setup
- [ ] Login as admin user
- [ ] Visit `/mfa/setup`
- [ ] Scan QR code with Google Authenticator
- [ ] Enter verification code
- [ ] Should see "MFA enabled successfully!"

#### 3. MFA Verification
- [ ] Logout
- [ ] Login again
- [ ] Should redirect to `/mfa/verify`
- [ ] Enter 6-digit code
- [ ] Should access dashboard

#### 4. Magic Link (Candidates)
- [ ] Go to public portal `/jobs`
- [ ] Click "Request magic link"
- [ ] Check logs for magic link URL
- [ ] Click magic link
- [ ] Should be authenticated

#### 5. Rate Limiting
- [ ] Try 6 failed logins rapidly
- [ ] Should get "429 Too Many Requests"
- [ ] Wait 1 minute, should work again

#### 6. Security Headers
```bash
curl -I https://your-app.up.railway.app
# Should see:
# Strict-Transport-Security
# X-Content-Type-Options
# X-Frame-Options
# Content-Security-Policy
```

#### 7. File Upload Validation
- [ ] Try uploading .exe file → Should reject
- [ ] Try uploading 50MB file → Should reject
- [ ] Try uploading PDF → Should accept

#### 8. Audit Logging
```bash
# Check logs
tail -f logs/security_audit.log
# Should see login/logout events
```

---

## 🚨 Common Integration Issues

### Issue 1: Import Errors
**Error**: `ModuleNotFoundError: No module named 'security'`

**Solution**:
```bash
# Ensure security.py is in the same directory as app.py
ls -la /home/user/webapp/security.py

# Reinstall dependencies
pip install -r requirements.txt
```

### Issue 2: Database Column Missing
**Error**: `column users.mfa_secret does not exist`

**Solution**:
```bash
# Run database migration SQL
# For SQLite:
sqlite3 ats.db < migration.sql

# For PostgreSQL:
psql $DATABASE_URL -f migration.sql
```

### Issue 3: Rate Limiting Not Working
**Error**: No rate limiting enforced

**Solution**:
```python
# Ensure limiter is initialized AFTER app creation
limiter = init_security(app)

# Apply decorator to routes
@limiter.limit("5 per minute")
```

### Issue 4: MFA QR Code Not Displaying
**Error**: QR code shows as broken image

**Solution**:
```bash
# Ensure Pillow is installed
pip install Pillow==10.1.0

# Check template for correct src attribute
# Should be: <img src="{{ qr_code }}" />
# qr_code is base64 data URI
```

---

## 📊 Integration Progress Tracker

| Component | Status | File | Line |
|-----------|--------|------|------|
| Security imports | ⏳ Pending | app.py | ~1 |
| Sentry init | ⏳ Pending | app.py | ~205 |
| Security middleware | ⏳ Pending | app.py | ~205 |
| MFA routes | ⏳ Pending | app.py | ~6200 |
| Magic link routes | ⏳ Pending | app.py | ~6300 |
| Rate limiting | ⏳ Pending | app.py | Various |
| Audit logging | ⏳ Pending | app.py | Various |
| File validation | ⏳ Pending | public.py | ~290 |
| MFA decorator | ⏳ Pending | app.py | Various |
| Database migration | ⏳ Pending | SQL | N/A |

**Progress**: 0% (Ready to integrate)

---

## 🎯 Priority Order

1. **CRITICAL** (Do First):
   - [ ] Database migration (MFA columns, audit log table)
   - [ ] Security imports and initialization
   - [ ] Rate limiting on login routes

2. **HIGH** (Do Next):
   - [ ] MFA routes (setup, verify, disable)
   - [ ] Audit logging integration
   - [ ] File upload validation

3. **MEDIUM** (Then):
   - [ ] Magic link authentication
   - [ ] MFA requirement on admin routes
   - [ ] Sentry integration

4. **LOW** (Optional):
   - [ ] Additional security headers customization
   - [ ] IP whitelist for admin access
   - [ ] Advanced audit log queries

---

## ✅ Verification Steps

After completing integration:

```bash
# 1. Run app
export FLASK_ENV=development
python app.py

# 2. Check logs for security initialization
# Should see: "Talisman initialized"
# Should see: "Rate limiter initialized"

# 3. Test security features (see Testing section above)

# 4. Review code changes
git diff app.py
git diff public.py

# 5. Commit changes
git add .
git commit -m "feat: integrate CREST-compliant security enhancements"
git push
```

---

## 📞 Need Help?

**Integration support**: Check each file in `security_integration.py` for complete code blocks

**Testing issues**: See troubleshooting section above

**Deployment questions**: See `DEPLOYMENT_GUIDE.md`

---

## 🎉 After Integration

Once integrated and tested:

1. ✅ Update this file to mark components as complete
2. ✅ Run full security audit
3. ✅ Deploy to Railway
4. ✅ Test in production
5. ✅ Enable MFA for all admin users
6. ✅ Document any custom modifications

---

**Integration Time Estimate**: 2-3 hours  
**Testing Time Estimate**: 1 hour  
**Total**: 3-4 hours

**Good luck! 🚀**
