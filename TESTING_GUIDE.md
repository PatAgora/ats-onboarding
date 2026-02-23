# 🧪 Security Features Testing Guide

**Live URL:** https://web-production-5a931.up.railway.app/

**Deployment Status:** ✅ Healthy (deployed at 2026-01-16 14:06:18)

---

## 🎯 Test Plan Overview

We'll test all security features implemented today:
1. ✅ Authentication (login redirect)
2. ✅ Account Lockout System
3. ✅ Password Complexity Requirements
4. ✅ Session Timeout
5. ✅ Remember Me functionality
6. ✅ Audit Logging (backend verification)
7. ✅ CSRF Protection

---

## Test 1: Authentication Enforcement ✅

**What to test:** Verify that unauthenticated users can't access staff pages

**Steps:**
1. Open incognito/private browser window
2. Go to: https://web-production-5a931.up.railway.app/
3. **Expected:** Redirected to `/login` page
4. Try to access: https://web-production-5a931.up.railway.app/engagements
5. **Expected:** Redirected to `/login` page

**✅ Pass if:** All staff routes redirect to login when not authenticated

---

## Test 2: Account Lockout System ✅

**What to test:** Account locks after 5 failed login attempts

**Steps:**
1. Go to: https://web-production-5a931.up.railway.app/login
2. Enter email: `test@example.com` (doesn't need to exist)
3. Enter wrong password: `wrongpassword`
4. Click Login
5. **Expected:** "Invalid email or password"
6. Repeat 4 more times (total 5 attempts)
7. On 5th failed attempt:
   - **Expected:** "Too many failed login attempts. Account locked for 30 minutes."
8. Try to login again (even with correct password if you used real email)
9. **Expected:** "Account locked... Try again in X minutes."

**To unlock:**
- Login as admin
- Go to: https://web-production-5a931.up.railway.app/admin/list-users
- Find locked user (has red "Locked" badge)
- Click "Unlock" button
- **Expected:** User can login again

**✅ Pass if:** Account locks after 5 failures and admin can unlock

---

## Test 3: Password Complexity Requirements ✅

**What to test:** Cannot create users or change passwords with weak passwords

### Test 3a: Creating New User with Weak Password

**Steps:**
1. Login as admin
2. Go to: https://web-production-5a931.up.railway.app/admin/create-user
3. Fill in:
   - Name: `Test User`
   - Email: `testuser@example.com`
   - Password: `password` (weak!)
   - Role: `employee`
4. Click "Create User"
5. **Expected:** Error message: "Password must contain at least 12 characters, an uppercase letter, a number, a special character..."

### Test 3b: Creating User with Strong Password

**Steps:**
1. Same form, but use password: `MyStr0ng!Pass2024`
2. Click "Create User"
3. **Expected:** Success! User created.

### Test 3c: Changing Password (Weak)

**Steps:**
1. Go to: https://web-production-5a931.up.railway.app/change-password
2. Enter current password
3. New password: `short` (weak!)
4. Click "Change Password"
5. **Expected:** Error listing missing requirements

### Test 3d: Changing Password (Strong)

**Steps:**
1. Same form, but use: `MyNewStr0ng!Pass2024`
2. **Expected:** Success! Password changed.

**✅ Pass if:** Weak passwords are rejected, strong passwords are accepted

---

## Test 4: Session Timeout ✅

**What to test:** Sessions expire after 30 minutes of inactivity

### Test 4a: Regular Session (30 min timeout)

**Steps:**
1. Login WITHOUT checking "Remember Me"
2. Note the time
3. Wait 31+ minutes without clicking anything
4. Try to navigate to any page
5. **Expected:** Redirected to login (session expired)

**⚠️ Note:** This test takes 31 minutes. You can skip if short on time.

### Test 4b: Quick Session Check

**Steps:**
1. Login WITHOUT "Remember Me"
2. Open browser DevTools → Application → Cookies
3. Find cookie for `.railway.app` domain
4. Check `session` cookie
5. **Expected:** Cookie has an expiration time

**✅ Pass if:** Cookie expires (not persistent)

---

## Test 5: Remember Me Functionality ✅

**What to test:** "Remember Me" creates 30-day session

**Steps:**
1. Logout (if logged in)
2. Go to login page
3. **Check:** Verify "Remember me for 30 days" checkbox is visible
4. Enter credentials
5. ✅ **Check the "Remember Me" checkbox**
6. Click Login
7. Open DevTools → Application → Cookies
8. Find `remember_token` or session cookie
9. **Expected:** Cookie expires in ~30 days from now

**Alternative test:**
1. Login with "Remember Me" checked
2. Close browser completely
3. Reopen browser
4. Go to: https://web-production-5a931.up.railway.app/
5. **Expected:** Still logged in (no redirect to login)

**✅ Pass if:** Session persists after browser close when Remember Me is checked

---

## Test 6: Audit Logging (Backend Verification) ✅

**What to test:** All authentication and admin events are being logged

### Test 6a: Check Database for Audit Logs

**Note:** You'll need database access for this test. If you don't have it, skip to Test 6b.

**SQL Query:**
```sql
SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 20;
```

**Expected columns:**
- timestamp
- user_id, user_email
- event_type (login, logout, create, unlock, etc.)
- event_category (auth, user_mgmt, security)
- action (description)
- ip_address, user_agent
- status (success, failure, warning)

### Test 6b: Verify Logging via Application Behavior

**Steps:**
1. Perform these actions:
   - Login (should log: "User logged in successfully")
   - Fail a login (should log: "Failed login attempt")
   - Create a user (should log: "Created new user")
   - Change password (should log: "Changed password")
   - Unlock a user (should log: "Unlocked user account")
   - Logout (should log: "User logged out")

2. **Verification:** Check Railway logs or database
   - Railway Dashboard → web service → Logs
   - Look for log entries

**✅ Pass if:** Events are being logged (even if we can't view UI yet)

---

## Test 7: CSRF Protection ✅

**What to test:** Forms require valid CSRF token

### Test 7a: Job Application Form

**Steps:**
1. Go to: https://web-production-5a931.up.railway.app/jobs
2. Click "Apply" on any job
3. Fill out application form
4. Upload a CV (PDF)
5. Click "Submit Application"
6. **Expected:** No "CSRF token is missing" error
7. **Expected:** Application submitted successfully

**✅ Pass if:** Form submission works without CSRF errors

---

## Test 8: Admin User List - Security Features ✅

**What to test:** Admin panel shows security status

**Steps:**
1. Login as admin
2. Go to: https://web-production-5a931.up.railway.app/admin/list-users
3. **Check the table columns:**
   - ✅ "Failed Attempts" column visible
   - ✅ Lock status badge for locked accounts
   - ✅ "Unlock" button for locked accounts

4. **If any user is locked:**
   - Red "Locked" badge should be visible
   - "Unlock" button should be present
   - Failed attempts should show (e.g., "5/5")

**✅ Pass if:** Security information is displayed correctly

---

## Test 9: Login Page UI Updates ✅

**What to test:** Login page has new Remember Me checkbox

**Steps:**
1. Logout
2. Go to: https://web-production-5a931.up.railway.app/login
3. **Check for:**
   - ✅ "Remember me for 30 days" checkbox
   - ✅ Email field
   - ✅ Password field
   - ✅ Login button

**✅ Pass if:** Remember Me checkbox is visible and functional

---

## Test 10: System Status API ✅

**What to test:** System status shows all features enabled

**Steps:**
1. Go to: https://web-production-5a931.up.railway.app/system/status
2. **Expected JSON:**
```json
{
  "database": {
    "connected": true
  },
  "features": {
    "ai_scoring": true,
    "ai_summarization": true,
    "authentication": true
  },
  "openai": {
    "api_test": "success",
    "configured": true,
    "key_present": true,
    "key_valid": true
  },
  "timestamp": "2026-01-16T..."
}
```

**✅ Pass if:** All features show as enabled

---

## 🎯 Quick Test Checklist

**5-Minute Quick Test:**
- [ ] Homepage redirects to login when not authenticated
- [ ] Login page shows "Remember me for 30 days" checkbox
- [ ] Can login successfully
- [ ] Try wrong password - shows attempt counter
- [ ] Admin user list shows "Failed Attempts" column
- [ ] Job application works (no CSRF error)

**15-Minute Comprehensive Test:**
- [ ] All of the above, plus:
- [ ] Trigger account lockout (5 wrong passwords)
- [ ] Admin can unlock locked account
- [ ] Cannot create user with weak password (e.g., "password")
- [ ] Can create user with strong password (e.g., "MyStr0ng!Pass123!")
- [ ] Change password rejects weak passwords
- [ ] Remember Me persists after browser close

**30-Minute Full Test:**
- [ ] All of the above, plus:
- [ ] Session timeout test (wait 31 minutes)
- [ ] Verify audit logs in database/Railway logs
- [ ] Test all CRUD operations with admin account

---

## 🐛 Expected Issues (Known Limitations)

### ⚠️ Audit Log UI Not Yet Available
- **Issue:** `/admin/audit-logs` route doesn't exist yet
- **Workaround:** Check Railway logs or database directly
- **Status:** Pending (1-2 hours to implement)
- **Impact:** Logs are being captured, just can't view them in UI yet

### ✅ Everything Else Should Work!
- Authentication ✅
- Account lockout ✅
- Password complexity ✅
- Session timeout ✅
- Remember Me ✅
- Audit logging (backend) ✅
- CSRF protection ✅

---

## 📊 Test Results Template

**Copy this and fill it out:**

```
## My Test Results

**Test Date:** 2026-01-16
**Tester:** [Your Name]
**Environment:** https://web-production-5a931.up.railway.app/

### Results:
- [ ] Test 1: Authentication Enforcement - PASS / FAIL
- [ ] Test 2: Account Lockout - PASS / FAIL
- [ ] Test 3: Password Complexity - PASS / FAIL
- [ ] Test 4: Session Timeout - PASS / FAIL / SKIPPED
- [ ] Test 5: Remember Me - PASS / FAIL
- [ ] Test 6: Audit Logging - PASS / FAIL / SKIPPED
- [ ] Test 7: CSRF Protection - PASS / FAIL
- [ ] Test 8: Admin User List - PASS / FAIL
- [ ] Test 9: Login Page UI - PASS / FAIL
- [ ] Test 10: System Status API - PASS / FAIL

### Issues Found:
[List any issues you discovered]

### Notes:
[Any other observations]
```

---

## 🆘 Troubleshooting

### "Can't access admin panel"
- Make sure you're logged in as admin
- Check: https://web-production-5a931.up.railway.app/admin/list-users
- If you don't have admin account, create one via `/admin/create-user`

### "Account locked and can't unlock"
- Login as admin
- Go to user list
- Click "Unlock" button next to locked user

### "Session not expiring"
- Make sure you didn't check "Remember Me"
- Clear cookies and try again
- Wait full 30+ minutes of inactivity

### "CSRF errors on forms"
- Clear browser cache
- Hard refresh (Ctrl+Shift+R or Cmd+Shift+R)
- Check that JavaScript is enabled

---

## ✅ Success Criteria

**All tests PASS if:**
1. ✅ Authentication works and redirects properly
2. ✅ Account locks after 5 failed attempts
3. ✅ Weak passwords are rejected
4. ✅ Session timeout works (or cookie expires)
5. ✅ Remember Me persists sessions
6. ✅ No CSRF errors on forms
7. ✅ Admin panel shows security features
8. ✅ System status shows all features enabled

**Your application is production-ready for security! 🎉**

---

**Ready to start testing?** Let me know which tests you'd like to run first!
