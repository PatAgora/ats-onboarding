# 🔑 Admin Login Credentials

## Issue: Default Admin Password is Random

The application creates an admin user during first startup with:
- **Email:** `admin@example.com`
- **Password:** Randomly generated (printed to console on first deploy)

The password is generated using `secrets.token_urlsafe(16)` and displayed in the Railway deployment logs.

---

## ✅ SOLUTION: Create a New Admin User

Since we can't easily access the original random password, let's create a new admin user with a known password.

### **Option 1: Use the Temporary Admin Creation Page** (EASIEST)

The app has a temporary admin user creation endpoint that's currently accessible:

**Steps:**
1. Go to: https://web-production-5a931.up.railway.app/admin/create-user
2. ⚠️ **WAIT** - This route requires authentication!

---

### **Option 2: Check Railway Logs** (If accessible)

**Steps:**
1. Go to Railway Dashboard: https://railway.app/
2. Select your project
3. Click on the "web" service
4. Go to "Deployments" tab
5. Click on the latest deployment
6. Click "View Logs"
7. Search for: "ADMIN USER CREATED"
8. You should see:
   ```
   ================================================================================
   🔐 ADMIN USER CREATED
   ================================================================================
   Email: admin@example.com
   Password: [random-password-here]
   ================================================================================
   ```

---

## ✅ BEST SOLUTION: I'll Create an Admin Route for You

Let me create a special one-time setup route that allows you to create the first admin user without authentication:

### What I'll Add:
- `/setup/admin` route (unauthenticated)
- Only works if no admin users exist
- Creates admin user with your chosen password
- Self-disables after first use

Would you like me to implement this? (5 minutes)

---

## 🔧 TEMPORARY WORKAROUND: Database Access

If you have direct database access (Railway provides this), you can:

**1. Check if admin user exists:**
```sql
SELECT id, name, email, role FROM users WHERE role IN ('admin', 'super_admin');
```

**2. Reset admin password:**
```sql
-- First, generate a hash for your desired password using Python:
-- python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('YourNewPassword123!', method='pbkdf2:sha256'))"

-- Then update the user:
UPDATE users 
SET password_hash = '[hash-from-above]' 
WHERE email = 'admin@example.com';
```

---

## 🎯 RECOMMENDED ACTION

**I recommend Option: Create a setup route**

This will allow you to:
1. Visit `/setup/admin` (no login required)
2. Enter your desired credentials
3. Create admin user
4. Route automatically disables
5. Login with your new credentials

**Should I implement this now?** (5 minutes)

Alternatively, if you can access Railway logs, check them for the original password that was printed during deployment.
