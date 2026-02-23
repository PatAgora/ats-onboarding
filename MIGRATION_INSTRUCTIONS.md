# Database Migration Required

## Problem
The production database has an old schema with `password` column, but the new code expects `password_hash`.

## Error
```
psycopg2.errors.UndefinedColumn: column users.password_hash does not exist
```

## Solution: Run Database Migration

### Option 1: Using Railway CLI (Recommended)

1. **Get your DATABASE_URL from Railway:**
   - Go to https://railway.app
   - Select your project
   - Click on "PostgreSQL" service
   - Go to "Variables" tab
   - Copy the `DATABASE_URL` value

2. **Run migration locally:**
   ```bash
   cd /home/user/ats-demo
   export DATABASE_URL='your-database-url-here'
   python3 run_migration.py
   ```

### Option 2: Direct SQL (Railway Dashboard)

1. Go to Railway Dashboard → PostgreSQL service → Data tab
2. Run this SQL:

```sql
-- Rename password to password_hash
ALTER TABLE users RENAME COLUMN password TO password_hash;

-- Add security columns
ALTER TABLE users 
  ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP,
  ADD COLUMN IF NOT EXISTS last_login TIMESTAMP,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Create audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    user_id INTEGER,
    user_email VARCHAR(255),
    event_type VARCHAR(50) NOT NULL,
    event_category VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id INTEGER,
    action VARCHAR(255) NOT NULL,
    details TEXT,
    status VARCHAR(20) DEFAULT 'success',
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
```

### Option 3: Quick Fix - Use Existing Password

If you want to login RIGHT NOW without migration, I can temporarily modify the code to use `password` column instead of `password_hash`.

## After Migration

Once the migration completes:
1. Login at: https://web-production-5a931.up.railway.app/login
2. Use existing credentials (check Railway logs for the password)
3. Change your password immediately after first login

## Need Help?

Let me know which option you prefer, and I can help you execute it.
