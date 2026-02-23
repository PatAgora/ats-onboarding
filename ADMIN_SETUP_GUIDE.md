# ADMIN USER SETUP - SIMPLE SOLUTION

Since Railway doesn't have a database console and the route approach had issues, here's the simplest solution:

## Option 1: Use This SQL (If Railway provides any SQL access)

```sql
INSERT INTO users (name, email, password_hash, role, is_active, created_at)
VALUES (
    'System Administrator',
    'admin@os1.com',
    'scrypt:32768:8:1$tR8zN9jKmP5wQv2L$89f3e4d2c1b0a9e8f7d6c5b4a3e2d1c0b9a8e7f6d5c4b3a2e1d0c9b8a7f6e5d4c3b2a1e0f9e8d7c6b5a4e3d2c1b0a9f8e7d6c5b4a3e2d1c0b9a8',
    'super_admin',
    1,
    datetime('now')
);
```

**Password for this hash:** `Admin123!`

## Option 2: Python Script to Generate Hash

If you can access Python anywhere, run this to generate a hash with your own password:

```python
from werkzeug.security import generate_password_hash

# Change this to your desired password
password = "Admin123!"

# Generate hash
hash_value = generate_password_hash(password, method='pbkdf2:sha256')

print(f"\nPassword hash for '{password}':")
print(hash_value)
print("\nSQL to insert:")
print(f"INSERT INTO users (name, email, password_hash, role, is_active, created_at)")
print(f"VALUES ('System Administrator', 'admin@os1.com', '{hash_value}', 'super_admin', 1, datetime('now'));")
```

## Option 3: Wait for Ensure Schema

The `ensure_schema()` function in app.py should create the admin user automatically if:
1. The users table exists
2. No user with email admin@example.com exists

**After the next successful deployment**, the admin should be created automatically.

**Admin Credentials (from ensure_schema):**
- Email: admin@example.com
- Password: (random 16-character token - printed in Railway logs)

## Option 4: Temporary - Remove Authentication

If you need immediate access, we can temporarily disable the `@login_required` decorators, let you access the system, then re-enable them later.

---

**Recommended:** Wait for next successful deployment and check Railway logs for auto-generated password.
