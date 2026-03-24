#!/bin/bash
# Railway startup script for ATS application - WITH DEBUGGING

set -e  # Exit on error

echo "🚀 Starting ATS Application..."
echo "================================"
echo "✓ Python version: $(python3 --version)"
echo "✓ DATABASE_URL: ${DATABASE_URL:0:30}..."
echo "✓ PORT: ${PORT:-8080}"
echo "✓ FLASK_ENV: ${FLASK_ENV:-development}"
echo "✓ GEMINI_API_KEY: ${GEMINI_API_KEY:0:20}... (length: ${#GEMINI_API_KEY})"

# Check critical environment variables
if [ -z "$DATABASE_URL" ]; then
    echo "⚠ WARNING: DATABASE_URL not set, using default SQLite"
fi

if [ -z "$FLASK_SECRET_KEY" ] || [ "$FLASK_SECRET_KEY" = "dev-secret" ]; then
    echo ""
    echo "⚠ WARNING: FLASK_SECRET_KEY not set, using default (INSECURE!)"
fi

# Test app import with detailed error output
echo ""
echo "Testing app import..."
python3 -c "from app import app; print('✓ App import successful')" 2>&1 || {
    echo "❌ App import failed!"
    echo ""
    echo "Attempting detailed import to find error..."
    python3 << 'PYEOF'
import sys
import traceback
try:
    print("Step 1: Importing Flask...")
    from flask import Flask
    print("✓ Flask imported")
    
    print("Step 2: Importing SQLAlchemy...")
    from sqlalchemy import create_engine
    print("✓ SQLAlchemy imported")
    
    print("Step 3: Importing app module...")
    import app
    print("✓ App module imported")
    
    print("Step 4: Getting app object...")
    app_obj = app.app
    print("✓ App object retrieved")
    
except Exception as e:
    print(f"❌ Error during import:")
    traceback.print_exc()
    sys.exit(1)
PYEOF
    
    if [ $? -ne 0 ]; then
        echo ""
        echo "❌ Detailed import also failed. Exiting."
        exit 1
    fi
}

# Demo seed DISABLED — real users are managed manually
echo ""
echo "Demo auto-seed is disabled."

# One-time demo data cleanup (preserves admin@demo.example.com + associate profiles)
echo ""
echo "Running demo data cleanup..."
python3 << 'CLEANEOF'
import os, psycopg2

DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    print("No DATABASE_URL — skipping cleanup.")
    exit(0)

try:
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    cur = conn.cursor()

    # Check if cleanup is needed — skip if already clean
    cur.execute("SELECT COUNT(*) FROM applications")
    apps = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM users WHERE email != 'admin@demo.example.com'")
    demo_users = cur.fetchone()[0]

    if apps == 0 and demo_users == 0:
        print("Already clean — skipping.")
        conn.close()
        exit(0)

    print(f"Cleaning: {apps} applications, {demo_users} demo users to remove...")

    # Delete all transactional demo data in FK-safe order
    cleanup_statements = [
        "DELETE FROM webhook_events",
        "DELETE FROM audit_logs",
        "DELETE FROM trustid_checks",
        "DELETE FROM esign_requests",
        "DELETE FROM shortlists",
        "DELETE FROM applications",
        "DELETE FROM invoices",
        "DELETE FROM jobs",
        "DELETE FROM engagement_plans",
        "DELETE FROM engagements",
        "DELETE FROM opportunities",
        "DELETE FROM candidate_notes",
        "DELETE FROM candidate_tags",
        "DELETE FROM documents",
        "DELETE FROM vetting_check",
        "DELETE FROM reference_requests",
        "DELETE FROM reference_contacts",
        "DELETE FROM employment_history",
        "DELETE FROM address_history",
        "DELETE FROM qualification_records",
        "DELETE FROM declaration_records",
        "DELETE FROM consent_records",
        "DELETE FROM company_details",
        "DELETE FROM candidates WHERE id NOT IN (SELECT candidate_id FROM associate_profiles)",
        "DELETE FROM timesheet_expenses",
        "DELETE FROM timesheet_entries",
        "DELETE FROM timesheets",
        "DELETE FROM timesheet_configs",
        "DELETE FROM password_history WHERE user_id IN (SELECT id FROM users WHERE email != 'admin@demo.example.com')",
        "DELETE FROM users WHERE email != 'admin@demo.example.com'",
    ]

    for stmt in cleanup_statements:
        cur.execute(stmt)

    conn.commit()

    cur.execute("SELECT id, email, role FROM users ORDER BY id")
    rows = cur.fetchall()
    print(f"Cleanup complete. Remaining users:")
    for r in rows:
        print(f"  ID {r[0]}: {r[1]} ({r[2]})")

    cur.execute("SELECT COUNT(*) FROM associate_profiles")
    profiles = cur.fetchone()[0]
    print(f"Associate profiles preserved: {profiles}")

    conn.close()

except Exception as e:
    print(f"Demo cleanup error: {e} — skipping.")
CLEANEOF

# Start application with gunicorn
echo ""
echo "Starting gunicorn..."
echo "================================"

exec gunicorn app:app \
    --bind 0.0.0.0:${PORT:-8080} \
    --workers 4 \
    --timeout 120 \
    --log-level info \
    --access-logfile - \
    --error-logfile -
