#!/bin/bash
# Railway startup script for ATS application - WITH DEBUGGING

set -e  # Exit on error

echo "🚀 Starting ATS Application..."
echo "================================"
echo "✓ Python version: $(python3 --version)"
echo "✓ DATABASE_URL: ${DATABASE_URL:0:30}..."
echo "✓ PORT: ${PORT:-8080}"
echo "✓ FLASK_ENV: ${FLASK_ENV:-development}"
echo "✓ OPENAI_API_KEY: ${OPENAI_API_KEY:0:20}... (length: ${#OPENAI_API_KEY})"

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
