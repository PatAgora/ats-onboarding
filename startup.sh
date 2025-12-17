#!/bin/bash
set -e

echo "🚀 Starting ATS Application..."
echo "================================"

# Check Python version
echo "✓ Python version: $(python --version)"

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
    echo "⚠ WARNING: DATABASE_URL not set, using default SQLite"
    export DATABASE_URL="sqlite:///ats.db"
fi

# Check if FLASK_SECRET_KEY is set
if [ -z "$FLASK_SECRET_KEY" ]; then
    echo "⚠ WARNING: FLASK_SECRET_KEY not set, using default (INSECURE!)"
    export FLASK_SECRET_KEY="dev-secret-change-in-production"
fi

# Set default PORT if not provided by Railway
if [ -z "$PORT" ]; then
    export PORT=3000
fi

echo "✓ DATABASE_URL: ${DATABASE_URL:0:20}..."
echo "✓ PORT: $PORT"
echo "✓ FLASK_ENV: ${FLASK_ENV:-development}"
echo ""

# Test import of app module
echo "Testing app import..."
python3 -c "from app import app; print('✓ App import successful')" || {
    echo "❌ Failed to import app module"
    echo "Detailed error:"
    python3 -c "from app import app" 2>&1
    exit 1
}

echo ""
echo "Starting gunicorn..."
echo "================================"

exec gunicorn app:app \
    --bind 0.0.0.0:$PORT \
    --workers 4 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile - \
    --log-level info \
    --preload
