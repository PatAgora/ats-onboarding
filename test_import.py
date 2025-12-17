#!/usr/bin/env python3
"""
Test if app.py can be imported without errors.
Simulates Railway environment.
"""
import sys
import os

# Simulate Railway environment
os.environ['RAILWAY_ENVIRONMENT'] = 'production'
os.environ['FLASK_ENV'] = 'production'
os.environ['DATABASE_URL'] = 'sqlite:///ats.db'
os.environ['FLASK_SECRET_KEY'] = 'test-secret'
os.environ['PORT'] = '8080'

print("=" * 60)
print("Testing app import (simulating Railway environment)")
print("=" * 60)
print(f"RAILWAY_ENVIRONMENT: {os.getenv('RAILWAY_ENVIRONMENT')}")
print(f"FLASK_ENV: {os.getenv('FLASK_ENV')}")
print(f"DATABASE_URL: {os.getenv('DATABASE_URL')}")
print()

try:
    print("Attempting to import app...")
    from app import app
    print("✓ App import successful!")
    print()
    print("App configuration:")
    print(f"  - Secret key set: {bool(app.secret_key)}")
    print(f"  - Debug mode: {app.debug}")
    print()
    print("SUCCESS: App can be imported without errors")
    sys.exit(0)
except Exception as e:
    print(f"❌ Failed to import app!")
    print()
    print("Error details:")
    print(f"  Type: {type(e).__name__}")
    print(f"  Message: {str(e)}")
    print()
    print("Full traceback:")
    import traceback
    traceback.print_exc()
    sys.exit(1)
