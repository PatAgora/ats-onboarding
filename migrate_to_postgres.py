"""
Database migration script: SQLite to PostgreSQL
Run this script once after deploying to Railway to migrate your data.

Usage:
    python migrate_to_postgres.py
"""
import os
import sys
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

# Source: SQLite database
SQLITE_DB = "ats.db"
SQLITE_URL = f"sqlite:///{SQLITE_DB}"

# Destination: PostgreSQL (Railway provides this via DATABASE_URL)
POSTGRES_URL = os.getenv("DATABASE_URL")

if not POSTGRES_URL:
    print("ERROR: DATABASE_URL environment variable not set")
    print("This script should be run on Railway after deployment")
    sys.exit(1)

# Fix Railway's postgres:// to postgresql://
if POSTGRES_URL.startswith("postgres://"):
    POSTGRES_URL = POSTGRES_URL.replace("postgres://", "postgresql://", 1)

print("=" * 60)
print("DATABASE MIGRATION: SQLite → PostgreSQL")
print("=" * 60)
print(f"Source: {SQLITE_URL}")
print(f"Target: {POSTGRES_URL[:30]}...")
print()

# Create engines
sqlite_engine = create_engine(SQLITE_URL)
postgres_engine = create_engine(POSTGRES_URL)

# Get table names from SQLite
inspector = inspect(sqlite_engine)
tables = inspector.get_table_names()

print(f"Found {len(tables)} tables to migrate:")
for table in tables:
    print(f"  - {table}")
print()

# Migrate data table by table
with Session(sqlite_engine) as sqlite_session, Session(postgres_engine) as postgres_session:
    
    for table_name in tables:
        print(f"Migrating {table_name}...", end=" ")
        
        try:
            # Read from SQLite
            result = sqlite_session.execute(text(f"SELECT * FROM {table_name}"))
            rows = result.fetchall()
            columns = result.keys()
            
            if not rows:
                print("(empty)")
                continue
            
            # Get column definitions
            col_defs = inspector.get_columns(table_name)
            col_names = [col['name'] for col in col_defs]
            
            # Build INSERT statement
            placeholders = ", ".join([f":{col}" for col in col_names])
            insert_sql = f"INSERT INTO {table_name} ({', '.join(col_names)}) VALUES ({placeholders})"
            
            # Insert into PostgreSQL
            for row in rows:
                row_dict = dict(zip(columns, row))
                postgres_session.execute(text(insert_sql), row_dict)
            
            postgres_session.commit()
            print(f"✓ ({len(rows)} rows)")
            
        except Exception as e:
            print(f"✗ Error: {e}")
            postgres_session.rollback()
            continue

print()
print("=" * 60)
print("Migration complete!")
print("=" * 60)
print()
print("Next steps:")
print("1. Verify data in PostgreSQL database")
print("2. Update DATABASE_URL in Railway environment variables")
print("3. Restart your Railway deployment")
print("4. Test all functionality")
