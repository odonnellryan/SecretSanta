"""
Migration script to add is_active field to Match table.
Run this once to update your existing database.
"""
from peewee import BooleanField
from models import db, Match

def migrate():
    # Check if the column already exists
    cursor = db.cursor()
    cursor.execute("PRAGMA table_info(match)")
    columns = [column[1] for column in cursor.fetchall()]

    if 'is_active' in columns:
        print("Column 'is_active' already exists in Match table.")
        return

    print("Adding 'is_active' column to Match table...")

    # Add the new column with default value True
    migrator = db.migrator()
    migrate_field = migrator.add_column('match', 'is_active', BooleanField(default=True))

    try:
        db.execute_sql('ALTER TABLE match ADD COLUMN is_active INTEGER DEFAULT 1')
        print("Column added successfully!")

        # Update all existing records to have is_active = True
        Match.update(is_active=True).execute()
        print("All existing matches marked as active.")

    except Exception as e:
        print(f"Error during migration: {e}")
        print("If the column already exists, you can ignore this error.")

if __name__ == '__main__':
    migrate()
