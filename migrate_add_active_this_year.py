"""
Migration script to add active_this_year field to User table.
Run this once to update your existing database.
"""
from peewee import BooleanField
from models import db, User

def migrate():
    # Check if the column already exists
    cursor = db.cursor()
    cursor.execute("PRAGMA table_info(user)")
    columns = [column[1] for column in cursor.fetchall()]

    if 'active_this_year' in columns:
        print("Column 'active_this_year' already exists in User table.")
        return

    print("Adding 'active_this_year' column to User table...")

    try:
        db.execute_sql('ALTER TABLE user ADD COLUMN active_this_year INTEGER DEFAULT 0')
        print("Column added successfully!")

        # Update all existing users to have active_this_year = False (they need to login)
        User.update(active_this_year=False).execute()
        print("All existing users marked as inactive (they will need to login to participate).")

    except Exception as e:
        print(f"Error during migration: {e}")
        print("If the column already exists, you can ignore this error.")

if __name__ == '__main__':
    migrate()
