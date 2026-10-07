"""
Migration script to add discord_id field to User table.
Run this once to update your existing database.
"""
from models import db

def migrate():
    # Check if the column already exists
    cursor = db.cursor()
    cursor.execute("PRAGMA table_info(user)")
    columns = [column[1] for column in cursor.fetchall()]

    if 'discord_id' in columns:
        print("Column 'discord_id' already exists in User table.")
        return

    print("Adding 'discord_id' column to User table...")

    try:
        db.execute_sql('ALTER TABLE user ADD COLUMN discord_id VARCHAR(255);')
        db.execute_sql('CREATE INDEX IF NOT EXISTS user_discord_id ON user (discord_id);')
        print("Column added successfully! It is filled in as each user logs in.")

    except Exception as e:
        print(f"Error during migration: {e}")
        print("If the column already exists, you can ignore this error.")

if __name__ == '__main__':
    migrate()
