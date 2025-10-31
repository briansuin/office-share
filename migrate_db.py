import sqlite3

def migrate():
    conn = sqlite3.connect('share.db')
    cursor = conn.cursor()

    # Check if the is_admin column exists
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'is_admin' not in columns:
        print("Adding 'is_admin' column to 'users' table...")
        cursor.execute("ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT 0")
        conn.commit()
        print("'is_admin' column added successfully.")
    else:
        print("'is_admin' column already exists.")

    # Add is_approved column to users table
    if 'is_approved' not in columns:
        print("Adding 'is_approved' column to 'users' table...")
        cursor.execute("ALTER TABLE users ADD COLUMN is_approved BOOLEAN NOT NULL DEFAULT 0")
        # Approve all existing users
        cursor.execute("UPDATE users SET is_approved = 1")
        conn.commit()
        print("'is_approved' column added successfully and existing users approved.")
    else:
        print("'is_approved' column already exists.")

    # Create and populate sharing_methods table
    cursor.execute("PRAGMA table_info(sharing_methods)")
    columns = [column[1] for column in cursor.fetchall()]
    if not columns:
        print("Creating 'sharing_methods' table...")
        cursor.execute('''
            CREATE TABLE sharing_methods (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        ''')
        methods = ['出借', '转让', '需求']
        for method in methods:
            cursor.execute("INSERT INTO sharing_methods (name) VALUES (?)", (method,))
        conn.commit()
        print("'sharing_methods' table created and populated successfully.")
    else:
        print("'sharing_methods' table already exists.")

    # Create settings table
    cursor.execute("PRAGMA table_info(settings)")
    columns = [column[1] for column in cursor.fetchall()]
    if not columns:
        print("Creating 'settings' table...")
        cursor.execute('''
            CREATE TABLE settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('registration_approval', 'false'))
        conn.commit()
        print("'settings' table created and populated successfully.")
    else:
        print("'settings' table already exists.")


    conn.close()

if __name__ == '__main__':
    migrate()