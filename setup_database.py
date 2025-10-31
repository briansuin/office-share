import sqlite3

# Connect to the database (this will create the file if it doesn't exist)
connection = sqlite3.connect('share.db')

# Create a cursor to execute commands
cursor = connection.cursor()

# Create the 'items' table. If it already exists, it will be dropped first.
cursor.execute('''
    CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        owner TEXT NOT NULL,
        location TEXT NOT NULL,
        thumbnail TEXT,
        contact TEXT,
        details TEXT,
        method TEXT NOT NULL
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        is_admin BOOLEAN NOT NULL DEFAULT 0
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS sharing_methods (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE
    )
''')

# Populate sharing_methods table
methods = ['出借', '转让', '需求']
for method in methods:
    cursor.execute("INSERT OR IGNORE INTO sharing_methods (name) VALUES (?)", (method,))

# Save the changes and close the connection
connection.commit()
connection.close()

print("Database 'share.db' created successfully.")
