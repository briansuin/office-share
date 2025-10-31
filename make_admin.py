import sqlite3
import sys

def make_admin(username):
    """Sets the is_admin flag for a user to 1."""
    conn = sqlite3.connect('share.db')
    cursor = conn.cursor()
    
    # Check if the user exists
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if user:
        # Update the user's is_admin flag
        cursor.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (username,))
        conn.commit()
        print(f"User '{username}' has been granted admin privileges.")
    else:
        print(f"User '{username}' not found.")
        
    conn.close()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python make_admin.py <username>")
        sys.exit(1)
        
    username = sys.argv[1]
    make_admin(username)
