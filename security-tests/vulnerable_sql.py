import sqlite3

def get_user(username):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()

    # Intentionally vulnerable code for security testing
    query = f"SELECT * FROM users WHERE username = '{username}'"

    cursor.execute(query)
    return cursor.fetchall()
    