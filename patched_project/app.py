import sqlite3

def login(user_input):
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    API_KEY = "AKIAIOSFODNN7EXAMPLE"
    return query
