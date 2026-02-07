"""Sample vulnerable code for benchmarking security tools.

This file contains intentional vulnerabilities for testing detection rates.
DO NOT use this code in production.
"""

import os
import pickle
import random
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)


# VULN 1: SQL Injection (CWE-89)
def get_user_by_id(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id={user_id}"  # Vulnerable
    cursor.execute(query)
    return cursor.fetchone()


# VULN 2: Command Injection (CWE-78)
def backup_file(filename):
    os.system(f"cp {filename} /backup/")  # Vulnerable


# VULN 3: eval() usage (CWE-95)
def calculate(expression):
    result = eval(expression)  # Vulnerable
    return result


# VULN 4: Hardcoded credentials (CWE-798)
API_KEY = "sk_live_1234567890abcdef"
DB_PASSWORD = "admin123"


# VULN 5: Path traversal (CWE-22)
@app.route("/download")
def download_file():
    filename = request.args.get("file")
    return open(f"/uploads/{filename}", "rb").read()  # Vulnerable


# VULN 6: Unsafe deserialization (CWE-502)
def load_data(data):
    return pickle.loads(data)  # Vulnerable


# VULN 7: SQL Injection with concatenation (CWE-89)
def search_users(keyword):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name LIKE '%" + keyword + "%'"  # Vulnerable
    cursor.execute(query)
    return cursor.fetchall()


# VULN 8: Shell injection via subprocess (CWE-78)
def process_file(filename):
    subprocess.call(f"grep pattern {filename}", shell=True)  # Vulnerable


# VULN 9: Weak random (CWE-330)
def generate_token():
    return str(random.randint(100000, 999999))  # Weak for security


# VULN 10: Missing HTTPS (CWE-319)
def authenticate(username: str, password: str) -> bool:
    """Dummy authentication function for demo purposes."""
    return username == "admin" and password == "password"


@app.route("/login", methods=["POST"])
def login():
    # Should use HTTPS, validate in production
    username = request.form["username"]
    password = request.form["password"]
    return "Login successful" if authenticate(username, password) else "Login failed"


if __name__ == "__main__":
    app.run(debug=True)  # Debug mode in production = vulnerability
