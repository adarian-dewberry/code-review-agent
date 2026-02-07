"""
SQL Injection Example - CWE-89, OWASP A03:2021

This code demonstrates a CRITICAL SQL injection vulnerability
caused by string formatting in database queries.

Expected Findings:
- CRITICAL: SQL Injection via string formatting (confidence: 1.0)
- HIGH: PII over-exposure from SELECT * (confidence: 0.9)
- HIGH: Missing audit trail for data access (confidence: 0.8)

Expected Verdict: 🚫 BLOCK

Attack Vector:
    user_id = "1; DROP TABLE users; --"
    # Results in: SELECT * FROM users WHERE id = 1; DROP TABLE users; --
    # The entire users table gets deleted

Remediation:
    Use parameterized queries:
    cursor.execute("SELECT id, name FROM users WHERE id = ?", (user_id,))
"""

from typing import Any


# Mock database for demonstration purposes
class _MockDB:
    """Simulated database connection."""

    def execute(self, query: str) -> Any:
        """Execute a query (mock)."""
        return []


db = _MockDB()


def get_user(user_id: str) -> Any:
    """Fetch user from database - VULNERABLE TO SQL INJECTION."""
    # BAD: String formatting allows SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)


def search_users(name: str) -> Any:
    """Search users by name - VULNERABLE TO SQL INJECTION."""
    # BAD: String concatenation allows SQL injection
    query = "SELECT * FROM users WHERE name LIKE '%" + name + "%'"
    return db.execute(query)


def update_user(user_id: str, email: str) -> Any:
    """Update user email - VULNERABLE TO SQL INJECTION."""
    # BAD: F-string in UPDATE statement
    query = f"UPDATE users SET email = '{email}' WHERE id = {user_id}"
    return db.execute(query)


def delete_user(user_id: str) -> Any:
    """Delete user - VULNERABLE TO SQL INJECTION."""
    # BAD: Direct interpolation in DELETE statement
    query = "DELETE FROM users WHERE id = %s" % user_id
    return db.execute(query)
