"""
Hardcoded Secrets Example - CWE-798, OWASP A07:2021

This code demonstrates CRITICAL security vulnerabilities
from hardcoding sensitive credentials directly in source code.

Expected Findings:
- CRITICAL: Hardcoded API key in source code (confidence: 1.0)
- CRITICAL: Hardcoded database password (confidence: 1.0)
- CRITICAL: Hardcoded JWT secret (confidence: 1.0)
- HIGH: Credentials exposed in version control (confidence: 0.95)

Expected Verdict: 🚫 BLOCK

Attack Vector:
    If this code is committed to GitHub (even private repos):
    - Attackers scan GitHub for exposed credentials
    - Credentials can be extracted from compiled binaries
    - Former employees retain access
    - Secrets in logs/error messages

Remediation:
    1. Use environment variables: os.environ.get("API_KEY")
    2. Use secrets manager (AWS Secrets Manager, HashiCorp Vault)
    3. Use .env files (excluded from git)
    4. Rotate credentials if previously exposed
"""

import smtplib
from datetime import datetime, timedelta
from typing import Any

import jwt
import psycopg2
import requests


# BAD: API keys hardcoded in source
# NOTE: These are FAKE examples that follow real format patterns but are not valid keys
OPENAI_API_KEY = "sk-FAKE-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
STRIPE_SECRET_KEY = "sk_test_FAKE_51ABC123DEF456GHI789JKL012MNO345"  # noqa: S105
AWS_ACCESS_KEY = "AKIAFAKEEXAMPLE7FAKE"  # noqa: S105
AWS_SECRET_KEY = "wJalrXUtnFAKE/FAKE/bPxRfiCYFAKEEXAMPLEKEY"  # noqa: S105

# BAD: Database credentials hardcoded
DATABASE_URL = "postgresql://admin:FakePassword123!@fake-db.example.com:5432/users"  # noqa: S105
MONGO_URI = "mongodb://root:FakePass123@fake.example.local:27017/dev"  # noqa: S105

# BAD: JWT secret hardcoded
JWT_SECRET = "fake-jwt-secret-for-demo-only-2026"  # noqa: S105


def connect_to_database() -> Any:
    """Connect to production database - HARDCODED CREDENTIALS."""
    # BAD: Connection string with embedded password
    conn = psycopg2.connect(
        host="fake-db.example.com",
        database="users",
        user="admin",
        password="FakePassword123!",  # BAD: Hardcoded password  # noqa: S106
    )
    return conn


def call_openai_api(prompt: str) -> dict[str, Any]:
    """Call OpenAI API - HARDCODED API KEY."""
    # BAD: API key directly in code
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers=headers,
        json={"model": "gpt-4", "messages": [{"role": "user", "content": prompt}]},
    )
    return response.json()


def generate_jwt_token(user_id: str) -> str:
    """Generate JWT token - HARDCODED SECRET."""
    # BAD: JWT secret hardcoded
    payload = {"user_id": user_id, "exp": datetime.utcnow() + timedelta(hours=24)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def send_email(to: str, subject: str, body: str) -> None:
    """Send email via SMTP - HARDCODED CREDENTIALS."""
    # BAD: SMTP credentials hardcoded
    smtp_server = smtplib.SMTP("smtp.fake.example.com", 587)
    smtp_server.login("noreply@fake.example.com", "FakeEmailPass456!")  # noqa: S106
    smtp_server.sendmail(
        "noreply@fake.example.com", to, f"Subject: {subject}\n\n{body}"
    )
    smtp_server.quit()
