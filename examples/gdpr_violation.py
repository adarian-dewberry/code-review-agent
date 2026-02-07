"""
GDPR Violation Example - Articles 5, 30, 32

This code demonstrates compliance violations related to
GDPR (General Data Protection Regulation) requirements
for handling personal data.

Expected Findings:
- HIGH: PII stored without encryption (confidence: 0.9)
- HIGH: No consent tracking mechanism (confidence: 0.85)
- HIGH: Missing data retention policy (confidence: 0.8)
- MEDIUM: No audit trail for data access (confidence: 0.75)
- MEDIUM: Excessive data collection (confidence: 0.7)

Expected Verdict: ⚠️ REVIEW_REQUIRED

GDPR Articles Violated:
- Article 5(1)(c): Data minimization
- Article 5(1)(e): Storage limitation
- Article 7: Conditions for consent
- Article 30: Records of processing
- Article 32: Security of processing

Remediation:
    1. Encrypt PII at rest and in transit
    2. Implement consent management
    3. Add data retention policies
    4. Create audit logs for all data access
    5. Minimize collected data to what's necessary
"""

from datetime import datetime
from typing import Any

import requests


# Mock database and request objects for demonstration
class _MockDB:
    """Simulated database."""

    class _Users:
        def insert(self, data: dict[str, Any]) -> None:
            pass

        def find(self, query: dict[str, Any]) -> list[dict[str, Any]]:
            return []

        def find_one(self, query: dict[str, Any]) -> dict[str, Any]:
            return {}

    users = _Users()


class _MockRequest:
    """Simulated Flask request."""

    remote_addr = "127.0.0.1"

    class headers:
        @staticmethod
        def get(key: str) -> str:
            return ""


class _MockActivityLogs:
    """Simulated activity logs collection."""

    def insert(self, data: dict[str, Any]) -> None:
        pass


db = _MockDB()
request = _MockRequest()
activity_logs = _MockActivityLogs()


def register_user(
    name: str,
    email: str,
    phone: str,
    ssn: str,
    date_of_birth: str,
    address: str,
    credit_card: str,
) -> dict[str, Any]:
    """Register a new user - GDPR VIOLATIONS."""
    # BAD: Collecting excessive PII (data minimization violation)
    # BAD: SSN and credit card likely not needed for registration

    user_data = {
        "name": name,
        "email": email,
        "phone": phone,
        "ssn": ssn,  # Why do we need SSN for registration?
        "date_of_birth": date_of_birth,
        "address": address,
        "credit_card": credit_card,  # Storing full credit card number
        "created_at": datetime.now(),
        # BAD: No consent field
        # BAD: No data retention timestamp
    }

    # BAD: Storing PII without encryption
    db.users.insert(user_data)

    # BAD: No audit log
    return user_data


def get_all_users() -> list[dict[str, Any]]:
    """Get all users for admin dashboard - GDPR VIOLATIONS."""
    # BAD: Returns all user data including sensitive fields
    # BAD: No access control or purpose limitation
    # BAD: No audit trail
    return list(db.users.find({}))


def log_user_activity(user_id: str, activity: str) -> None:
    """Log user activity - GDPR VIOLATIONS."""
    # BAD: Logging PII in plaintext
    log_entry = {
        "user_id": user_id,
        "activity": activity,
        "ip_address": request.remote_addr,
        "user_agent": request.headers.get("User-Agent"),
        "timestamp": datetime.now(),
        # BAD: No retention policy - logs kept forever
    }

    # BAD: Logs stored unencrypted
    activity_logs.insert(log_entry)


def share_user_data(user_id: str, third_party_api: str) -> dict[str, Any]:
    """Share user data with partner - GDPR VIOLATIONS."""
    user = db.users.find_one({"_id": user_id})

    # BAD: No consent check before sharing
    # BAD: No data processing agreement verification
    # BAD: Sharing all data instead of minimum necessary
    # BAD: No audit trail of data sharing

    response = requests.post(third_party_api, json=user)
    return response.json()
