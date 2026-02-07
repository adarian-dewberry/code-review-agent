"""
Path Traversal Example - CWE-22, OWASP A01:2021

This code demonstrates CRITICAL path traversal vulnerabilities
that allow attackers to read or write files outside intended directories.

Expected Findings:
- CRITICAL: Path traversal via user-controlled filename (confidence: 1.0)
- HIGH: Arbitrary file read vulnerability (confidence: 0.95)
- HIGH: Arbitrary file write vulnerability (confidence: 0.95)
- MEDIUM: No input validation on file paths (confidence: 0.85)

Expected Verdict: 🚫 BLOCK

Attack Vector:
    filename = "../../../etc/passwd"
    # Reads system password file

    filename = "....//....//....//etc/shadow"
    # Bypasses simple ../ filtering

    filename = "%2e%2e%2f%2e%2e%2fetc/passwd"
    # URL-encoded path traversal

Remediation:
    1. Use os.path.basename() to extract only filename
    2. Validate against allowlist of permitted files
    3. Use os.path.realpath() and verify within allowed directory
    4. Never use user input directly in file paths
"""

import os
from typing import Optional


UPLOAD_DIR = "/var/www/uploads"
DOCUMENT_DIR = "/var/www/documents"


def read_user_file(filename: str) -> str:
    """Read a file from uploads directory - VULNERABLE TO PATH TRAVERSAL."""
    # BAD: User-controlled filename directly concatenated
    filepath = UPLOAD_DIR + "/" + filename

    with open(filepath, "r") as f:
        return f.read()


def download_document(document_name: str) -> bytes:
    """Download a document - VULNERABLE TO PATH TRAVERSAL."""
    # BAD: os.path.join doesn't prevent path traversal if filename starts with /
    filepath = os.path.join(DOCUMENT_DIR, document_name)

    # BAD: No validation that resulting path is within DOCUMENT_DIR
    with open(filepath, "rb") as f:
        return f.read()


def save_uploaded_file(filename: str, content: str) -> str:
    """Save an uploaded file - VULNERABLE TO PATH TRAVERSAL."""
    # BAD: Attacker can write to any location
    filepath = f"{UPLOAD_DIR}/{filename}"

    with open(filepath, "w") as f:
        f.write(content)

    return filepath


def delete_user_file(filename: str) -> None:
    """Delete a user's file - VULNERABLE TO PATH TRAVERSAL."""
    # BAD: Attacker can delete system files
    filepath = os.path.join(UPLOAD_DIR, filename)
    os.remove(filepath)


def get_file_with_weak_filter(filename: str) -> str:
    """Attempt to filter path traversal - STILL VULNERABLE."""
    # BAD: Simple replace doesn't handle all bypass techniques
    safe_name = filename.replace("../", "")
    # Can be bypassed with: ....//....//etc/passwd

    filepath = os.path.join(UPLOAD_DIR, safe_name)

    with open(filepath, "r") as f:
        return f.read()


def serve_static_file(file_path: str) -> Optional[bytes]:
    """Serve static files - VULNERABLE TO PATH TRAVERSAL."""
    # BAD: Accepts full path from user, only checks extension
    if file_path.endswith((".css", ".js", ".png")):
        # Extension check is easily bypassed: ../../../etc/passwd.png
        with open(file_path, "rb") as f:
            return f.read()
    return None
