"""
Weak Cryptography Example - CWE-327, OWASP A02:2025 (Cryptographic Failures)

This code demonstrates vulnerabilities related to broken or
weak cryptographic algorithms and implementations.

Expected Findings:
- CRITICAL: MD5 used for password hashing (confidence: 1.0)
- CRITICAL: Hardcoded encryption key (confidence: 1.0)
- HIGH: SHA1 used for security purposes (confidence: 0.95)
- HIGH: ECB mode encryption (confidence: 0.9)
- MEDIUM: Weak random number generation (confidence: 0.85)

Expected Verdict: 🚫 BLOCK

Attack Vector:
    MD5 Password Cracking:
    - Rainbow tables can crack MD5 passwords in seconds
    - Hashcat can crack millions of MD5 hashes per second
    - No salt means identical passwords have identical hashes

    ECB Mode Vulnerability:
    - ECB encrypts identical blocks to identical ciphertext
    - Patterns in plaintext are visible in ciphertext
    - Famous "ECB Penguin" demonstrates visual leakage

Remediation:
    1. Use bcrypt, argon2, or scrypt for password hashing
    2. Use AES-GCM or ChaCha20-Poly1305 for encryption
    3. Use secrets.token_bytes() for cryptographic randomness
    4. Never hardcode encryption keys
    5. Use proper IV/nonce generation
"""

import hashlib
import random

from Crypto.Cipher import AES


# Hardcoded encryption key - CRITICAL vulnerability
ENCRYPTION_KEY = b"MySecretKey12345"  # CWE-798


def hash_password_vulnerable_md5(password: str) -> str:
    """
    VULNERABLE: Uses MD5 for password hashing.

    MD5 is cryptographically broken:
    - Collision attacks are trivial
    - No salt means rainbow table attacks
    - Extremely fast to brute force
    """
    return hashlib.md5(password.encode()).hexdigest()  # CRITICAL: MD5 for passwords


def hash_password_vulnerable_sha1(password: str) -> str:
    """
    VULNERABLE: Uses SHA1 for password hashing.

    SHA1 is deprecated for security:
    - Collision attacks demonstrated (SHAttered)
    - Too fast for password hashing (no work factor)
    - No salt means duplicate password detection
    """
    return hashlib.sha1(password.encode()).hexdigest()  # HIGH: SHA1 for passwords


def encrypt_data_ecb_vulnerable(data: bytes) -> bytes:
    """
    VULNERABLE: Uses ECB mode for encryption.

    ECB mode is insecure because:
    - Identical plaintext blocks produce identical ciphertext
    - Patterns are preserved in the ciphertext
    - No semantic security
    """
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)  # HIGH: ECB mode
    # Pad to block size
    padded = data + b"\x00" * (16 - len(data) % 16)
    return cipher.encrypt(padded)


def generate_token_vulnerable() -> str:
    """
    VULNERABLE: Uses weak random number generator.

    random.random() is not cryptographically secure:
    - Predictable seed based on time
    - State can be reverse-engineered from outputs
    - Not suitable for tokens, keys, or IVs
    """
    token = ""
    for _ in range(32):
        token += str(random.randint(0, 9))  # MEDIUM: Weak RNG
    return token


def derive_key_vulnerable(password: str) -> bytes:
    """
    VULNERABLE: Weak key derivation.

    Simple hashing is not key derivation:
    - No iterations (work factor)
    - No salt
    - Susceptible to brute force
    """
    return hashlib.sha256(password.encode()).digest()  # Should use PBKDF2/Argon2


# ============================================================
# SECURE implementations for comparison
# ============================================================


def hash_password_secure(password: str) -> str:
    """
    SECURE: Uses bcrypt for password hashing.

    bcrypt is recommended because:
    - Built-in salt generation
    - Configurable work factor
    - Memory-hard (resists GPU attacks)
    """
    import bcrypt

    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt).decode()


def encrypt_data_secure(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    SECURE: Uses AES-GCM for authenticated encryption.

    AES-GCM provides:
    - Confidentiality and integrity
    - Unique IV/nonce per encryption
    - Authentication tag prevents tampering
    """
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce, ciphertext, tag


def generate_token_secure() -> str:
    """
    SECURE: Uses cryptographically secure random generator.
    """
    import secrets

    return secrets.token_hex(32)


def derive_key_secure(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    SECURE: Uses PBKDF2 for key derivation.
    """
    import os
    from hashlib import pbkdf2_hmac

    if salt is None:
        salt = os.urandom(16)

    key = pbkdf2_hmac("sha256", password.encode(), salt, iterations=100000)
    return key, salt


if __name__ == "__main__":
    # Demonstrate vulnerabilities
    weak_hash = hash_password_vulnerable_md5("password123")
    print(f"MD5 hash (VULNERABLE): {weak_hash}")

    secure_hash = hash_password_secure("password123")
    print(f"Bcrypt hash (SECURE): {secure_hash}")
