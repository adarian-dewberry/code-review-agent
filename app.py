"""
Code Review Agent - Multi-pass AI code review with structured findings
Risk Propagation & Blast Radius + Decision Accountability (V1+V2 ready)

=============================================================================
UI COPY AND EASTER EGG GUIDELINES

Voice:
- Sounds like a smart, friendly coworker you trust
- Young, confident, feminine, and professional
- Light inside-joke energy for people who work in tech
- Calm and reassuring, never sarcastic or mean

Humor rules:
- Allowed: subtle, knowing, shared-experience humor
- Not allowed: jokes during errors, failures, or BLOCK verdicts
- Never mock the user or the code
- Never joke about breaches, outages, or harm

Style rules:
- Short, conversational sentences
- Plain language over buzzwords
- No em dashes
- No corporate training tone
- No chatbot filler like "As an AI" or "Please note"

Easter eggs:
- UI-only and ephemeral
- Max one per run
- Only shown when explicitly triggered
- Never included in logs, CI output, or exports

If unsure, prefer clarity over cleverness.

Copy lint rules:
- Avoid "please", "kindly", "note that"
- Avoid corporate phrases like "best practice" unless necessary
- Avoid emojis outside verdict icons
- Avoid exclamation marks
=============================================================================
"""

import hashlib
import html
import json
import logging
import os
import re
import uuid
import random
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any


import anthropic
import gradio as gr
import httpx

FRANKIE_B64 = """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4O/siPjJsGoOiY3VybHgwc2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS5pbmdyZWRpZW50LnYzX18zZGhhc2hYIAnVbvQnsAvYplqjqyGq7+czLObxZ3Sy1x41rk0CKbRmomN1cmx4MHNlbGYjanVtYmY9YzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M19fNGRoYXNoWCA7aE7x/Cm/C+YqICG13dwUrfrWErmwI5Cwmm1WI3acLKJjdXJseDBzZWxmI2p1bWJmPWMycGEuYXNzZXJ0aW9ucy9jMnBhLmluZ3JlZGllbnQudjNfXzVkaGFzaFggLW05C1Ciq/XkGdhJ/qsyc+uNBxjsPBWxV7n/lN3rGIeiY3VybHgwc2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS5pbmdyZWRpZW50LnYzX182ZGhhc2hYIB7YJ3lejNsE7AyYBnJLFjiiqH8/uWVv99E46e1tSlw6omN1cmx4KnNlbGYjanVtYmY9YzJwYS5hc3NlcnRpb25zL2MycGEuYWN0aW9ucy52MmRoYXNoWCDfrvEdSDICjJtxKuhq1mweBJxtettRH/Gt8WNG+XnFt6JjdXJseClzZWxmI2p1bWJmPWMycGEuYXNzZXJ0aW9ucy9jMnBhLmhhc2guZGF0YWRoYXNoWCBQ9fg3btAyIxBw8eCYmD4n66/bs5FEL7bdxTggd9+SMGlzaWduYXR1cmV4GXNlbGYjanVtYmY9YzJwYS5zaWduYXR1cmVjYWxnZnNoYTI1NgAAB35qdW1iAAAAKWp1bWRjMmFzABEAEIAAAKoAOJtxA2MycGEuYXNzZXJ0aW9ucwAAAACcanVtYgAAAChqdW1kY2JvcgARABCAAACqADibcQNjMnBhLmhhc2guZGF0YQAAAABsY2JvcqRqZXhjbHVzaW9uc4GiZXN0YXJ0GCFmbGVuZ3RoGR/IY2FsZ2ZzaGEyNTZkaGFzaFggHNz1e/JghGtudYQ16ENQitVot4Z9nxgtc1Ki9tC5u/JjcGFkTQAAAAAAAAAAAAAAAAAAAAOIanVtYgAAAClqdW1kY2JvcgARABCAAACqADibcQNjMnBhLmFjdGlvbnMudjIAAAADV2Nib3KhZ2FjdGlvbnOBpGZhY3Rpb25sYzJwYS5jcmVhdGVka2Rlc2NyaXB0aW9ueCBDcmVhdGVkIGJ5IEdvb2dsZSBHZW5lcmF0aXZlIEFJLnFkaWdpdGFsU291cmNlVHlwZXhGaHR0cDovL2N2LmlwdGMub3JnL25ld3Njb2Rlcy9kaWdpdGFsc291cmNldHlwZS90cmFpbmVkQWxnb3JpdGhtaWNNZWRpYWpwYXJhbWV0ZXJzoWtpbmdyZWRpZW50c4eiY3VybHgtc2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS5pbmdyZWRpZW50LnYzZGhhc2hYIEPPQQUmfu68wdIEHLdRNcwvAGFseCftiCe5+857WDmWomN1cmx4MHNlbGYjanVtYmY9YzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M19fMWRoYXNoWCAVclPWZvmGvl1yJJJFIKVjMTldBPijflMgnfw2JSGnp6JjdXJseDBzZWxmI2p1bWJmPWMycGEuYXNzZXJ0aW9ucy9jMnBhLmluZ3JlZGllbnQudjNfXzJkaGFzaFggI7nRO5yIVLiZFu1NsWx50MrugLVARaB4O/siPjJsGoOiY3VybHgwc2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS5pbmdyZWRpZW50LnYzX18zZGhhc2hYIAnVbvQnsAvYplqjqyGq7+czLObxZ3Sy1x41rk0CKbRmomN1cmx4MHNlbGYjanVtYmY9YzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M19fNGRoYXNoWCA7aE7x/Cm/C+YqICG13dwUrfrWErmwI5Cwmm1WI3acLKJjdXJseDBzZWxmI2p1bWJmPWMycGEuYXNzZXJ0aW9ucy9jMnBhLmluZ3JlZGllbnQudjNfXzVkaGFzaFggLW05C1Ciq/XkGdhJ/qsyc+uNBxjsPBWxV7n/lN3rGIeiY3VybHgwc2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS5pbmdyZWRpZW50LnYzX182ZGhhc2hYIB7YJ3lejNsE7AyYBnJLFjiiqH8/uWVv99E46e1tSlw6AAAAdGp1bWIAAAAvanVtZGNib3IAEQAQgAAAqgA4m3EDYzJwYS5pbmdyZWRpZW50LnYzX182AAAAAD1jYm9yomxyZWxhdGlvbnNoaXBnaW5wdXRUb2tkZXNjcmlwdGlvbnJJbnB1dCBpbmdyZWRpZW50IDYAAAB0anVtYgAAAC9qdW1kY2JvcgARABCAAACqADibcQNjMnBhLmluZ3JlZGllbnQudjNfXzUAAAAAPWNib3KibHJlbGF0aW9uc2hpcGdpbnB1dFRva2Rlc2NyaXB0aW9ucklucHV0IGluZ3JlZGllbnQgNQAAAHRqdW1iAAAAL2p1bWRjYm9yABEAEIAAAKoAOJtxA2MycGEuaW5ncmVkaWVudC52M19fNAAAAAA9Y2JvcqJscmVsYXRpb25zaGlwZ2lucHV0VG9rZGVzY3JpcHRpb25ySW5wdXQgaW5ncmVkaWVudCA0AAAAdGp1bWIAAAAvanVtZGNib3IAEQAQgAAAqgA4m3EDYzJwYS5pbmdyZWRpZW50LnYzX18zAAAAAD1jYm9yomxyZWxhdGlvbnNoaXBnaW5wdXRUb2tkZXNjcmlwdGlvbnJJbnB1dCBpbmdyZWRpZW50IDMAAAB0anVtYgAAAC9qdW1kY2JvcgARABCAAACqADibcQNjMnBhLmluZ3JlZGllbnQudjNfXzIAAAAAPWNib3KibHJlbGF0aW9uc2hpcGdpbnB1dFRva2Rlc2NyaXB0aW9ucklucHV0IGluZ3JlZGllbnQgMgAAAHRqdW1iAAAAL2p1bWRjYm9yABEAEIAAAKoAOJtxA2MycGEuaW5ncmVkaWVudC52M19fMQAAAAA9Y2JvcqJscmVsYXRpb25zaGlwZ2lucHV0VG9rZGVzY3JpcHRpb25ySW5wdXQgaW5ncmVkaWVudCAxAAAAcWp1bWIAAAAsanVtZGNib3IAEQAQgAAAqgA4m3EDYzJwYS5pbmdyZWRpZW50LnYzAAAAAD1jYm9yomxyZWxhdGlvbnNoaXBnaW5wdXRUb2tkZXNjcmlwdGlvbnJJbnB1dCBpbmdyZWRpZW50IDAAACH4anVtYgAAAEdqdW1kYzJtYQARABCAAACqADibcQN1cm46YzJwYTo0Y2YwOTEzYy1kZjgzLTI3NzEtZTRkZS00YjQ3NjRiY2VkZjQAAAATAGp1bWIAAAAoanVtZGMyY3MAEQAQgAAAqgA4m3EDYzJwYS5zaWduYXR1cmUAAAAS0GNib3LShFkGKqIBJhghglkDPjCCAzowggLAoAMCAQICFACP4cxZpzDqUvh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jYm9ypGpleGNsdXNpb25zgaJlc3RhcnQYIWZsZW5ndGgZQcBjYWxnZnNoYTI1NmRoYXNoWCAFVMMBv/QTemfkx/Zt8Nz70f0QBl6rkcvcCjLuL2tMWmNwYWRNAAAAAAAAAAAAAAAAAAAAAiVqdW1iAAAAKWp1bWRjYm9yABEAEIAAAKoAOJtxA2MycGEuYWN0aW9ucy52MgAAAAH0Y2JvcqFnYWN0aW9uc4SiZmFjdGlvbmtjMnBhLm9wZW5lZGpwYXJhbWV0ZXJzoWtpbmdyZWRpZW50c4GiY3VybHgtc2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS5pbmdyZWRpZW50LnYzZGhhc2hYIENVsndy1eWQRPYUg2ClmnMS4m2gEmyWeMEH0BT25vFZo2ZhY3Rpb25rYzJwYS5lZGl0ZWRrZGVzY3JpcHRpb25nd0FkZGVkIGltcGVyY2VwdGlibGUgU3ludGhJRCB3YXRlcm1hcmtxZGlnaXRhbFNvdXJjZVR5cGV4Rmh0dHA6Ly9jdi5pcHRjLm9yZy9uZXdzY29kZXMvZGlnaXRhbHNvdXJjZXR5cGUvdHJhaW5lZEFsZ29yaXRobWljTWVkaWGjZmFjdGlvbmtjMnBhLmVkaXRlZGtkZXNjcmlwdGlvbndBZGRlZCB2aXNpYmxlIHdhdGVybWFya3FkaWdpdGFsU291cmNlVHlwZXg4aHR0cDovL2N2LmlwdGMub3JnL25ld3Njb2Rlcy9kaWdpdGFsc291cmNldHlwZS9jb21wb3NpdGWiZmFjdGlvbm5jMnBhLmNvbnZlcnRlZGtkZXNjcmlwdGlvbnFDb252ZXJ0ZWQgdG8gLnBuZwAACaVqdW1iAAAALGp1bWRjYm9yABEAEIAAAKoAOJtxA2MycGEuaW5ncmVkaWVudC52MwAAAAlxY2JvcqRscmVsYXRpb25zaGlwaHBhcmVudE9mcXZhbGlkYXRpb25SZXN1bHRzoW5hY3RpdmVNYW5pZmVzdKNnZmFpbHVyZYBnc3VjY2Vzc5CiZGNvZGV4IXNpZ25pbmdDcmVkZW50aWFsLm9jc3Aubm90UmV2b2tlZGN1cmx4TXNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6MjZlZjk5NzYtMjBjMS1hNTVlLTA5ZmItNDMyNGExZTIxZjgyL2MycGEuc2lnbmF0dXJlomRjb2Rlc3RpbWVTdGFtcC52YWxpZGF0ZWRjdXJseE1zZWxmI2p1bWJmPS9jMnBhL3VybjpjMnBhOjI2ZWY5OTc2LTIwYzEtYTU1ZS0wOWZiLTQzMjRhMWUyMWY4Mi9jMnBhLnNpZ25hdHVyZaJkY29kZXF0aW1lU3RhbXAudHJ1c3RlZGN1cmx4TXNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6MjZlZjk5NzYtMjBjMS1hNTVlLTA5ZmItNDMyNGExZTIxZjgyL2MycGEuc2lnbmF0dXJlomRjb2RleBlzaWduaW5nQ3JlZGVudGlhbC50cnVzdGVkY3VybHhNc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYToyNmVmOTk3Ni0yMGMxLWE1NWUtMDlmYi00MzI0YTFlMjFmODIvYzJwYS5zaWduYXR1cmWiZGNvZGV4HWNsYWltU2lnbmF0dXJlLmluc2lkZVZhbGlkaXR5Y3VybHhNc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYToyNmVmOTk3Ni0yMGMxLWE1NWUtMDlmYi00MzI0YTFlMjFmODIvYzJwYS5zaWduYXR1cmWiZGNvZGV4GGNsYWltU2lnbmF0dXJlLnZhbGlkYXRlZGN1cmx4TXNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6MjZlZjk5NzYtMjBjMS1hNTVlLTA5ZmItNDMyNGExZTIxZjgyL2MycGEuc2lnbmF0dXJlomRjb2RleBlhc3NlcnRpb24uaGFzaGVkVVJJLm1hdGNoY3VybHhhc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYToyNmVmOTk3Ni0yMGMxLWE1NWUtMDlmYi00MzI0YTFlMjFmODIvYzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M6JkY29kZXgZYXNzZXJ0aW9uLmhhc2hlZFVSSS5tYXRjaGN1cmx4ZHNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6MjZlZjk5NzYtMjBjMS1hNTVlLTA5ZmItNDMyNGExZTIxZjgyL2MycGEuYXNzZXJ0aW9ucy9jMnBhLmluZ3JlZGllbnQudjNfXzGiZGNvZGV4GWFzc2VydGlvbi5oYXNoZWRVUkkubWF0Y2hjdXJseGRzZWxmI2p1bWJmPS9jMnBhL3VybjpjMnBhOjI2ZWY5OTc2LTIwYzEtYTU1ZS0wOWZiLTQzMjRhMWUyMWY4Mi9jMnBhLmFzc2VydGlvbnMvYzJwYS5pbmdyZWRpZW50LnYzX18yomRjb2RleBlhc3NlcnRpb24uaGFzaGVkVVJJLm1hdGNoY3VybHhkc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYToyNmVmOTk3Ni0yMGMxLWE1NWUtMDlmYi00MzI0YTFlMjFmODIvYzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M19fM6JkY29kZXgZYXNzZXJ0aW9uLmhhc2hlZFVSSS5tYXRjaGN1cmx4ZHNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6MjZlZjk5NzYtMjBjMS1hNTVlLTA5ZmItNDMyNGExZTIxZjgyL2MycGEuYXNzZXJ0aW9ucy9jMnBhLmluZ3JlZGllbnQudjNfXzSiZGNvZGV4GWFzc2VydGlvbi5oYXNoZWRVUkkubWF0Y2hjdXJseGRzZWxmI2p1bWJmPS9jMnBhL3VybjpjMnBhOjI2ZWY5OTc2LTIwYzEtYTU1ZS0wOWZiLTQzMjRhMWUyMWY4Mi9jMnBhLmFzc2VydGlvbnMvYzJwYS5pbmdyZWRpZW50LnYzX181omRjb2RleBlhc3NlcnRpb24uaGFzaGVkVVJJLm1hdGNoY3VybHhkc2VsZiNqdW1iZj0vYzJwYS91cm46YzJwYToyNmVmOTk3Ni0yMGMxLWE1NWUtMDlmYi00MzI0YTFlMjFmODIvYzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M19fNqJkY29kZXgZYXNzZXJ0aW9uLmhhc2hlZFVSSS5tYXRjaGN1cmx4XnNlbGYjanVtYmY9L2MycGEvdXJuOmMycGE6MjZlZjk5NzYtMjBjMS1hNTVlLTA5ZmItNDMyNGExZTIxZjgyL2MycGEuYXNzZXJ0aW9ucy9jMnBhLmFjdGlvbnMudjKiZGNvZGV4GWFzc2VydGlvbi5oYXNoZWRVUkkubWF0Y2hjdXJseF1zZWxmI2p1bWJmPS9jMnBhL3VybjpjMnBhOjI2ZWY5OTc2LTIwYzEtYTU1ZS0wOWZiLTQzMjRhMWUyMWY4Mi9jMnBhLmFzc2VydGlvbnM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"""

# Configure logging with structured format
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

# Strip whitespace from API key (common issue with copy/paste in HF secrets)
ANTHROPIC_API_KEY = (os.getenv("ANTHROPIC_API_KEY") or "").strip()

# Allow model override via environment variable
MODEL = os.getenv("CODE_REVIEW_MODEL", "claude-sonnet-4-20250514")
SCHEMA_VERSION = "1.0"
TOOL_VERSION = "0.2.2"

# Rate limiting configuration
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "10"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # seconds

# Cache configuration
CACHE_MAX_SIZE = int(os.getenv("CACHE_MAX_SIZE", "100"))
CACHE_TTL = int(os.getenv("CACHE_TTL", "3600"))  # 1 hour


# =============================================================================
# RATE LIMITER - Prevent API abuse
# =============================================================================


class RateLimiter:
    """
    Simple in-memory rate limiter.
    Limits requests per time window to prevent abuse.
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str = "global") -> bool:
        """Check if request is allowed under rate limit."""
        now = time.time()

        with self._lock:
            if key not in self.requests:
                self.requests[key] = []

            # Remove old requests outside window
            self.requests[key] = [
                ts for ts in self.requests[key] if now - ts < self.window_seconds
            ]

            if len(self.requests[key]) >= self.max_requests:
                return False

            self.requests[key].append(now)
            return True

    def get_retry_after(self, key: str = "global") -> int:
        """Get seconds until next request is allowed."""
        now = time.time()
        with self._lock:
            if key not in self.requests or not self.requests[key]:
                return 0
            oldest = min(self.requests[key])
            return max(0, int(self.window_seconds - (now - oldest)))


# =============================================================================
# LRU CACHE - Cache review results for identical code
# =============================================================================


# Type alias for cached review results (summary, details, fixes, audit_record)
CacheValue = tuple[str, str, str, dict | None]


class LRUCache:
    """
    Simple LRU cache with TTL.
    Caches review results to reduce API calls and latency.
    """

    def __init__(self, max_size: int = 100, ttl_seconds: int = 3600):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache: OrderedDict[str, tuple[float, CacheValue]] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def _make_key(self, code: str, categories: list[str]) -> str:
        """Generate cache key from code and categories."""
        content = f"{code}:{':'.join(sorted(categories))}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def get(self, code: str, categories: list[str]) -> CacheValue | None:
        """Get cached result if exists and not expired."""
        key = self._make_key(code, categories)
        now = time.time()

        with self._lock:
            if key in self.cache:
                timestamp, value = self.cache[key]
                if now - timestamp < self.ttl_seconds:
                    # Move to end (most recently used)
                    self.cache.move_to_end(key)
                    self._hits += 1
                    logger.info(f"Cache hit: {key[:8]}...")
                    return value
                else:
                    # Expired
                    del self.cache[key]

            self._misses += 1
            return None

    def set(self, code: str, categories: list[str], value: CacheValue) -> None:
        """Store result in cache."""
        key = self._make_key(code, categories)
        now = time.time()

        with self._lock:
            if key in self.cache:
                del self.cache[key]

            self.cache[key] = (now, value)

            # Evict oldest if over capacity
            while len(self.cache) > self.max_size:
                self.cache.popitem(last=False)

    def stats(self) -> dict:
        """Return cache statistics."""
        total = self._hits + self._misses
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self._hits / total if total > 0 else 0,
            "size": len(self.cache),
            "max_size": self.max_size,
        }


# Initialize rate limiter and cache
rate_limiter = RateLimiter(
    max_requests=RATE_LIMIT_REQUESTS, window_seconds=RATE_LIMIT_WINDOW
)
review_cache = LRUCache(max_size=CACHE_MAX_SIZE, ttl_seconds=CACHE_TTL)


def generate_session_id() -> str:
    """Generate a unique session ID for rate limiting."""
    return uuid.uuid4().hex[:12]


# =============================================================================
# CURATED UI COPY - Do not generate new copy here
# IMPORTANT: Only select from predefined copy. Humor and tone are intentional.
# =============================================================================

EasterEggType = dict[str, str | list[str] | int | float]

EASTER_EGGS: dict[str, EasterEggType] = {
    "quiet_win": {
        "id": "quiet_win",
        "copy": "Nothing scary here. We love to see it.",
        "allowed_verdicts": ["PASS"],
        "audience": ["beginner", "intermediate", "advanced"],
        "max_per_session": 1,
        "probability": 0.3,
    },
    "clean_slate": {
        "id": "clean_slate",
        "copy": "A clean review. Someone's been reading the docs.",
        "allowed_verdicts": ["PASS"],
        "audience": ["intermediate", "advanced"],
        "max_per_session": 1,
        "probability": 0.2,
    },
    "review_pause": {
        "id": "review_pause",
        "copy": "Not a fail. Just a pause.",
        "allowed_verdicts": ["REVIEW_REQUIRED"],
        "audience": ["beginner"],
        "max_per_session": 1,
        "probability": 0.25,
    },
    "worth_a_look": {
        "id": "worth_a_look",
        "copy": "Worth a second look before you ship.",
        "allowed_verdicts": ["REVIEW_REQUIRED"],
        "audience": ["intermediate", "advanced"],
        "max_per_session": 1,
        "probability": 0.2,
    },
    "security_pattern": {
        "id": "security_pattern",
        "copy": "Yeah... this is one of those patterns.",
        "allowed_verdicts": ["REVIEW_REQUIRED"],
        "audience": ["intermediate", "advanced"],
        "min_confidence": 0.85,
        "max_per_session": 1,
        "probability": 0.15,
    },
}


# =============================================================================
# FRANKIE - The Alaskan Malamute Loading Mascot
# Rules:
# - Frankie appears ONLY during processing (not on results, errors, or BLOCK)
# - Frankie is calm, quiet, observant - not a dancing mascot
# - One line at a time, rotated, no exclamation points
# - Think: "Frankie is watching. Frankie is judging. Frankie is on your side."
# =============================================================================

FRANKIE_LINES = [
    "Frankie is taking a look.",
    "Frankie is checking the usual suspects.",
    "Hang tight. Frankie doesn't rush.",
    "Frankie has thoughts. One sec.",
    "Frankie is being thorough. As always.",
]


def pick_frankie_line(run_id: str, last_line: str | None = None) -> str:
    """
    Deterministic pick based on run_id, avoids immediate repeats.
    run_id can be timestamp-based, uuid, or hash of input.
    """
    import hashlib

    h = hashlib.sha256(run_id.encode("utf-8")).hexdigest()
    idx = int(h[:8], 16) % len(FRANKIE_LINES)
    candidate = FRANKIE_LINES[idx]

    if last_line and candidate == last_line:
        candidate = FRANKIE_LINES[(idx + 1) % len(FRANKIE_LINES)]

    return candidate


def select_easter_egg(verdict: str, confidence: float, audience: str) -> str | None:
    """
    Selects an optional easter egg based on run context.

    Selection rules:
    - Never select if verdict is BLOCK
    - Never select more than one per run
    - Respect audience mode (beginner, intermediate, advanced)
    - Prefer no message over a forced one

    Tone check:
    - Would this feel okay if a senior engineer said it in a PR review?
    - Would a junior feel supported, not embarrassed?
    - Would a manager be fine seeing this in a screenshot?

    If any answer is no, do not show the message.
    """
    # Never show easter eggs on BLOCK - this is serious
    if verdict == "BLOCK":
        return None

    audience_lower = audience.lower()
    candidates = []

    for egg in EASTER_EGGS.values():
        # Check verdict match
        allowed = egg.get("allowed_verdicts", [])
        if verdict not in (allowed if isinstance(allowed, list) else []):
            continue

        # Check audience match
        aud_list = egg.get("audience", [])
        if audience_lower not in (aud_list if isinstance(aud_list, list) else []):
            continue

        # Check confidence threshold if specified
        min_conf_val = egg.get("min_confidence", 0.0)
        min_conf = (
            float(min_conf_val) if isinstance(min_conf_val, (int, float)) else 0.0
        )
        if confidence < min_conf:
            continue

        candidates.append(egg)

    if not candidates:
        return None

    # Probabilistic selection - prefer no message over forced humor
    for egg in candidates:
        prob_val = egg.get("probability", 0.2)
        prob = float(prob_val) if isinstance(prob_val, (int, float)) else 0.2
        if random.random() < prob:
            copy = egg.get("copy", "")
            return str(copy) if copy else None

    return None


# Verdict UI copy - calm, human-readable, no jokes on BLOCK
# IMPORTANT: Do not generate new UI copy here.
# Only select from predefined copy in EASTER_EGGS or UI_COPY.
UI_COPY = {
    "BLOCK": {
        "headline": "⚠️ Unsafe to merge",
        "subtext": "This code contains patterns that pose security risks and should be revised before merging.",
        "confidence_text": "High confidence",
        "alt_subtext": None,  # No jokes allowed
    },
    "REVIEW_REQUIRED": {
        "headline": "⚠️ Review recommended",
        "subtext": "Some patterns could become risky depending on how this code is used. Human review is recommended.",
        "confidence_text": "Medium-High confidence",
        "alt_subtext": None,  # Easter egg can replace this
    },
    "PASS": {
        "headline": "✅ No issues found",
        "subtext": "This code follows safe patterns based on the signals we checked.",
        "confidence_text": "High confidence",
        "alt_subtext": None,  # Easter egg can replace this
    },
}

# Policy rules for decision accountability
PolicyRuleType = dict[str, str | float]
POLICY: dict[str, str | list[PolicyRuleType]] = {
    "version": "v1",
    "block_rules": [
        {
            "rule_id": "BR-001",
            "description": "Block if any CRITICAL with confidence >= 0.8",
            "severity": "CRITICAL",
            "min_confidence": 0.8,
        },
    ],
    "review_rules": [
        {
            "rule_id": "RR-001",
            "description": "Review required if any HIGH with confidence >= 0.7",
            "severity": "HIGH",
            "min_confidence": 0.7,
        },
        {
            "rule_id": "RR-002",
            "description": "Review required if any CRITICAL with confidence < 0.8",
            "severity": "CRITICAL",
            "min_confidence": 0.0,
            "max_confidence": 0.8,
        },
    ],
}

# Structured prompt with JSON schema for consistent output
# Policy v2: GRC-aligned with CWE/OWASP 2025 mapping
SYSTEM_PROMPT = """You are the "Frankie" Secure Code Review Agent, a Senior AppSec & GRC Engineer.
You produce audit-ready, policy-driven security reviews mapped to industry standards.

# POLICY FRAMEWORK: v2 (OWASP 2025)
Audit code against these controls with explicit standards mapping:

## Injection Flaws (OWASP A03:2025 - Injection)
- CWE-89: SQL Injection - Unparameterized queries
- CWE-78: OS Command Injection - Unsanitized subprocess calls
- CWE-79: Cross-Site Scripting - Unescaped HTML output
- CWE-94: Code Injection - eval(), exec() with user input

## AI/LLM-Specific Risks (OWASP Top 10 for LLM Applications:2025)
- LLM01: Prompt Injection - Direct string interpolation in prompts, instruction override
- LLM02: Insecure Output Handling - Unvalidated/unsanitized model responses
- LLM03: Training Data Poisoning - Compromised training data sources
- LLM04: Model Denial of Service - Unbounded token generation, resource exhaustion
- LLM05: Supply Chain Vulnerabilities - Untrusted model sources or plugins
- LLM06: Sensitive Information Disclosure - PII/secrets in prompts or responses
- LLM07: Insecure Plugin Design - Plugins with excessive permissions
- LLM08: Excessive Agency - Autonomous actions without human oversight
- LLM09: Overreliance - Trusting model output without validation
- LLM10: Model Theft - Insufficient access controls on model artifacts

## Access Control (OWASP A01:2025 - Broken Access Control)
- CWE-798: Hardcoded Credentials - API keys, passwords in code
- CWE-200: Information Exposure - Excessive data in responses
- CWE-284: Improper Access Control - Missing auth checks

## Cryptographic Failures (OWASP A02:2025)
- CWE-327: Broken Crypto Algorithm - MD5, SHA1 for security
- CWE-328: Weak Hash - Insufficient iterations, no salt
- CWE-259: Hard-coded Password - Embedded credentials

## Security Misconfiguration (OWASP A05:2025)
- CWE-772: Missing Resource Release - Unclosed connections
- CWE-400: Resource Exhaustion - Unbounded operations
- CWE-16: Configuration - Debug enabled, default credentials

## Server-Side Request Forgery (OWASP A10:2025 - SSRF)
- CWE-918: SSRF - User-controlled URLs without validation

<output_schema>
{
  "findings": [
    {
      "id": "F-001",
      "root_cause": "The underlying issue (group related findings)",
      "title": "Brief issue title",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 0.0-1.0,
      "cwe": "CWE-89 (if applicable)",
      "owasp": "A03:2025 or LLM01:2025 (if applicable)",
      "tags": ["security", "compliance", "logic", "performance"],
      "location": "function_name():line or file.py:line",
      "evidence": "exact vulnerable code with ^ caret pointing to issue",
      "description": "What the issue is",
      "impact": "Why it matters (context-specific)",
      "escalation": "When severity increases (e.g., 'CRITICAL if LLM has tool access')",
      "recommendation": "Multi-step fix with specific techniques",
      "blast_radius": {
        "technical_scope": "function|module|service|cross-service|unknown",
        "data_scope": "none|internal|customer|pii|regulated|unknown",
        "org_scope": "single-team|multi-team|external-customers|regulators|unknown"
      },
      "why_it_matters": ["reason1", "reason2"]
    }
  ]
}
</output_schema>

<rules>
1. DEDUPE: One finding per ROOT CAUSE. Use tags array for cross-cutting concerns.

2. CWE/OWASP MAPPING: Include cwe and owasp fields for all security findings:
   - SQL Injection → CWE-89, A03:2025
   - Prompt Injection → LLM01:2025
   - Insecure Output Handling → LLM02:2025
   - Hardcoded Secrets → CWE-798, A01:2025
   - Weak Crypto → CWE-327, A02:2025
   - SSRF → CWE-918, A10:2025

3. EVIDENCE: Show exact line with caret (^) pointing to the vulnerability:
   query = f"SELECT * FROM users WHERE id = {user_id}"
                                          ^ untrusted input in SQL string

4. LOCATION: Use descriptive format - "chat():2" or "get_user():5", not "unknown:2"

5. BLAST RADIUS ESTIMATION (for HIGH/CRITICAL findings):
   - technical_scope: How far can exploitation spread? (function → module → service → cross-service)
   - data_scope: What data is at risk? (none → internal → customer → pii → regulated)
   - org_scope: Who is affected? (single-team → multi-team → external-customers → regulators)

   Heuristics:
   - SQL injection + SELECT * FROM users → data_scope: "pii", technical_scope: "service"
   - Prompt injection without tool access → technical_scope: "function"
   - Auth bypass → org_scope: "external-customers"

5. WHY_IT_MATTERS: List 2-3 specific reasons this finding is significant (for audit trail)

6. COMPLIANCE: Use CONDITIONAL language for PII:
   "If the users table contains PII, SELECT * increases exposure surface"

7. CONTEXT-SPECIFIC IMPACT:
   - SQLite: "file locks, open handle limits, concurrency issues"
   - PostgreSQL/MySQL: "connection pool exhaustion, server resource drain"
   - LLM: "behavior manipulation, prompt override, information disclosure"

8. PROMPT INJECTION RULES:
   - Never claim pattern detection "stops" injection (it's heuristic only)
   - Use: "flag suspicious instruction-like input for review (heuristic)"
   - Recommend "instruction hierarchy" (system > developer > user)
   - blast_radius.technical_scope = "function" unless tool access detected

9. MULTI-STEP RECOMMENDATIONS:
   - SQL: "1) Validate type 2) Parameterize 3) Handle errors safely"
   - LLM: "1) Structured prompting with instruction hierarchy 2) Input flagging (heuristic) 3) Output validation 4) Least-privilege model access"

10. ESCALATION FIELD: Always include "When this becomes CRITICAL" for HIGH/MEDIUM findings.

11. CONFIDENCE: 1.0 only for definite vulnerabilities. 0.7-0.9 for context-dependent issues.
</rules>"""

CATEGORY_PROMPTS = {
    "security": """Focus on: SQL injection (A03:2025), command injection, XSS, SSRF (A10:2025), path traversal,
auth bypass (A01:2025), secrets exposure, insecure deserialization, prompt injection (LLM01:2025).
For prompt injection: use "instruction hierarchy" concept, flag heuristically, include escalation conditions.
For SQL injection: validate type + parameterize + handle errors.
For LLM apps: check for LLM02 (insecure output), LLM06 (sensitive data), LLM08 (excessive agency).
Always estimate blast_radius for HIGH/CRITICAL findings.""",
    "compliance": """Focus on: PII exposure (LLM06:2025), missing consent, audit trail gaps, data retention,
encryption at rest/transit (A02:2025). Use CONDITIONAL language: "If table contains PII..."
Suggest CONTROLS not violations. Include escalation for when it becomes CRITICAL.
Set data_scope appropriately (pii, regulated, customer).""",
    "logic": """Focus on: Null/undefined handling, race conditions, off-by-one errors,
unhandled exceptions, infinite loops, resource leaks.
For errors: "don't leak internals" and "log safely without secrets".
For LLM apps: check for LLM09 (overreliance on model output without validation).""",
    "performance": """Focus on: N+1 queries, unbounded loops, memory leaks, blocking I/O,
missing indexes, inefficient algorithms, cache misses.
For LLM apps: check for LLM04 (model denial of service via unbounded token generation).
Use DATABASE-SPECIFIC language (sqlite vs postgres vs mysql).""",
}


def generate_run_id() -> str:
    """Generate unique run ID."""
    return f"RUN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"


def generate_decision_id() -> str:
    """Generate unique decision ID."""
    return f"D-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:4]}"


def parse_findings(text: str) -> dict[str, list[dict[str, Any]]]:
    """Extract JSON findings from LLM response."""
    json_match = re.search(r'\{[\s\S]*"findings"[\s\S]*\}', text)
    if json_match:
        try:
            result = json.loads(json_match.group())
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass
    return {"findings": []}


def review_code(
    code: str,
    sec: bool,
    comp: bool,
    logic: bool,
    perf: bool,
    ctx: str = "",
    review_mode: str = "Deep",
    session_id: str = "global",
) -> tuple[str, str, str, dict | None]:
    """Run multi-pass code review with structured output.

    Returns:
        tuple: (summary_html, details_markdown, fixes_markdown, audit_record)
    """

    # Rate limiting check (per-session for multi-tenant isolation)
    if not rate_limiter.is_allowed(session_id):
        retry_after = rate_limiter.get_retry_after(session_id)
        logger.warning(
            f"Rate limit exceeded for session {session_id[:6]}, retry after {retry_after}s"
        )
        return (
            f"<div class='error-banner warning'><div class='error-icon'>⏱️</div><div class='error-content'><h3>Slow down there</h3><p>You've made a lot of requests. Try again in <strong>{retry_after} seconds</strong>.</p></div></div>",
            "",
            "",
            None,
        )

    if not code or not code.strip():
        return (
            "<div class='error-banner warning'><div class='error-icon'>📝</div><div class='error-content'><h3>Nothing to review yet</h3><p>Paste your code in the editor on the left, then click <strong>Analyze My Code</strong>.</p></div></div>",
            "",
            "",
            None,
        )

    if len(code) > 50000:
        return (
            f"<div class='error-banner warning'><div class='error-icon'>📏</div><div class='error-content'><h3>That's a lot of code</h3><p>Your snippet is <strong>{len(code):,}</strong> characters. Break it into smaller chunks (under 50,000 characters) for best results.</p></div></div>",
            "",
            "",
            None,
        )

    if not any([sec, comp, logic, perf]):
        return (
            "<div class='error-banner warning'><div class='error-icon'>☑️</div><div class='error-content'><h3>Pick something to check</h3><p>Select at least one category in <strong>Fine-Tune Categories</strong> below the code editor.</p></div></div>",
            "",
            "",
            None,
        )

    if not ANTHROPIC_API_KEY:
        return (
            "<div class='error-banner error'><div class='error-icon'>🔑</div><div class='error-content'><h3>API key not configured</h3><p>This space needs an Anthropic API key. If you're the owner, add <code>ANTHROPIC_API_KEY</code> in Settings → Secrets.</p></div></div>",
            "",
            "",
            None,
        )

    cats = []
    if sec:
        cats.append("security")
    if comp:
        cats.append("compliance")
    if logic:
        cats.append("logic")
    if perf:
        cats.append("performance")

    # Check cache first (cache key now includes review mode)
    cache_key_cats = cats + [review_mode]
    cached_result = review_cache.get(code, cache_key_cats)
    if cached_result is not None:
        logger.info("Returning cached result")
        return cached_result

    http_client = None
    try:
        http_client = httpx.Client(
            timeout=httpx.Timeout(90.0, connect=30.0),
            http2=False,
        )
        client = anthropic.Anthropic(
            api_key=ANTHROPIC_API_KEY,
            http_client=http_client,
        )

        # Build category focus list
        focus_areas = "\n".join(
            [f"- {cat.upper()}: {CATEGORY_PROMPTS[cat]}" for cat in cats]
        )

        # Single consolidated prompt
        user_prompt = f"""<code>
{code}
</code>

<context>
File: {ctx if ctx else "unknown"}
Categories to review: {", ".join(cats)}
</context>

<focus_areas>
{focus_areas}
</focus_areas>

Analyze the code and return findings as JSON per the schema. Include line numbers and 3-line snippets."""

        # Use prompt caching for system prompt (75% cost reduction on cache hits)
        resp = client.messages.create(
            model=MODEL,
            max_tokens=4000,
            temperature=0.0,
            system=[
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user_prompt}],
        )

        # Log token usage for cost tracking
        usage = resp.usage
        logger.info(
            f"API call: input={usage.input_tokens}, output={usage.output_tokens}"
        )

        parsed = parse_findings(resp.content[0].text)
        findings = parsed.get("findings", [])

        # Count by severity and confidence
        block_findings = [
            f
            for f in findings
            if f.get("severity") in ["CRITICAL", "HIGH"]
            and f.get("confidence", 0) >= 0.8
        ]
        warn_findings = [
            f
            for f in findings
            if f.get("severity") in ["CRITICAL", "HIGH"]
            and f.get("confidence", 0) < 0.8
        ]

        # Determine triggered rules for decision accountability
        triggered_block_rules: list[dict[str, Any]] = []
        triggered_review_rules: list[dict[str, Any]] = []

        block_rules = POLICY.get("block_rules", [])
        review_rules = POLICY.get("review_rules", [])

        if isinstance(block_rules, list):
            for rule in block_rules:
                if not isinstance(rule, dict):
                    continue
                for f in findings:
                    if f.get("severity") == rule.get("severity") and f.get(
                        "confidence", 0
                    ) >= float(rule.get("min_confidence", 0)):
                        triggered_block_rules.append({"rule": rule, "finding": f})
                        break

        if isinstance(review_rules, list):
            for rule in review_rules:
                if not isinstance(rule, dict):
                    continue
                max_conf = float(rule.get("max_confidence", 1.0))
                for f in findings:
                    if (
                        f.get("severity") == rule.get("severity")
                        and float(rule.get("min_confidence", 0))
                        <= f.get("confidence", 0)
                        < max_conf
                    ):
                        triggered_review_rules.append({"rule": rule, "finding": f})
                        break

        # Decision logic with policy-based verdict
        if triggered_block_rules:
            verdict = "BLOCK"
        elif triggered_review_rules or len(block_findings) > 0:
            verdict = "REVIEW_REQUIRED"
        elif len(warn_findings) > 0:
            verdict = "REVIEW_REQUIRED"
        else:
            verdict = "PASS"

        # Generate decision record for audit trail
        run_id = generate_run_id()
        decision_record = {
            "schema_version": SCHEMA_VERSION,
            "decision_id": generate_decision_id(),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "verdict": verdict,
            "policy": {
                "policy_version": POLICY["version"],
                "policy_url": "https://github.com/adarian-dewberry/code-review-agent/blob/main/POLICIES.md",
                "block_rules": [
                    {
                        "rule_id": r["rule"]["rule_id"],
                        "description": r["rule"]["description"],
                        "triggered": True,
                    }
                    for r in triggered_block_rules
                ],
                "review_rules": [
                    {
                        "rule_id": r["rule"]["rule_id"],
                        "description": r["rule"]["description"],
                        "triggered": True,
                    }
                    for r in triggered_review_rules
                ],
            },
            "decision_drivers": [
                {
                    "finding_id": f.get("id", "unknown"),
                    "title": f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "confidence": f.get("confidence", 0),
                    "cwe": f.get("cwe", None),
                    "owasp": f.get("owasp", None),
                    "location": f.get("location", ""),
                    "why_it_matters": f.get(
                        "why_it_matters", [f.get("description", "")]
                    ),
                }
                for f in (block_findings + warn_findings)[:5]  # Top 5 drivers
            ],
            "override": {
                "allowed": True,
                "status": "none",
                "approver": None,
                "justification": None,
            },
            "run_context": {
                "run_id": run_id,
                "mode": "manual",
                "source": "stdin",
                "files_reviewed": 1,
                "limits": {
                    "max_chars": 50000,
                    "truncated": len(code) > 50000,
                },
            },
        }

        # Extract blast radius summaries for HIGH/CRITICAL findings
        blast_radius_findings = []
        for f in findings:
            if f.get("severity") in ["CRITICAL", "HIGH"] and f.get("blast_radius"):
                blast_radius_findings.append(
                    {
                        "finding_id": f.get("id", "unknown"),
                        "blast_radius": f.get("blast_radius"),
                        "confidence": f.get("confidence", 0),
                    }
                )

        # Check for high blast radius findings (for UI indicator)
        has_high_blast = any(
            br.get("blast_radius", {}).get("data_scope") in ["pii", "regulated"]
            or br.get("blast_radius", {}).get("org_scope")
            in ["external-customers", "regulators"]
            for br in blast_radius_findings
        )

        # Get top confidence for easter egg selection
        top_confidence = max((f.get("confidence", 0) for f in findings), default=0)

        # Default audience mode (will be passed from UI in future)
        audience_mode = "intermediate"

        # Try to select an easter egg (respects voice guidelines)
        easter_egg = select_easter_egg(verdict, top_confidence, audience_mode)

        # Build verdict copy from curated UI_COPY
        # IMPORTANT: Do not generate new UI copy here.
        base_copy = UI_COPY.get(verdict, UI_COPY["PASS"])

        # Use easter egg for subtext if available (never on BLOCK)
        subtext = easter_egg if easter_egg else base_copy["subtext"]

        # Count findings by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "MEDIUM")
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Verdict display config
        verdict_config = {
            "BLOCK": {
                "icon": "⚠️",
                "css_class": "block",
                "dot_color": "#FF9800",
            },
            "REVIEW_REQUIRED": {
                "icon": "⚠️",
                "css_class": "review",
                "dot_color": "#CD8F7A",
            },
            "PASS": {
                "icon": "✅",
                "css_class": "pass",
                "dot_color": "#28a745",
            },
        }

        vc = verdict_config.get(verdict, verdict_config["PASS"])

        # Build top 3 fixes for quick action
        top_fixes_html = ""
        sorted_findings = sorted(
            findings,
            key=lambda x: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                    x.get("severity", "LOW"), 4
                ),
                -x.get("confidence", 0),
            ),
        )
        for i, f in enumerate(sorted_findings[:3]):
            sev = f.get("severity", "MEDIUM").lower()
            safe_title = html.escape(f.get("title", "Issue"))
            location = f.get("location") or (
                f"Line {f.get('line')}" if f.get("line") else "—"
            )
            safe_location = html.escape(str(location))
            owasp = f.get("owasp", "")
            cwe = f.get("cwe", "")
            tags = f" · {owasp}" if owasp else (f" · {cwe}" if cwe else "")
            top_fixes_html += f"""
            <div class="top_fix">
                <div class="fix_number">{i + 1}</div>
                <div class="fix_content">
                    <div class="fix_title">{safe_title}</div>
                    <div class="fix_meta">
                        <span class="fix_severity {sev}">{sev.upper()}</span>
                        <span>{safe_location}{tags}</span>
                    </div>
                </div>
            </div>"""

        # Extract review mode display name
        review_mode_display = (
            review_mode.replace("⚡ ", "").replace("🔬 ", "").replace("📋 ", "")
            if review_mode
            else "Deep"
        )
        review_mode_icon = (
            "⚡"
            if "Quick" in (review_mode or "")
            else "📋"
            if "Compliance" in (review_mode or "")
            else "🔬"
        )

        # Premium verdict card with severity counters
        summary = f"""
<div id="verdict_card">
    <div class="verdict_header">
        <div class="verdict_icon {vc["css_class"]}">{vc["icon"]}</div>
        <div class="verdict_main">
            <div class="verdict_pill {vc["css_class"]}">
                <span style="width: 8px; height: 8px; background: {vc["dot_color"]}; border-radius: 50%;"></span>
                {verdict.replace("_", " ")}
            </div>
            <h2 class="verdict_headline">{base_copy["headline"]}</h2>
            <p class="verdict_subtext">{subtext}</p>
        </div>
    </div>

    <div class="severity_counters">
        <div class="severity_counter">
            <div class="counter_value critical">{severity_counts["CRITICAL"]}</div>
            <div class="counter_label">Critical</div>
        </div>
        <div class="severity_counter">
            <div class="counter_value high">{severity_counts["HIGH"]}</div>
            <div class="counter_label">High</div>
        </div>
        <div class="severity_counter">
            <div class="counter_value medium">{severity_counts["MEDIUM"]}</div>
            <div class="counter_label">Medium</div>
        </div>
        <div class="severity_counter">
            <div class="counter_value low">{severity_counts["LOW"]}</div>
            <div class="counter_label">Low</div>
        </div>
    </div>

    {"<div class='top_fixes'><div class='top_fixes_title'>Top Fixes</div>" + top_fixes_html + "</div>" if findings else ""}

    <div class="trust_signals">
        <span class="trust_signal">{review_mode_icon} <strong>{review_mode_display}</strong> mode</span>
        <span class="trust_signal">📊 <strong>{len(findings)}</strong> finding{"s" if len(findings) != 1 else ""}</span>
        <span class="trust_signal">📁 <strong>1</strong> file analyzed</span>
        <span class="trust_signal">🎯 <strong>{base_copy["confidence_text"]}</strong></span>
        {"<span class='trust_signal' title='This vulnerability could affect multiple parts of the system or have cascading effects'>💥 <strong>High Blast Radius</strong></span>" if has_high_blast else ""}
    </div>
</div>
<p style="font-size: 0.78em; color: #A89F91; margin-top: 10px; text-align: center;">
    Decision ID: <code style="background: rgba(0,0,0,0.05); padding: 2px 6px; border-radius: 4px;">{decision_record["decision_id"]}</code> · Policy: {POLICY["version"]}
</p>
"""

        # Build detailed markdown report with progressive disclosure
        details = ""

        if not findings:
            details += """
## ✅ No issues found

This code follows safe patterns based on the signals we checked.

<div style="background: rgba(40,167,69,0.08); border-left: 3px solid #28a745; padding: 16px; border-radius: 0 8px 8px 0; margin: 16px 0;">

**What was checked:**
- SQL injection patterns
- Cross-site scripting (XSS)
- Hardcoded secrets
- Prompt injection (for LLM code)
- Access control issues

</div>

*This doesn't guarantee zero risk, but no concerning patterns were detected in this review.*
"""
        else:
            # Layer 1: Plain language overview (Beginner-friendly)
            details += "## 🔍 What we found\n\n"

            for i, f in enumerate(sorted_findings[:3]):  # Top 3 for overview
                sev = f.get("severity", "MEDIUM")
                border_color = {
                    "CRITICAL": "#FF9800",
                    "HIGH": "#e67700",
                    "MEDIUM": "#ffc107",
                    "LOW": "#6c757d",
                }.get(sev, "#D8C5B2")

                # Plain language explanation - escape to prevent XSS
                plain_title = html.escape(f.get("title", "Issue"))
                plain_desc = html.escape(f.get("description", "An issue was detected."))
                plain_impact = html.escape(
                    f.get("impact", "This could affect how the code behaves.")
                )
                plain_rec = html.escape(
                    f.get("recommendation", "Review and address this issue.")
                )

                details += f"""
<div style="border-left: 3px solid {border_color}; padding-left: 16px; margin-bottom: 20px;">

**{plain_title}**

{plain_desc}

**Why this matters:** {plain_impact}

**What to do:** {plain_rec}

</div>
"""

            if len(findings) > 3:
                details += f"\n*+ {len(findings) - 3} more finding{'s' if len(findings) - 3 != 1 else ''} below*\n"

            # Add "What was checked" context to all findings
            details += """
<div style="background: rgba(32,201,51,0.08); border-left: 3px solid #28a745; padding: 16px; border-radius: 0 8px 8px 0; margin: 16px 0;">

**What was checked:**
- SQL injection patterns
- Cross-site scripting (XSS)
- Hardcoded secrets
- Prompt injection (for LLM code)
- Access control issues

</div>
"""

            # Layer 2: Findings Table (Intermediate - scannable)
            details += "\n---\n\n## 📋 All Findings\n\n"

            # Build findings table HTML
            details += """<table class="findings_table">
<thead>
<tr>
<th>Severity</th>
<th>Title</th>
<th>Location</th>
<th title="Likelihood this issue is a true positive">Confidence</th>
</tr>
</thead>
<tbody>
"""
            for f in sorted_findings:
                sev = f.get("severity", "MEDIUM")
                sev_lower = sev.lower()
                safe_title = html.escape(f.get("title", "Issue"))
                location = f.get("location") or (
                    f"Line {f.get('line')}" if f.get("line") else "—"
                )
                safe_location = html.escape(str(location))
                conf = f.get("confidence", 0)
                conf_pct = int(conf * 100)

                details += f"""<tr>
<td><span class="severity_badge {sev_lower}">{sev}</span></td>
<td><strong>{safe_title}</strong></td>
<td><code>{safe_location}</code></td>
<td><div class="confidence_bar"><div class="confidence_fill" style="width: {conf_pct}%"></div></div> <span title="{conf_pct}% confidence in this finding">{conf_pct}%</span></td>
</tr>
"""
            details += "</tbody></table>\n\n"

            # Layer 3: Technical details by root cause (Advanced)
            details += "---\n\n## 🔬 Technical Analysis\n\n"

            # Group by root cause
            root_causes: dict[str, list[dict[str, Any]]] = {}
            for f in sorted_findings:
                rc = f.get("root_cause", f.get("title", "Other"))
                if rc not in root_causes:
                    root_causes[rc] = []
                root_causes[rc].append(f)

            for root_cause, items in root_causes.items():
                # Escape root cause for XSS prevention
                safe_root_cause = html.escape(root_cause)
                details += f"### 🎯 {safe_root_cause}\n\n"

                for f in items:
                    sev = f.get("severity", "UNKNOWN")
                    conf = f.get("confidence", 0)
                    conf_text = (
                        "High confidence"
                        if conf >= 0.8
                        else "Medium confidence"
                        if conf >= 0.5
                        else "Low confidence"
                    )

                    # Escape dynamic content for XSS prevention
                    safe_title = html.escape(f.get("title", "Issue"))
                    details += f"**{safe_title}** · {sev} · {conf_text}\n\n"

                    location = f.get("location") or (
                        f"Line {f.get('line')}" if f.get("line") else None
                    )
                    if location:
                        safe_location = html.escape(str(location))
                        details += f"Location: `{safe_location}`\n\n"

                    if f.get("evidence"):
                        # Evidence in code block - escape for safety
                        safe_evidence = html.escape(str(f.get("evidence", "")))
                        details += f"```\n{safe_evidence}\n```\n\n"
                    elif f.get("snippet"):
                        safe_snippet = html.escape(str(f.get("snippet", "")))
                        details += f"```python\n{safe_snippet}\n```\n\n"

                    if f.get("tags"):
                        safe_tags = ", ".join(html.escape(t) for t in f.get("tags", []))
                        details += f"Tags: {safe_tags}\n\n"

                    # Blast radius for HIGH/CRITICAL
                    br = f.get("blast_radius")
                    if br and sev in ["CRITICAL", "HIGH"]:
                        details += (
                            "<details>\n<summary>Blast Radius Estimate</summary>\n\n"
                        )
                        details += f"- **Technical:** {html.escape(br.get('technical_scope', 'unknown'))}\n"
                        details += f"- **Data:** {html.escape(br.get('data_scope', 'unknown'))}\n"
                        details += f"- **Organizational:** {html.escape(br.get('org_scope', 'unknown'))}\n\n"
                        details += "</details>\n\n"

                    if f.get("escalation") and sev in ["HIGH", "MEDIUM"]:
                        safe_escalation = html.escape(str(f.get("escalation", "")))
                        details += f"*Escalates to CRITICAL if: {safe_escalation}*\n\n"

                details += "---\n\n"

        # Decision accountability section (collapsible)
        if triggered_block_rules or triggered_review_rules:
            details += "<details>\n<summary>Decision Reasoning</summary>\n\n"
            details += "**Why this verdict was reached:**\n\n"
            for tr in triggered_block_rules:
                details += (
                    f"- **{tr['rule']['rule_id']}**: {tr['rule']['description']}\n"
                )
            for tr in triggered_review_rules:
                details += (
                    f"- **{tr['rule']['rule_id']}**: {tr['rule']['description']}\n"
                )
            details += "\n*Override allowed with human approval + justification*\n\n"
            details += "</details>\n\n"

        # Audit record (Advanced tab content)
        details += "<details>\n<summary>Audit Record (JSON)</summary>\n\n```json\n"
        details += json.dumps(decision_record, indent=2)
        details += "\n```\n</details>\n"

        # Generate Fixes tab content with consolidated recommendations
        fixes_content = ""
        if findings:
            fixes_content = "## 🔧 Recommended Fixes\n\n"
            fixes_content += (
                "Prioritized by severity and confidence. Address these in order.\n\n"
            )

            for i, f in enumerate(sorted_findings):
                sev = f.get("severity", "MEDIUM")
                sev_emoji = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "⚪",
                }.get(sev, "⚪")
                safe_title = html.escape(f.get("title", "Issue"))
                location = f.get("location") or (
                    f"Line {f.get('line')}" if f.get("line") else "—"
                )
                safe_location = html.escape(str(location))
                safe_rec = html.escape(
                    f.get("recommendation", "Review and address this issue.")
                )

                fixes_content += f"### {sev_emoji} {i + 1}. {safe_title}\n\n"
                fixes_content += f"**Location:** `{safe_location}`\n\n"
                fixes_content += f"**Fix:** {safe_rec}\n\n"

                # Add evidence if available
                if f.get("evidence"):
                    safe_evidence = html.escape(str(f.get("evidence", "")))
                    fixes_content += f"<details>\n<summary>Show vulnerable code</summary>\n\n```\n{safe_evidence}\n```\n</details>\n\n"

                fixes_content += "---\n\n"
        else:
            fixes_content = "## ✅ No Fixes Needed\n\nThis code follows safe patterns. No changes required based on this review."

        # Cache the result for future identical requests
        result = (summary, details, fixes_content, decision_record)
        review_cache.set(code, cache_key_cats, result)
        logger.info(f"Review complete: verdict={verdict}, findings={len(findings)}")

        return result

    except anthropic.AuthenticationError as e:
        logger.error(f"Authentication error: {e}")
        return (
            "<div class='error-banner error'><div class='error-icon'>🔐</div><div class='error-content'><h3>Invalid API key</h3><p>The API key was rejected. Double-check <code>ANTHROPIC_API_KEY</code> in Settings → Secrets.</p></div></div>",
            "",
            "",
            None,
        )

    except anthropic.NotFoundError as e:
        logger.error(f"Model not found: {e}")
        return (
            "<div class='error-banner error'><div class='error-icon'>🤖</div><div class='error-content'><h3>Model unavailable</h3><p>The AI model isn't responding right now. This usually resolves in a few minutes.</p></div></div>",
            "",
            "",
            None,
        )

    except anthropic.APIConnectionError as e:
        # Log full error server-side
        error_detail = str(e)
        logger.error(f"API connection error: {error_detail}")
        if "SSL" in error_detail or "certificate" in error_detail.lower():
            hint = "There's a secure connection issue. The team has been notified."
        elif "timeout" in error_detail.lower():
            hint = "The request timed out. Try again in a moment."
        else:
            hint = "Can't reach the AI service right now. Try again in a few seconds."
        return (
            f"<div class='error-banner error'><div class='error-icon'>🌐</div><div class='error-content'><h3>Connection issue</h3><p>{hint}</p></div></div>",
            "",
            "",
            None,
        )

    except anthropic.BadRequestError as e:
        logger.error(f"Bad request error: {e}")
        return (
            "<div class='error-banner error'><div class='error-icon'>📋</div><div class='error-content'><h3>Couldn't process that</h3><p>The code might be too complex or contain unusual characters. Try a smaller snippet.</p></div></div>",
            "",
            "",
            None,
        )

    except Exception:
        # Log full exception server-side, show generic message to users
        logger.exception("Unexpected error during code review")
        return (
            "<div class='error-banner error'><div class='error-icon'>🐛</div><div class='error-content'><h3>Something went wrong</h3><p>We hit an unexpected error. Try again, or <a href='https://github.com/adarian-dewberry/code-review-agent/issues' target='_blank'>report this</a> if it keeps happening.</p></div></div>",
            "",
            "",
            None,
        )

    finally:
        # Ensure HTTP client is always closed
        if http_client:
            http_client.close()


# Theme configuration for Gradio
APP_THEME = gr.themes.Base(
    primary_hue=gr.themes.colors.orange,
    secondary_hue=gr.themes.colors.stone,
    neutral_hue=gr.themes.colors.stone,
    font=gr.themes.GoogleFont("Inter"),
    font_mono=gr.themes.GoogleFont("JetBrains Mono"),
)

APP_CSS = """
/* =================================================================
   2026 TECH-FORWARD UI v2 - Premium Security Console
   Design: Compact, readable, persona-aware
   Rule: Results above the fold, clear hierarchy
   Rule: Frankie owns processing, not output
   ================================================================= */

/* Global mobile viewport fix */
html, body {
  max-width: 100vw !important;
  overflow-x: hidden !important;
  width: 100% !important;
}

/* Prevent any element from causing horizontal overflow */
body > *, .gradio-container > * {
  max-width: 100% !important;
}

:root {
  /* Light canvas (Light mode) */
  --bg: #FAF8F4;
  --panel: #E7DCCE;
  --panel2: #D8C5B2;
  --text: #2A2926;
  --text2: #1B1A18;
  --muted: #6B6560;
  --accent: #CD8F7A;
  --accent-dark: #B87A65;
  --gold: #DCCCB3;

  /* Severity colors */
  --critical: #dc3545;
  --high: #e67700;
  --medium: #d4a017;
  --low: #6c757d;
  --pass: #28a745;

  /* Dark spine */
  --spine: #1B1A18;
  --spine2: #2A2926;
  --spineText: #FAF8F4;

  /* UI tokens */
  --radius: 16px;
  --radiusSm: 10px;
  --radiusXs: 6px;
  --border: rgba(42,41,38,0.12);
  --shadow: 0 8px 24px rgba(27,26,24,0.10);
  --shadow-sm: 0 4px 12px rgba(27,26,24,0.08);

  /* Typography - LARGER for readability */
  --font-base: 1rem;
  --font-lg: 1.125rem;
  --font-xl: 1.25rem;
  --font-2xl: 1.5rem;
  --font-sm: 0.9rem;
  --font-xs: 0.8rem;

  /* Animation */
  --transition: all 0.2s ease;
}

/* Dark mode */
body[data-theme="dark-mode"] {
  --bg: #1B1A18;
  --panel: #2A2926;
  --panel2: #2A2926;
  --text: #FAF8F4;
  --text2: #FAF8F4;
  --muted: rgba(250,248,244,0.65);
  --border: rgba(250,248,244,0.14);
  --shadow: 0 12px 36px rgba(0,0,0,0.35);
  --shadow-sm: 0 4px 12px rgba(0,0,0,0.25);
  --spine: #121110;
  --spine2: #1B1A18;
}

/* Reduced motion support */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}

/* Page */
.gradio-container {
  background: var(--bg) !important;
  color: var(--text2) !important;
  max-width: 1200px !important;
  margin: 0 auto !important;
  font-family: 'Inter', system-ui, sans-serif !important;
  font-size: var(--font-base) !important;
  box-sizing: border-box !important;
}

/* Ensure all elements use border-box */
*, *::before, *::after {
  box-sizing: border-box;
}

/* =================================================================
   HEADER - Compact hero with trust signals
   ================================================================= */
#brand_header {
  text-align: center;
  padding: 28px 20px 32px 20px;
  background: linear-gradient(145deg, rgba(205,143,122,0.05) 0%, rgba(220,204,179,0.08) 100%);
  border-bottom: 1px solid var(--border);
  margin: -12px -12px 20px -12px;
  border-radius: var(--radius) var(--radius) 0 0;
}
.header_badge {
  display: inline-block;
  background: linear-gradient(135deg, var(--accent), var(--accent-dark));
  color: white;
  font-size: var(--font-xs);
  font-weight: 700;
  padding: 5px 14px;
  border-radius: 999px;
  letter-spacing: 0.08em;
  margin-bottom: 12px;
  box-shadow: 0 3px 10px rgba(205,143,122,0.25);
}
#brand_title {
  font-family: 'Playfair Display', Georgia, serif;
  font-size: 2.2em;
  font-weight: 600;
  color: var(--text);
  margin: 0;
  line-height: 1.1;
}
.header_tagline {
  font-size: var(--font-lg);
  color: var(--accent);
  font-weight: 600;
  margin-top: 4px;
}
#brand_subtitle {
  font-size: var(--font-base);
  color: var(--muted);
  margin-top: 10px;
  line-height: 1.5;
  max-width: 580px;
  margin-left: auto;
  margin-right: auto;
}
.header_features {
  display: flex;
  justify-content: center;
  gap: 12px;
  margin-top: 16px;
  flex-wrap: wrap;
}
.feature_tag {
  font-size: var(--font-sm);
  color: var(--muted);
  padding: 6px 14px;
  background: rgba(255,255,255,0.5);
  border: 1px solid var(--border);
  border-radius: 999px;
  font-weight: 500;
}
body[data-theme="dark-mode"] #brand_header {
  background: linear-gradient(145deg, rgba(205,143,122,0.08) 0%, rgba(42,41,38,0.6) 100%);
}
body[data-theme="dark-mode"] .feature_tag {
  background: rgba(42,41,38,0.6);
  color: rgba(250,248,244,0.75);
}

/* =================================================================
   THEME TOGGLE - Compact
   ================================================================= */
#mode_toggle {
  display: flex;
  justify-content: center;
  margin-bottom: 16px;
}
#mode_toggle .wrap {
  background: var(--panel) !important;
  border: 1px solid var(--border) !important;
  border-radius: 999px !important;
  padding: 4px 6px !important;
}
#mode_toggle label {
  padding: 6px 18px !important;
  border-radius: 999px !important;
  font-weight: 600 !important;
  font-size: var(--font-sm) !important;
  cursor: pointer !important;
}
#mode_toggle input:checked + label {
  background: var(--accent) !important;
  color: var(--bg) !important;
}
body[data-theme="dark-mode"] #mode_toggle .wrap {
  background: var(--spine2) !important;
}

/* =================================================================
   MAIN SHELL - Tighter layout
   ================================================================= */
#shell {
  gap: 0 !important;
}

/* LEFT: Dark input spine - COMPACT */
#left_spine {
  background: var(--spine) !important;
  border-radius: var(--radius) 0 0 var(--radius) !important;
  padding: 20px !important;
  border: none !important;
}
#left_spine .block, #left_spine .form {
  background: transparent !important;
  border: none !important;
}

/* Spine labels - LARGER */
.spine_label {
  color: var(--accent);
  font-size: var(--font-sm);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 6px;
  font-weight: 700;
}
.spine_title {
  color: var(--spineText);
  font-weight: 700;
  font-size: var(--font-xl);
  margin-bottom: 6px;
  line-height: 1.3;
}
.spine_hint {
  color: rgba(250,248,244,0.6);
  font-size: var(--font-base);
  margin-bottom: 14px;
  line-height: 1.4;
}

/* Code editor - reasonable height */
#left_spine textarea, #left_spine .cm-editor {
  background: var(--spine2) !important;
  color: var(--spineText) !important;
  border: 1px solid rgba(250,248,244,0.12) !important;
  border-radius: var(--radiusSm) !important;
  font-family: 'JetBrains Mono', ui-monospace, monospace !important;
  font-size: var(--font-base) !important;
  min-height: 200px !important;
  max-height: 300px !important;
  line-height: 1.5 !important;
}
#left_spine textarea:focus, #left_spine .cm-editor.cm-focused {
  outline: none !important;
  box-shadow: 0 0 0 2px rgba(205,143,122,0.4) !important;
  border-color: var(--accent) !important;
}

/* =================================================================
   REVIEW MODE SELECTOR - LARGER, more readable
   ================================================================= */
#review_mode_container {
  margin: 14px 0;
}
.review_mode_header {
  color: var(--accent);
  font-size: var(--font-sm);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 10px;
  font-weight: 700;
}
#review_mode .wrap {
  display: flex !important;
  gap: 8px !important;
  background: transparent !important;
  padding: 0 !important;
  border: none !important;
}
#review_mode label {
  flex: 1 !important;
  text-align: center !important;
  padding: 12px 10px !important;
  background: rgba(250,248,244,0.08) !important;
  border: 1px solid rgba(250,248,244,0.18) !important;
  border-radius: var(--radiusSm) !important;
  color: rgba(250,248,244,0.9) !important;
  font-weight: 600 !important;
  font-size: var(--font-base) !important;
  cursor: pointer !important;
  transition: var(--transition) !important;
}
#review_mode label:hover {
  background: rgba(250,248,244,0.14) !important;
}
#review_mode input:checked + label {
  background: linear-gradient(135deg, var(--accent), var(--accent-dark)) !important;
  border-color: var(--accent) !important;
  color: white !important;
  box-shadow: 0 3px 12px rgba(205,143,122,0.35) !important;
}
.mode_descriptions {
  margin-top: 10px;
  padding: 10px 12px;
  background: rgba(250,248,244,0.06);
  border-radius: var(--radiusXs);
  color: rgba(250,248,244,0.7);
  font-size: var(--font-base);
  line-height: 1.5;
}
.mode_descriptions strong {
  color: rgba(250,248,244,0.95);
}

/* Action buttons */
#action_buttons {
  margin-top: 12px !important;
  gap: 10px !important;
}
#review_btn button {
  background: linear-gradient(180deg, #D9977F 0%, var(--accent) 50%, #B87A65 100%) !important;
  color: white !important;
  border: none !important;
  border-radius: 12px !important;
  padding: 14px 20px !important;
  font-weight: 700 !important;
  font-size: var(--font-lg) !important;
  width: 100% !important;
  cursor: pointer !important;
  box-shadow: 0 3px 0 #9A6555, 0 4px 10px rgba(154,101,85,0.3) !important;
}
#review_btn button:hover {
  transform: translateY(-1px) !important;
  box-shadow: 0 4px 0 #9A6555, 0 6px 14px rgba(154,101,85,0.35) !important;
}
#sample_btn button {
  background: rgba(250,248,244,0.1) !important;
  color: rgba(250,248,244,0.9) !important;
  border: 1px solid rgba(250,248,244,0.2) !important;
  border-radius: 12px !important;
  padding: 14px 20px !important;
  font-weight: 600 !important;
  font-size: var(--font-lg) !important;
  width: 100% !important;
}

/* Filename input - compact */
#filename_box {
  margin-top: 12px !important;
}
#filename_box input {
  background: rgba(250,248,244,0.08) !important;
  color: var(--spineText) !important;
  border: 1px solid rgba(250,248,244,0.18) !important;
  border-radius: var(--radiusSm) !important;
  padding: 10px 14px !important;
  font-size: var(--font-base) !important;
}
#filename_box label {
  color: rgba(250,248,244,0.8) !important;
  font-size: var(--font-base) !important;
  font-weight: 500 !important;
}

/* Fine-tune accordion - VISIBLE, not hidden */
#customize_acc {
  margin-top: 16px !important;
  background: rgba(42,41,38,0.3) !important;
  border: 2px solid rgba(205,143,122,0.4) !important;
  border-radius: var(--radiusSm) !important;
}
#customize_acc .label-wrap {
  color: #FAF8F4 !important;
  font-weight: 700 !important;
  font-size: 1.05em !important;
  padding: 14px 16px !important;
}
#customize_acc .icon {
  color: var(--accent) !important;
  font-size: 1.2em !important;
}
.beginner_tip {
  background: rgba(205,143,122,0.12);
  border: 2px solid rgba(205,143,122,0.5);
  border-radius: var(--radiusXs);
  padding: 14px 16px;
  margin-bottom: 16px;
  color: #FAF8F4;
  font-size: 0.95em;
  line-height: 1.6;
  font-weight: 500;
}
.config_section_title {
  color: #FAF8F4;
  font-weight: 700;
  font-size: 1.1em;
  margin-top: 4px;
  margin-bottom: 16px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  font-size: var(--font-md);
}
#customize_acc label {
  color: #FAF8F4 !important;
  font-size: var(--font-base) !important;
  font-weight: 600 !important;
  margin-bottom: 6px !important;
}
#customize_acc .info {
  font-size: var(--font-sm) !important;
  color: rgba(250,248,244,0.75) !important;
  font-weight: 400 !important;
  line-height: 1.4 !important;
}

/* =================================================================
   RIGHT PANEL - Results (PRIORITY ZONE)
   ================================================================= */
#right_panel {
  background: rgba(231,220,206,0.35) !important;
  border: 1px solid var(--border) !important;
  border-left: none !important;
  border-radius: 0 var(--radius) var(--radius) 0 !important;
  padding: 20px !important;
}
body[data-theme="dark-mode"] #right_panel {
  background: rgba(42,41,38,0.5) !important;
}
#right_panel .block, #right_panel .form {
  background: transparent !important;
  border: none !important;
}

.results_label {
  color: var(--accent);
  font-size: var(--font-sm);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 4px;
  font-weight: 700;
}
.results_title {
  color: var(--text);
  font-weight: 700;
  font-size: var(--font-2xl);
  margin-bottom: 16px;
  line-height: 1.2;
}

/* Right panel global text color - ensures all content inherits correct color */
#right_panel, #right_panel * {
  color: var(--text);
}
body[data-theme="dark-mode"] #right_panel,
body[data-theme="dark-mode"] #right_panel * {
  color: #FAF8F4;
}
/* Preserve specific colors that should NOT be overridden */
#right_panel .severity_badge,
#right_panel .counter_value,
#right_panel .verdict_pill,
#right_panel a {
  color: inherit;
}

/* =================================================================
   EMPTY STATE - Clear CTA
   ================================================================= */
#empty_state {
  background: linear-gradient(145deg, rgba(250,248,244,0.8), rgba(231,220,206,0.5));
  border: 2px dashed rgba(42,41,38,0.2);
  border-radius: var(--radiusSm);
  padding: 40px 24px;
  text-align: center;
}
#empty_state .empty_icon {
  font-size: 2.5em;
  margin-bottom: 12px;
}
#empty_state .empty_title {
  font-weight: 700;
  font-size: var(--font-xl);
  color: var(--text);
  margin-bottom: 10px;
}
#empty_state .empty_text {
  color: var(--muted);
  font-size: var(--font-base);
  line-height: 1.5;
  margin-bottom: 14px;
}
#empty_state .empty_hint {
  color: var(--accent);
  font-size: var(--font-base);
  font-weight: 600;
}
body[data-theme="dark-mode"] #empty_state {
  background: linear-gradient(145deg, rgba(42,41,38,0.7), rgba(27,26,24,0.6));
  border-color: rgba(250,248,244,0.15);
}

/* =================================================================
   VERDICT CARD - Premium, compact
   ================================================================= */
#verdict_card {
  background: linear-gradient(145deg, rgba(250,248,244,0.95), rgba(231,220,206,0.85));
  border: 1px solid var(--border);
  border-radius: var(--radiusSm);
  padding: 0;
  margin-bottom: 16px;
  overflow: hidden;
  box-shadow: var(--shadow-sm);
}
body[data-theme="dark-mode"] #verdict_card {
  background: linear-gradient(145deg, rgba(42,41,38,0.9), rgba(27,26,24,0.8));
}

.verdict_header {
  padding: 16px 20px;
  display: flex;
  align-items: center;
  gap: 14px;
  border-bottom: 1px solid var(--border);
}
.verdict_icon {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.4em;
  flex-shrink: 0;
}
.verdict_icon.block { background: rgba(220,53,69,0.15); }
.verdict_icon.review { background: rgba(205,143,122,0.2); }
.verdict_icon.pass { background: rgba(40,167,69,0.15); }

.verdict_main { flex: 1; }
.verdict_pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 12px;
  border-radius: 999px;
  font-weight: 700;
  font-size: var(--font-xs);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 4px;
}
.verdict_pill.block { background: rgba(220,53,69,0.16); color: var(--critical); }
.verdict_pill.review { background: rgba(205,143,122,0.2); color: var(--accent-dark); }
.verdict_pill.pass { background: rgba(40,167,69,0.16); color: var(--pass); }

.verdict_headline {
  font-family: 'Playfair Display', Georgia, serif;
  font-size: var(--font-xl);
  font-weight: 500;
  color: var(--text);
  margin: 0;
  line-height: 1.3;
}
.verdict_subtext {
  color: var(--muted);
  font-size: var(--font-sm);
  margin-top: 3px;
  line-height: 1.4;
}

/* =================================================================
   SEVERITY COUNTERS - Fixed width, no wrapping
   ================================================================= */
.severity_counters {
  display: flex;
  gap: 0;
  background: rgba(0,0,0,0.02);
}
body[data-theme="dark-mode"] .severity_counters {
  background: rgba(0,0,0,0.12);
}
.severity_counter {
  flex: 1;
  padding: 12px 8px;
  text-align: center;
  border-right: 1px solid var(--border);
  min-width: 70px;
}
.severity_counter:last-child {
  border-right: none;
}
.counter_value {
  font-size: var(--font-2xl);
  font-weight: 700;
  line-height: 1;
}
.counter_value.critical { color: var(--critical); }
.counter_value.high { color: var(--high); }
.counter_value.medium { color: var(--medium); }
.counter_value.low { color: var(--low); }
.counter_label {
  font-size: var(--font-xs);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--muted);
  margin-top: 4px;
  font-weight: 600;
  white-space: nowrap;
}

/* =================================================================
   TOP FIXES - Compact, actionable
   ================================================================= */
.top_fixes {
  padding: 14px 20px;
  border-bottom: 1px solid var(--border);
}
.top_fixes_title {
  font-weight: 700;
  font-size: var(--font-sm);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--muted);
  margin-bottom: 10px;
}
.top_fix {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 12px;
  background: rgba(255,255,255,0.5);
  border: 1px solid var(--border);
  border-radius: var(--radiusXs);
  margin-bottom: 8px;
}
body[data-theme="dark-mode"] .top_fix {
  background: rgba(42,41,38,0.5);
}
.fix_number {
  width: 22px;
  height: 22px;
  border-radius: 50%;
  background: var(--accent);
  color: white;
  font-size: var(--font-xs);
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.fix_content { flex: 1; }
.fix_title {
  font-weight: 600;
  color: var(--text);
  font-size: var(--font-base);
  margin-bottom: 2px;
}
.fix_meta {
  display: flex;
  gap: 10px;
  font-size: var(--font-sm);
  color: var(--muted);
}
.fix_severity {
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: var(--font-xs);
  white-space: nowrap;
}
.fix_severity.critical { background: rgba(220,53,69,0.14); color: var(--critical); }
.fix_severity.high { background: rgba(230,119,0,0.14); color: var(--high); }
.fix_severity.medium { background: rgba(212,160,23,0.14); color: var(--medium); }

/* Trust signals - compact */
.trust_signals {
  padding: 12px 20px;
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
  background: rgba(0,0,0,0.02);
  font-size: var(--font-sm);
  color: var(--muted);
}
body[data-theme="dark-mode"] .trust_signals {
  background: rgba(0,0,0,0.08);
}
.trust_signal {
  display: flex;
  align-items: center;
  gap: 5px;
}
.trust_signal strong {
  color: var(--text);
}

/* =================================================================
   TABS - CLEARLY CLICKABLE, prominent
   ================================================================= */
#right_panel .tabs {
  margin-top: 14px;
}
#right_panel .tab-nav {
  display: flex;
  gap: 4px;
  background: rgba(0,0,0,0.04);
  padding: 4px;
  border-radius: var(--radiusSm);
  margin-bottom: 14px;
}
body[data-theme="dark-mode"] #right_panel .tab-nav {
  background: rgba(0,0,0,0.2);
}
#right_panel .tab-nav button {
  flex: 1 !important;
  color: var(--muted) !important;
  font-weight: 600 !important;
  font-size: var(--font-base) !important;
  padding: 12px 16px !important;
  border-radius: var(--radiusXs) !important;
  border: none !important;
  background: transparent !important;
  cursor: pointer !important;
  transition: var(--transition) !important;
}
#right_panel .tab-nav button:hover {
  background: rgba(205,143,122,0.1) !important;
  color: var(--text) !important;
}
#right_panel .tab-nav button.selected {
  background: var(--bg) !important;
  color: var(--text) !important;
  box-shadow: 0 2px 8px rgba(0,0,0,0.1) !important;
}
body[data-theme="dark-mode"] #right_panel .tab-nav button.selected {
  background: var(--spine2) !important;
}

/* Tab content area */
#right_panel .tabitem {
  padding: 0 !important;
}

/* Markdown content styling for tabs */
#right_panel .tabitem .prose,
#right_panel .tabitem .markdown-body,
#right_panel .tabitem > div {
  color: var(--text) !important;
}
#right_panel .tabitem h1,
#right_panel .tabitem h2,
#right_panel .tabitem h3,
#right_panel .tabitem h4,
#right_panel .tabitem strong {
  color: var(--text) !important;
}
#right_panel .tabitem p,
#right_panel .tabitem li,
#right_panel .tabitem td,
#right_panel .tabitem span {
  color: var(--text) !important;
}
body[data-theme="dark-mode"] #right_panel .tabitem .prose,
body[data-theme="dark-mode"] #right_panel .tabitem .markdown-body,
body[data-theme="dark-mode"] #right_panel .tabitem > div {
  color: #FAF8F4 !important;
}
body[data-theme="dark-mode"] #right_panel .tabitem h1,
body[data-theme="dark-mode"] #right_panel .tabitem h2,
body[data-theme="dark-mode"] #right_panel .tabitem h3,
body[data-theme="dark-mode"] #right_panel .tabitem h4,
body[data-theme="dark-mode"] #right_panel .tabitem strong {
  color: #FAF8F4 !important;
}
body[data-theme="dark-mode"] #right_panel .tabitem p,
body[data-theme="dark-mode"] #right_panel .tabitem li,
body[data-theme="dark-mode"] #right_panel .tabitem td,
body[data-theme="dark-mode"] #right_panel .tabitem span {
  color: rgba(250,248,244,0.9) !important;
}

/* Details/Summary elements (Blast Radius, Decision Reasoning, Audit Record) */
#right_panel details {
  margin: 12px 0;
  border: 1px solid var(--border);
  border-radius: var(--radiusSm);
  padding: 0;
  background: rgba(0,0,0,0.02);
}
#right_panel summary {
  padding: 12px 16px;
  cursor: pointer;
  font-weight: 700;
  color: var(--text);
  background: rgba(0,0,0,0.03);
  border-radius: var(--radiusSm);
  list-style: none;
}
#right_panel summary::-webkit-details-marker {
  display: none;
}
#right_panel summary::before {
  content: "▶ ";
  font-size: 0.8em;
  margin-right: 6px;
  color: var(--accent);
}
#right_panel details[open] summary::before {
  content: "▼ ";
}
#right_panel details > *:not(summary) {
  padding: 0 16px 12px;
  color: var(--text);
}
body[data-theme="dark-mode"] #right_panel details {
  background: rgba(255,255,255,0.03);
  border-color: rgba(250,248,244,0.15);
}
body[data-theme="dark-mode"] #right_panel summary {
  color: #FAF8F4;
  background: rgba(255,255,255,0.05);
}
body[data-theme="dark-mode"] #right_panel details > *:not(summary) {
  color: rgba(250,248,244,0.9);
}

/* Code blocks in markdown content */
#right_panel code {
  background: rgba(0,0,0,0.06);
  color: var(--text);
  padding: 2px 6px;
  border-radius: 4px;
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: 0.9em;
}
#right_panel pre {
  background: rgba(0,0,0,0.04);
  border: 1px solid var(--border);
  border-radius: var(--radiusSm);
  padding: 12px 16px;
  overflow-x: auto;
  color: var(--text);
}
#right_panel pre code {
  background: transparent;
  padding: 0;
}
body[data-theme="dark-mode"] #right_panel code {
  background: rgba(255,255,255,0.1);
  color: #FAF8F4;
}
body[data-theme="dark-mode"] #right_panel pre {
  background: rgba(0,0,0,0.3);
  border-color: rgba(250,248,244,0.15);
  color: #FAF8F4;
}

/* Blockquotes */
#right_panel blockquote {
  border-left: 3px solid var(--accent);
  margin: 12px 0;
  padding: 8px 16px;
  background: rgba(205,143,122,0.08);
  color: var(--text);
}
body[data-theme="dark-mode"] #right_panel blockquote {
  background: rgba(205,143,122,0.12);
  color: rgba(250,248,244,0.9);
}

/* Horizontal rules */
#right_panel hr {
  border: none;
  border-top: 1px solid var(--border);
  margin: 20px 0;
}
body[data-theme="dark-mode"] #right_panel hr {
  border-color: rgba(250,248,244,0.15);
}

/* Lists */
#right_panel ul, #right_panel ol {
  padding-left: 24px;
  color: var(--text);
}
body[data-theme="dark-mode"] #right_panel ul,
body[data-theme="dark-mode"] #right_panel ol {
  color: rgba(250,248,244,0.9);
}

/* =================================================================
   FINDINGS TABLE - Fixed columns, no wrapping
   ================================================================= */
.findings_table {
  width: 100%;
  border-collapse: collapse;
  font-size: var(--font-sm);
  margin: 12px 0;
}
.findings_table th {
  text-align: left;
  padding: 10px 12px;
  background: rgba(0,0,0,0.04);
  border-bottom: 2px solid var(--border);
  font-weight: 700;
  font-size: var(--font-xs);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--muted);
  white-space: nowrap;
}
body[data-theme="dark-mode"] .findings_table th {
  background: rgba(255,255,255,0.04);
  color: rgba(250,248,244,0.7);
}
.findings_table td {
  padding: 12px 12px;
  border-bottom: 1px solid var(--border);
  vertical-align: middle;
  color: var(--text);
}
body[data-theme="dark-mode"] .findings_table td {
  color: #FAF8F4;
}
.findings_table tr:hover {
  background: rgba(205,143,122,0.05);
}
/* Fixed width severity column */
.findings_table td:first-child,
.findings_table th:first-child {
  width: 90px;
  min-width: 90px;
}
.severity_badge {
  display: inline-block;
  padding: 4px 10px;
  border-radius: 4px;
  font-size: var(--font-xs);
  font-weight: 700;
  text-transform: uppercase;
  white-space: nowrap;
  min-width: 70px;
  text-align: center;
}
.severity_badge.critical { background: rgba(220,53,69,0.14); color: var(--critical); }
.severity_badge.high { background: rgba(230,119,0,0.14); color: var(--high); }
.severity_badge.medium { background: rgba(212,160,23,0.14); color: #856404; }
.severity_badge.low { background: rgba(108,117,125,0.14); color: var(--low); }

.confidence_bar {
  width: 50px;
  height: 5px;
  background: rgba(0,0,0,0.1);
  border-radius: 3px;
  overflow: hidden;
  display: inline-block;
  vertical-align: middle;
  margin-right: 6px;
}
.confidence_fill {
  height: 100%;
  background: var(--accent);
  border-radius: 3px;
}

/* =================================================================
   FINDING CARDS - Inline fixes
   ================================================================= */
.finding_card {
  background: rgba(250,248,244,0.7);
  border: 1px solid var(--border);
  border-radius: var(--radiusSm);
  margin-bottom: 14px;
  overflow: hidden;
}
body[data-theme="dark-mode"] .finding_card {
  background: rgba(42,41,38,0.6);
}
.finding_card_header {
  padding: 14px 16px;
  display: flex;
  align-items: center;
  gap: 12px;
}
.finding_severity_dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
}
.finding_severity_dot.critical { background: var(--critical); }
.finding_severity_dot.high { background: var(--high); }
.finding_severity_dot.medium { background: var(--medium); }
.finding_severity_dot.low { background: var(--low); }

.finding_card_content {
  padding: 0 16px 14px 16px;
  border-top: 1px solid var(--border);
}
.finding_section {
  margin-top: 12px;
}
.finding_section_title {
  font-weight: 700;
  font-size: var(--font-xs);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--muted);
  margin-bottom: 6px;
}
.finding_evidence {
  background: var(--spine2);
  color: var(--spineText);
  padding: 12px 14px;
  border-radius: var(--radiusXs);
  font-family: 'JetBrains Mono', monospace;
  font-size: var(--font-sm);
  line-height: 1.5;
  overflow-x: auto;
}
.finding_recommendation {
  background: rgba(40,167,69,0.1);
  border-left: 3px solid var(--pass);
  padding: 12px 14px;
  border-radius: 0 var(--radiusXs) var(--radiusXs) 0;
  font-size: var(--font-base);
  line-height: 1.5;
}
.finding_tags {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  margin-top: 10px;
}
.finding_tag {
  font-size: var(--font-xs);
  padding: 3px 8px;
  background: rgba(205,143,122,0.12);
  color: var(--accent-dark);
  border-radius: 4px;
  font-weight: 600;
}

/* =================================================================
   ERROR BANNERS - User-friendly error states
   ================================================================= */
.error-banner {
  display: flex;
  align-items: flex-start;
  gap: 16px;
  padding: 20px 24px;
  border-radius: var(--radius);
  margin: 16px 0;
}
.error-banner.warning {
  background: linear-gradient(135deg, rgba(255,193,7,0.08) 0%, rgba(255,193,7,0.04) 100%);
  border: 1px solid rgba(255,193,7,0.3);
  border-left: 4px solid #ffc107;
}
.error-banner.error {
  background: linear-gradient(135deg, rgba(220,53,69,0.08) 0%, rgba(220,53,69,0.04) 100%);
  border: 1px solid rgba(220,53,69,0.3);
  border-left: 4px solid #dc3545;
}
.error-banner .error-icon {
  font-size: 1.75rem;
  flex-shrink: 0;
  line-height: 1;
}
.error-banner .error-content h3 {
  margin: 0 0 6px 0;
  font-size: var(--font-lg);
  font-weight: 600;
  color: var(--text);
}
.error-banner .error-content p {
  margin: 0;
  font-size: var(--font-base);
  color: var(--muted);
  line-height: 1.5;
}
.error-banner .error-content code {
  background: rgba(0,0,0,0.06);
  padding: 2px 6px;
  border-radius: 4px;
  font-size: var(--font-sm);
}
.error-banner .error-content a {
  color: var(--accent);
  text-decoration: underline;
}
body[data-theme="dark-mode"] .error-banner .error-content code {
  background: rgba(255,255,255,0.1);
}

/* =================================================================
   COPY TO CLIPBOARD - Button for results
   ================================================================= */
.copy-btn {
  position: absolute;
  top: 8px;
  right: 8px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: var(--radiusXs);
  padding: 6px 10px;
  font-size: var(--font-xs);
  color: var(--muted);
  cursor: pointer;
  opacity: 0;
  transition: opacity 0.2s ease, background 0.2s ease;
}
.copy-btn:hover {
  background: var(--panel2);
  color: var(--text);
}
.copy-btn.copied {
  background: rgba(40,167,69,0.15);
  color: #28a745;
  border-color: rgba(40,167,69,0.3);
}
.result-container:hover .copy-btn {
  opacity: 1;
}

/* =================================================================
   CLEAR BUTTON STYLING
   ================================================================= */
#clear_btn {
  background: var(--panel) !important;
  color: var(--muted) !important;
  border: 1px solid var(--border) !important;
}
#clear_btn:hover {
  background: var(--panel2) !important;
  color: var(--text) !important;
  border-color: var(--accent) !important;
}

/* =================================================================
   FOOTER - Minimal
   ================================================================= */
.footer {
  text-align: center;
  padding: 20px 0;
  margin-top: 24px;
  border-top: 1px solid var(--border);
}
.footer a {
  color: var(--accent);
  text-decoration: none;
  font-size: var(--font-sm);
  font-weight: 500;
  margin: 0 10px;
}
.footer p {
  font-size: var(--font-xs);
  color: var(--muted);
  margin-top: 8px;
}

/* =================================================================
   FRANKIE LOADING MODAL - Professional GRC-grade loading overlay
   Large centered modal with high-quality 3D Malamute animation
   ================================================================= */
#frankie_overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  width: 100vw;
  height: 100vh;
  background: rgba(0, 0, 0, 0.72);
  backdrop-filter: blur(4px);
  -webkit-backdrop-filter: blur(4px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 9999;
  opacity: 1;
  transition: opacity 0.4s ease;
  pointer-events: auto;
  overflow: hidden;
}

#frankie_inline_container {
  position: fixed;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 520px;
  max-width: 90vw;
  max-height: 85vh;
  pointer-events: auto;
  transition: all 0.4s ease;
  animation: modalSlideIn 0.5s cubic-bezier(0.23, 1, 0.320, 1);
}

@keyframes modalSlideIn {
  from {
    opacity: 0;
    transform: scale(0.92) translateY(20px);
  }
  to {
    opacity: 1;
    transform: scale(1) translateY(0);
  }
}

#frankie_loader {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: flex-start;
  padding: 48px 32px 40px;
  text-align: center;
  background: linear-gradient(135deg, rgba(20,19,18,0.98) 0%, rgba(35,33,30,0.96) 100%);
  border: 1.5px solid rgba(205,143,122,0.25);
  border-radius: 20px;
  box-shadow: 
    0 25px 50px rgba(0,0,0,0.5),
    inset 0 1px 0 rgba(255,255,255,0.1);
  width: 100%;
  position: relative;
  backdrop-filter: saturate(180%) blur(16px);
  -webkit-backdrop-filter: saturate(180%) blur(16px);
}

body[data-theme="dark-mode"] #frankie_loader {
  background: linear-gradient(135deg, rgba(12,11,10,0.98) 0%, rgba(28,26,23,0.96) 100%);
  border: 1.5px solid rgba(205,143,122,0.2);
}

.frankie_container {
  position: relative;
  width: 280px;
  height: auto;
  min-height: 120px;
  margin: 0 auto 32px;
  overflow: visible;
  flex-shrink: 0;
  display: block;
  filter: drop-shadow(0 6px 14px rgba(0,0,0,0.2));
}

.frankie_silhouette {
  width: 100%;
  height: auto;
  min-height: 100px;
  display: block;
  animation: frankieBreath 4s ease-in-out infinite;
}

.frankie_mascot_img,
.frankie_mascot_svg {
  width: 100%;
  height: auto;
  min-height: 80px;
  display: block !important;
  visibility: visible !important;
  object-fit: contain;
}

.frankie_mascot_svg .frankie-tail {
  animation: tailWag 2s ease-in-out infinite;
  transform-origin: 155px 150px;
}

/* Separate red ball element */
.frankie_ball {
  position: absolute;
  width: 28px;
  height: 28px;
  background-color: #ff3333;
  border-radius: 50%;
  top: 18px;
  left: 0;
  box-shadow: 0 4px 12px rgba(255, 51, 51, 0.4), inset 0 2px 4px rgba(255, 100, 100, 0.3);
  animation: ballBounce 3s ease-in-out infinite;
  z-index: 10;
}

.frankie_ball::after {
  content: "";
  position: absolute;
  width: 100%;
  height: 100%;
  border-radius: 50%;
  background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.45), transparent 60%);
}

/* ===== PROFESSIONAL LOADING ANIMATIONS ===== */

@keyframes ballBounce {
  0% {
    transform: translate(0, 0) scale(1);
  }
  25% {
    transform: translate(70px, -18px) scale(1.05);
  }
  50% {
    transform: translate(140px, -30px) scale(1.1);
  }
  75% {
    transform: translate(210px, -14px) scale(1.05);
  }
  100% {
    transform: translate(0, 0) scale(1);
  }
}

/* Gentle breathing/nodding with head tilt synced to ball bounce */
@keyframes frankieBreath {
  0%, 100% { 
    transform: scale(1) rotateZ(0deg) translateY(0);
  }
  25% {
    transform: scale(1.02) rotateZ(2deg) translateY(-2px);
  }
  50% {
    transform: scale(1.03) rotateZ(4deg) translateY(-4px);
  }
  75% {
    transform: scale(1.02) rotateZ(2deg) translateY(-2px);
  }
}

/* Tail wag - happy, playful motion -->
.frankie-tail {
  animation: tailWag 3.5s ease-in-out infinite;
  transform-origin: 110px 160px;
}

@keyframes tailWag {
  0%, 100% { transform: rotateZ(0deg); }
  25% { transform: rotateZ(22deg); }
  50% { transform: rotateZ(-18deg); }
  75% { transform: rotateZ(15deg); }
}

/* Respects reduced motion preference */
@media (prefers-reduced-motion: reduce) {
  .frankie_ball,
  .frankie_silhouette,
  .frankie_mascot_svg,
  .frankie_mascot_svg .frankie-tail,
  .frankie_progress_fill {
    animation: none !important;
  }
  
  #frankie_inline_container {
    animation: none !important;
  }

  /* Static progress bar for reduced motion */
  .frankie_progress_fill {
    width: 50% !important;
    opacity: 1 !important;
  }

  @keyframes modalSlideIn {
    from, to {
      opacity: 1;
      transform: none;
    }
  }
}

/* Frankie scanning eye - subtle intensity */
.frankie_silhouette svg .frankie-scanning-eye {
  animation: eyeShimmer 2.8s ease-in-out infinite;
  transform-origin: center;
}

@keyframes eyeShimmer {
  0%, 100% { opacity: 0.95; }
  50% { opacity: 1; }
}

.frankie_silhouette svg .frankie-alert-tail {
  transform-origin: 35px 65px;
  animation: frankieAlertTail 3s ease-in-out infinite;
}

.frankie_glow {
  position: absolute;
  bottom: -8px;
  left: 50%;
  transform: translateX(-50%);
  width: 70%;
  height: 16px;
  background: radial-gradient(ellipse, rgba(205,143,122,0.15), transparent 75%);
  animation: frankieGlowPulse 4s ease-in-out infinite;
}

/* Sentinel animations - active scanning state */
@keyframes frankieIntenseFocus {
  0%, 100% { opacity: 0.85; }
  40% { opacity: 1; }
  60% { opacity: 0.8; }
}

@keyframes frankieAlertTail {
  0%, 100% { transform: rotate(-5deg); }
  25% { transform: rotate(3deg); }
  50% { transform: rotate(8deg); }
  75% { transform: rotate(2deg); }
}

@keyframes frankieGlowPulse {
  0%, 100% { opacity: 0.5; transform: translateX(-50%) scaleX(0.95); }
  50% { opacity: 0.8; transform: translateX(-50%) scaleX(1.05); }
}

.frankie_title {
  font-weight: 700;
  font-size: 1.4rem;
  color: #FFD700;
  margin-bottom: 12px;
  letter-spacing: 0.8px;
  text-transform: none;
}

.frankie_line {
  color: #E8DFD5;
  font-size: 1.05rem;
  font-weight: 500;
  max-width: 420px;
  line-height: 1.6;
  margin-bottom: 24px;
  letter-spacing: 0.3px;
}

.frankie_hint {
  color: #A8A0A0;
  font-size: 0.9rem;
  margin-top: 8px;
  opacity: 0.85;
  font-weight: 400;
  letter-spacing: 0.2px;
}

/* Progress bar container - sleek gold-and-charcoal design */
.frankie_progress_section {
  width: 100%;
  margin-top: 24px;
}

.frankie_progress_bar {
  height: 8px;
  background: linear-gradient(90deg, #2A2926 0%, #3A3A36 50%, #2A2926 100%);
  border-radius: 4px;
  overflow: hidden;
  border: 1px solid rgba(255, 215, 0, 0.15);
  box-shadow: 
    inset 0 2px 4px rgba(0, 0, 0, 0.5),
    0 0 8px rgba(0, 0, 0, 0.3);
  position: relative;
}

.frankie_progress_fill {
  height: 100%;
  background: linear-gradient(90deg, 
    #FFE44D 0%, 
    #FFD700 25%, 
    #FFC700 50%, 
    #FFD700 75%, 
    #FFE44D 100%);
  border-radius: 3px;
  animation: progressPulse 2.2s cubic-bezier(0.25, 0.46, 0.45, 0.94) infinite;
  box-shadow: 
    0 0 16px rgba(255, 215, 0, 0.6),
    inset 0 1px 2px rgba(255, 255, 255, 0.3),
    inset 0 -1px 2px rgba(0, 0, 0, 0.4);
  position: relative;
}

@keyframes progressPulse {
  0%, 100% { width: 15%; opacity: 0.7; }
  50% { width: 90%; opacity: 1; }
}

/* Mobile responsive */
@media (max-width: 768px) {
  #frankie_inline_container {
    width: 90vw;
    max-width: 480px;
  }
  
  #frankie_loader {
    padding: 32px 24px 32px;
  }
  
  .frankie_container {
    width: 250px;
    height: auto;
    margin-bottom: 24px;
  }
  
  .frankie_title {
    font-size: 1.2rem;
  }
  
  .frankie_line {
    font-size: 0.95rem;
  }
  
  .frankie_hint {
    font-size: 0.85rem;
  }
}

/* =================================================================
   FRANKIE STATE ANIMATIONS - Sentinel behavioral states
   Scanning: Active search for vulnerabilities
   Found: Results discovered, shifting focus
   Monitoring: Review complete, watchful presence
   ================================================================= */

/* State: SCANNING (active vulnerability search) */
#frankie_inline_container.frankie-state-scanning {
  animation: frankieScanningPulse 0.8s ease-in-out infinite;
}

@keyframes frankieScanningPulse {
  0%, 100% { transform: scale(1) translateX(0); }
  50% { transform: scale(1.02) translateX(2px); }
}

/* Modal state: SCANNING (initial loading state) */
#frankie_inline_container.frankie-state-scanning .frankie_title {
  color: #FFD700;
  text-shadow: 0 0 12px rgba(255, 215, 0, 0.3);
  animation: titleGlow 2s ease-in-out infinite;
}

@keyframes titleGlow {
  0%, 100% { text-shadow: 0 0 8px rgba(255, 215, 0, 0.2); }
  50% { text-shadow: 0 0 16px rgba(255, 215, 0, 0.4); }
}

#frankie_inline_container.frankie-state-scanning .frankie_silhouette {
  animation: none !important;
}

/* Modal state: FOUND (results appearing) */
#frankie_inline_container.frankie-state-found {
  animation: none;
}

#frankie_inline_container.frankie-state-found .frankie_title {
  color: #FFD700;
}

#frankie_inline_container.frankie-state-found .frankie_silhouette {
  animation: none !important;
}

/* Modal state: MONITORING (review complete, watchful) */
#frankie_inline_container.frankie-state-monitoring {
  animation: none;
}

#frankie_inline_container.frankie-state-monitoring .frankie_title {
  color: #FFD700;
}

#frankie_inline_container.frankie-state-monitoring .frankie_silhouette {
  animation: none !important;
}

@keyframes frankieMonitoring {
  0%, 100% { transform: scaleX(1); }
  50% { transform: scaleX(1.01); }
}

/* Modal default state - always start visible */
#frankie_overlay {
  opacity: 1;
  pointer-events: auto;
  transition: opacity 0.4s ease;
}

/* Modal hidden state (when overlay closes) */
#frankie_overlay.frankie-hidden {
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.4s ease;
}

/* =================================================================
   ACCESSIBILITY IMPROVEMENTS
   - High contrast text
   - Visible focus states
   - Dropdown/accordion indicators
   ================================================================= */

/* Focus states for keyboard navigation */
*:focus-visible {
  outline: 3px solid var(--accent) !important;
  outline-offset: 2px !important;
}
button:focus-visible,
input:focus-visible,
textarea:focus-visible,
[role="button"]:focus-visible {
  outline: 3px solid var(--accent) !important;
  outline-offset: 2px !important;
  box-shadow: 0 0 0 4px rgba(205,143,122,0.3) !important;
}

/* Ensure minimum contrast on text */
.gradio-container, .gradio-container * {
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

/* Accordion dropdown indicator - clearly visible chevron */
.gradio-accordion .label-wrap {
  position: relative !important;
}
.gradio-accordion .label-wrap::after {
  content: "▼" !important;
  position: absolute !important;
  right: 16px !important;
  top: 50% !important;
  transform: translateY(-50%) !important;
  font-size: 0.8em !important;
  color: var(--accent) !important;
  transition: transform 0.2s ease !important;
}
.gradio-accordion.open .label-wrap::after {
  transform: translateY(-50%) rotate(180deg) !important;
}
#customize_acc .label-wrap::after {
  color: var(--accent) !important;
  font-weight: bold !important;
}

/* Ensure dropdown/select elements have visible borders and indicators */
.gradio-container select,
.gradio-container .dropdown {
  border: 2px solid var(--border) !important;
  border-radius: var(--radiusSm) !important;
  padding-right: 36px !important;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23CD8F7A' d='M2 4l4 4 4-4'/%3E%3C/svg%3E") !important;
  background-repeat: no-repeat !important;
  background-position: right 12px center !important;
  appearance: none !important;
  -webkit-appearance: none !important;
}
.gradio-container select:hover,
.gradio-container .dropdown:hover {
  border-color: var(--accent) !important;
}

/* Radio buttons as clear pill selectors */
#review_mode label {
  position: relative !important;
}
#review_mode input:checked + label::before {
  content: "✓" !important;
  margin-right: 6px !important;
  font-weight: bold !important;
}

/* Checkbox visibility improvements */
.gradio-container input[type="checkbox"] {
  width: 20px !important;
  height: 20px !important;
  border: 2px solid var(--border) !important;
  border-radius: 4px !important;
  cursor: pointer !important;
}
.gradio-container input[type="checkbox"]:checked {
  background: var(--accent) !important;
  border-color: var(--accent) !important;
}

/* Improve button visibility in both modes */
#review_btn button,
#sample_btn button {
  min-height: 48px !important;  /* Touch target size */
  font-size: var(--font-lg) !important;
}

/* Dark mode accessibility fixes */
body[data-theme="dark-mode"] .gradio-container {
  color: #FAF8F4 !important;
}
body[data-theme="dark-mode"] .results_title,
body[data-theme="dark-mode"] .verdict_headline,
body[data-theme="dark-mode"] #empty_state .empty_title,
body[data-theme="dark-mode"] .finding_title,
body[data-theme="dark-mode"] .top_fix_title {
  color: #FAF8F4 !important;
}
body[data-theme="dark-mode"] .results_label {
  color: var(--accent) !important;
}
body[data-theme="dark-mode"] .muted,
body[data-theme="dark-mode"] .text2,
body[data-theme="dark-mode"] .verdict_subtext,
body[data-theme="dark-mode"] #empty_state .empty_text,
body[data-theme="dark-mode"] .finding_desc {
  color: rgba(250,248,244,0.75) !important;
}
body[data-theme="dark-mode"] select,
body[data-theme="dark-mode"] .dropdown {
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23CD8F7A' d='M2 4l4 4 4-4'/%3E%3C/svg%3E") !important;
  color: #FAF8F4 !important;
}
body[data-theme="dark-mode"] .spine_hint,
body[data-theme="dark-mode"] .mode_descriptions {
  color: rgba(250,248,244,0.75) !important;
}
/* Light mode text contrast improvements */
.results_title,
.verdict_headline,
#empty_state .empty_title,
.finding_title,
.top_fix_title {
  color: var(--text) !important;
}
.verdict_subtext,
#empty_state .empty_text,
.finding_desc {
  color: var(--muted) !important;
}

/* =================================================================
   MOBILE RESPONSIVE - iOS and Android friendly
   ================================================================= */

/* Tablet breakpoint */
@media screen and (max-width: 1024px) {
  html, body {
    overflow-x: hidden !important;
    max-width: 100vw !important;
  }

  .gradio-container {
    max-width: 100% !important;
    padding: 0 12px !important;
    overflow-x: hidden !important;
  }

  #shell {
    flex-direction: column !important;
    max-width: 100% !important;
  }

  #left_spine,
  #right_panel {
    border-radius: var(--radius) !important;
    margin-bottom: 16px !important;
  }

  #left_spine {
    border-right: none !important;
  }

  #right_panel {
    border-left: 1px solid var(--border) !important;
  }

  .header_features {
    flex-wrap: wrap !important;
    justify-content: center !important;
  }
}

/* Mobile breakpoint */
@media screen and (max-width: 768px) {
  :root {
    --font-base: 1rem;
    --font-lg: 1.125rem;
    --font-xl: 1.25rem;
    --font-2xl: 1.375rem;
  }

  html, body {
    overflow-x: hidden !important;
    width: 100% !important;
    max-width: 100vw !important;
  }

  .gradio-container {
    padding: 0 8px !important;
    overflow-x: hidden !important;
    width: 100% !important;
    max-width: 100% !important;
    box-sizing: border-box !important;
  }

  /* Main layout mobile fix */
  #shell {
    width: 100% !important;
    max-width: 100% !important;
    flex-direction: column !important;
    box-sizing: border-box !important;
  }

  #left_spine,
  #right_panel {
    width: 100% !important;
    max-width: 100% !important;
    box-sizing: border-box !important;
    padding: 12px !important;
  }

  /* Frankie overlay mobile fix */
  #frankie_overlay {
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    right: 0 !important;
    bottom: 0 !important;
    width: 100vw !important;
    height: 100vh !important;
    z-index: 99999 !important;
  }

  #frankie_inline_container {
    position: fixed !important;
    top: 50% !important;
    left: 50% !important;
    transform: translate(-50%, -50%) !important;
    width: 92vw !important;
    max-width: 92vw !important;
    max-height: 80vh !important;
    margin: 0 !important;
  }

  #frankie_loader {
    padding: 28px 20px 24px !important;
    width: 100% !important;
    box-sizing: border-box !important;
  }

  .frankie_container {
    width: 180px !important;
    height: auto !important;
    min-height: 100px !important;
    margin-bottom: 20px !important;
  }

  .frankie_silhouette,
  .frankie_mascot_svg {
    width: 100% !important;
    height: auto !important;
    min-height: 80px !important;
  }

  .frankie_ball {
    width: 22px !important;
    height: 22px !important;
  }

  .frankie_title {
    font-size: 1.15rem !important;
    margin-bottom: 8px !important;
  }

  .frankie_line {
    font-size: 0.95rem !important;
  }

  #brand_header {
    padding: 16px 12px 20px 12px !important;
    margin: 0 0 12px 0 !important;
    width: 100% !important;
    box-sizing: border-box !important;
  }

  #brand_title {
    font-size: 1.5em !important;
    word-wrap: break-word !important;
  }

  #brand_subtitle {
    font-size: var(--font-base) !important;
  }

  .header_features {
    gap: 8px !important;
  }

  .feature_tag {
    font-size: var(--font-xs) !important;
    padding: 4px 10px !important;
  }

  /* Stack review mode buttons vertically on mobile */
  #review_mode .wrap {
    flex-direction: column !important;
    gap: 8px !important;
  }

  #review_mode label {
    padding: 14px 12px !important;
  }

  /* Stack action buttons */
  #action_buttons {
    flex-direction: column !important;
  }

  #action_buttons > div {
    width: 100% !important;
  }

  /* Larger touch targets */
  #review_btn button,
  #sample_btn button {
    min-height: 52px !important;
    font-size: var(--font-lg) !important;
    padding: 16px 20px !important;
  }

  /* Findings table: horizontal scroll */
  .findings_table {
    display: block !important;
    overflow-x: auto !important;
    -webkit-overflow-scrolling: touch !important;
  }

  /* Severity counters: 2x2 grid on mobile */
  .severity_counters {
    flex-wrap: wrap !important;
  }

  .severity_counter {
    flex: 1 1 50% !important;
    min-width: 0 !important;
    border-bottom: 1px solid var(--border) !important;
  }

  .severity_counter:nth-child(3),
  .severity_counter:nth-child(4) {
    border-bottom: none !important;
  }

  .severity_counter:nth-child(2),
  .severity_counter:nth-child(4) {
    border-right: none !important;
  }

  /* Top fixes: full width */
  .top_fix {
    flex-direction: column !important;
    gap: 8px !important;
  }

  .fix_number {
    align-self: flex-start !important;
  }

  /* Trust signals: wrap nicely */
  .trust_signals {
    justify-content: center !important;
    gap: 10px !important;
  }

  /* Tabs: scrollable on mobile */
  #right_panel .tab-nav {
    overflow-x: auto !important;
    -webkit-overflow-scrolling: touch !important;
    flex-wrap: nowrap !important;
  }

  #right_panel .tab-nav button {
    flex: 0 0 auto !important;
    white-space: nowrap !important;
    padding: 12px 14px !important;
  }

  /* Code editor: better mobile height */
  #left_spine textarea,
  #left_spine .cm-editor {
    min-height: 150px !important;
    max-height: 250px !important;
  }

  /* Footer: stacked links */  /* Footer: stacked links */
  .footer_links {
    display: flex !important;
    flex-wrap: wrap !important;
    justify-content: center !important;
    gap: 8px !important;
  }

  .footer a {
    margin: 0 6px !important;
  }
}

/* Small phone breakpoint */
@media screen and (max-width: 480px) {
  :root {
    --font-base: 0.9375rem;
    --font-sm: 0.8125rem;
  }

  #brand_title {
    font-size: 1.5em !important;
  }

  /* Frankie loader mobile compact */
  #frankie_inline_container {
    position: fixed !important;
    top: 50% !important;
    left: 50% !important;
    transform: translate(-50%, -50%) !important;
    width: 95vw !important;
    max-width: none !important;
  }

  #frankie_loader {
    padding: 24px 16px 24px !important;
  }

  .frankie_container {
    width: 180px !important;
    margin-bottom: 16px !important;
  }

  .frankie_ball {
    width: 20px !important;
    height: 20px !important;
  }

  .frankie_title {
    font-size: 1.1rem !important;
  }

  .frankie_line {
    font-size: 0.875rem !important;
    margin-bottom: 16px !important;
  }

  .frankie_progress_bar {
    height: 6px !important;
  }

  .frankie_hint {
    font-size: 0.8rem !important;
  }

  .header_tagline {
    font-size: var(--font-base) !important;
  }

  /* Single column severity counters on very small screens */
  .severity_counter {
    flex: 1 1 50% !important;
  }

  /* Compact verdict card */
  .verdict_header {
    flex-direction: column !important;
    text-align: center !important;
    gap: 12px !important;
  }

  .verdict_main {
    text-align: center !important;
  }

  /* Accordion: ensure tap target */
  #customize_acc .label-wrap {
    padding: 14px 40px 14px 14px !important;
    min-height: 48px !important;
  }
}

/* iOS Safari fixes */
@supports (-webkit-touch-callout: none) {
  /* Fix for iOS input zoom */
  input, textarea, select {
    font-size: 16px !important;
  }

  /* iOS safe area for notched devices */
  .gradio-container {
    padding-left: max(12px, env(safe-area-inset-left)) !important;
    padding-right: max(12px, env(safe-area-inset-right)) !important;
  }

  .footer {
    padding-bottom: max(20px, env(safe-area-inset-bottom)) !important;
  }

  /* Frankie overlay safe area */
  #frankie_overlay {
    padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left);
  }
}

/* Landscape mode on mobile */
@media screen and (max-height: 500px) and (orientation: landscape) {
  #frankie_inline_container {
    max-height: 90vh !important;
    overflow-y: auto !important;
  }

  #frankie_loader {
    padding: 16px !important;
    flex-direction: row !important;
    flex-wrap: wrap !important;
    justify-content: center !important;
    gap: 16px;
  }

  .frankie_container {
    width: 120px !important;
    margin-bottom: 0 !important;
  }

  .frankie_title {
    font-size: 1rem !important;
  }

  .frankie_line {
    font-size: 0.85rem !important;
    margin-bottom: 8px !important;
  }

  .frankie_progress_section {
    margin-top: 8px !important;
  }

  .frankie_hint {
    display: none !important;
  }
}

/* Touch target sizing - WCAG 2.5.5 (AAA) 44x44px minimum */
@media (pointer: coarse) {
  button,
  [role="button"],
  input[type="submit"],
  input[type="button"],
  .accordion-toggle,
  #review_mode label {
    min-height: 44px !important;
    min-width: 44px !important;
  }

  /* Ensure Frankie loader buttons/interactive elements are tappable */
  #frankie_loader {
    -webkit-tap-highlight-color: transparent;
  }
}

/* High contrast mode support */
@media (prefers-contrast: high) {
  :root {
    --border: rgba(0,0,0,0.4);
  }

  body[data-theme="dark-mode"] {
    --border: rgba(255,255,255,0.4);
  }

  .severity_badge,
  .fix_severity,
  .verdict_pill {
    border: 2px solid currentColor !important;
  }

  button, [role="button"] {
    border: 2px solid currentColor !important;
  }
}
"""

# Sample code for demo
SAMPLE_CODE = '''def chat(user_input):
    """Simple chat function with potential prompt injection risk."""
    prompt = f"You are a helpful assistant. User says: {user_input}"
    return llm.generate(prompt)

def get_user(user_id):
    """Fetch user from database - potential SQL injection."""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
'''

# Example vulnerable code snippets for gr.Examples
EXAMPLE_SNIPPETS = [
    # SQL Injection
    [
        """def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)""",
        "user_service.py",
    ],
    # Prompt Injection
    [
        """def chat(user_input):
    prompt = f"You are helpful. User says: {user_input}"
    return llm.generate(prompt)""",
        "chatbot.py",
    ],
    # Hardcoded Secrets
    [
        """API_KEY = "sk-abc123secret"
DATABASE_URL = "postgres://admin:password@db:5432/prod"

def connect():
    return db.connect(DATABASE_URL)""",
        "config.py",
    ],
    # Path Traversal
    [
        """def download(filename):
    path = f"/uploads/{filename}"
    return open(path, "rb").read()""",
        "file_handler.py",
    ],
    # GDPR Violation
    [
        """def register(name, email, ssn, credit_card):
    user = {"name": name, "email": email, "ssn": ssn,
            "credit_card": credit_card}
    db.insert(user)  # No consent, no encryption""",
        "user_registration.py",
    ],
]


def load_sample():
    """Load sample vulnerable code for demo."""
    return SAMPLE_CODE, "app.py"


def get_frankie_loader(run_id: str = "") -> str:
    """
    Generate Frankie loader HTML.

    Frankie appears ONLY when:
    - Review is in progress
    - Verdict is not yet determined
    - No errors have occurred

    Frankie NEVER appears when:
    - Verdict is BLOCK
    - An error or crash occurs
    - Results are visible
    """
    if not run_id:
        run_id = str(int(datetime.now(timezone.utc).timestamp() * 1000))

    loading_messages = [
        "Frankie's catchin' the scent...",
        "He's a thorough boy, sugar!",
        "Finding those gaps for you...",
    ]

    # Inline SVG of Frankie the Alaskan Malamute - professional 3D styled mascot
    frankie_svg = """<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg" class="frankie_mascot_svg">
        <defs>
            <linearGradient id="furGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style="stop-color:#8B7355"/>
                <stop offset="50%" style="stop-color:#6B5344"/>
                <stop offset="100%" style="stop-color:#4A3728"/>
            </linearGradient>
            <linearGradient id="chestGradient" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" style="stop-color:#F5F5F0"/>
                <stop offset="100%" style="stop-color:#E8E0D5"/>
            </linearGradient>
            <linearGradient id="noseGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style="stop-color:#2C2C2C"/>
                <stop offset="100%" style="stop-color:#1A1A1A"/>
            </linearGradient>
            <filter id="softShadow" x="-20%" y="-20%" width="140%" height="140%">
                <feDropShadow dx="2" dy="4" stdDeviation="3" flood-opacity="0.3"/>
            </filter>
        </defs>
        <!-- Body -->
        <ellipse cx="100" cy="155" rx="55" ry="40" fill="url(#furGradient)" filter="url(#softShadow)"/>
        <!-- Chest fur -->
        <ellipse cx="100" cy="140" rx="35" ry="30" fill="url(#chestGradient)"/>
        <!-- Head -->
        <ellipse cx="100" cy="85" rx="45" ry="40" fill="url(#furGradient)" filter="url(#softShadow)"/>
        <!-- Face mask (white) -->
        <path d="M100 55 Q120 75 115 100 Q100 115 85 100 Q80 75 100 55" fill="url(#chestGradient)"/>
        <!-- Left ear -->
        <path d="M60 50 Q55 25 70 35 Q80 45 75 65 Z" fill="url(#furGradient)"/>
        <path d="M65 48 Q62 32 72 38 Q78 46 74 58 Z" fill="#D4B5A0"/>
        <!-- Right ear -->
        <path d="M140 50 Q145 25 130 35 Q120 45 125 65 Z" fill="url(#furGradient)"/>
        <path d="M135 48 Q138 32 128 38 Q122 46 126 58 Z" fill="#D4B5A0"/>
        <!-- Eyes -->
        <ellipse cx="80" cy="80" rx="10" ry="11" fill="#1A1A1A"/>
        <ellipse cx="120" cy="80" rx="10" ry="11" fill="#1A1A1A"/>
        <ellipse cx="82" cy="78" rx="4" ry="5" fill="#4A3728"/>
        <ellipse cx="122" cy="78" rx="4" ry="5" fill="#4A3728"/>
        <circle cx="84" cy="76" r="2.5" fill="#FFFFFF" opacity="0.9"/>
        <circle cx="124" cy="76" r="2.5" fill="#FFFFFF" opacity="0.9"/>
        <!-- Nose -->
        <ellipse cx="100" cy="100" rx="12" ry="9" fill="url(#noseGradient)"/>
        <ellipse cx="100" cy="98" rx="4" ry="2" fill="#444" opacity="0.5"/>
        <!-- Mouth -->
        <path d="M100 109 Q90 118 85 115" stroke="#3A2A1A" stroke-width="2" fill="none" stroke-linecap="round"/>
        <path d="M100 109 Q110 118 115 115" stroke="#3A2A1A" stroke-width="2" fill="none" stroke-linecap="round"/>
        <!-- Tongue (happy panting) -->
        <ellipse cx="100" cy="120" rx="8" ry="12" fill="#E57373"/>
        <path d="M96 118 Q100 125 104 118" stroke="#C55A5A" stroke-width="1" fill="none"/>
        <!-- Front paws -->
        <ellipse cx="75" cy="185" rx="18" ry="10" fill="url(#furGradient)"/>
        <ellipse cx="125" cy="185" rx="18" ry="10" fill="url(#furGradient)"/>
        <!-- Paw details -->
        <ellipse cx="75" cy="188" rx="12" ry="6" fill="url(#chestGradient)"/>
        <ellipse cx="125" cy="188" rx="12" ry="6" fill="url(#chestGradient)"/>
        <!-- Tail (wagging) -->
        <path class="frankie-tail" d="M155 150 Q175 130 165 110 Q160 100 170 95" stroke="url(#furGradient)" stroke-width="14" fill="none" stroke-linecap="round"/>
    </svg>"""

    return f"""
    <div id="frankie_overlay" style="display: flex; opacity: 1;">
        <div id="frankie_inline_container" class="frankie-state-scanning">
            <div id="frankie_loader">
                <div class="frankie_container" aria-live="polite" aria-label="Code review in progress - Frankie's watching your code">
                    <div class="frankie_ball"></div>
                    <div class="frankie_silhouette">
                        {frankie_svg}
                    </div>
                </div>
                <div class="frankie_title">Frankie's got his eye on it</div>
                <div class="frankie_line" id="frankie_loading_text">{loading_messages[0]}</div>
                <div class="frankie_progress_section">
                    <div class="frankie_progress_bar">
                        <div class="frankie_progress_fill"></div>
                    </div>
                </div>
                <div class="frankie_hint">Analyzing thoroughly...</div>
            </div>
        </div>
    </div>
    <script>
        window.frankieMessageIndex = 0;
        window.frankieMessages = {json.dumps(loading_messages)};

        function cycleFrankieMessage() {{
            const textElement = document.getElementById("frankie_loading_text");
            if (!textElement || !window.frankieMessages) return;
            window.frankieMessageIndex = (window.frankieMessageIndex + 1) % window.frankieMessages.length;
            textElement.textContent = window.frankieMessages[window.frankieMessageIndex];
        }}

        if (!window.frankieMessageInterval) {{
            window.frankieMessageInterval = setInterval(cycleFrankieMessage, 2000);
        }}
    </script>
    """


with gr.Blocks(title="Code Review Agent", theme=APP_THEME, css=APP_CSS) as demo:
    # Header - Hero section with trust signals
    gr.HTML("""
    <div id="brand_header">
        <div class="header_badge">🛡️ AI-POWERED SECURITY</div>
        <div id="brand_title">Code Review Agent</div>
        <div class="header_tagline">Frankie</div>
        <div id="brand_subtitle">Catch security flaws before they ship. Multi-pass review with OWASP/CWE mapping, blast radius analysis, and audit-ready output.</div>
        <div class="header_features">
            <span class="feature_tag">✓ OWASP 2025 Mapping</span>
            <span class="feature_tag">✓ Blast Radius Analysis</span>
            <span class="feature_tag">✓ Audit-Ready Verdicts</span>
        </div>
    </div>
    """)

    # Frankie state management script
    gr.HTML("""
    <script>
    window.frankieState = {
        currentState: 'hidden',
        setFrankieState: function(state) {
            const container = document.getElementById('frankie_inline_container');
            const overlay = document.getElementById('frankie_overlay');
            if (!container || !overlay) return;
            
            // Remove all state classes
            container.className = container.className.replace(/frankie-state-\\w+/g, '').trim();
            
            // Add new state class
            if (state === 'scanning') {
                container.classList.add('frankie-state-scanning');
                overlay.classList.remove('frankie-hidden');
                this.currentState = 'scanning';
            } else if (state === 'found') {
                container.classList.add('frankie-state-found');
                overlay.classList.remove('frankie-hidden');
                this.currentState = 'found';
            } else if (state === 'monitoring') {
                container.classList.add('frankie-state-monitoring');
                overlay.classList.remove('frankie-hidden');
                this.currentState = 'monitoring';
            } else if (state === 'hidden') {
                overlay.classList.add('frankie-hidden');
                this.currentState = 'hidden';
            }
        },
        transitionToFound: function() {
            setTimeout(() => this.setFrankieState('found'), 500);
        },
        transitionToMonitoring: function() {
            setTimeout(() => this.setFrankieState('monitoring'), 1500);
        },
        hide: function() {
            this.setFrankieState('hidden');
        }
    };
    
    // Watch for verdict card appearance to trigger state transitions and auto-hide
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.type === 'childList' || mutation.type === 'characterData') {
                const verdictCard = document.getElementById('verdict_card_container');
                if (verdictCard && verdictCard.textContent.trim() !== '' && !verdictCard.textContent.includes('Frankie')) {
                    if (window.frankieState.currentState !== 'hidden') {
                        // Auto-hide Frankie after 3 seconds when results appear
                        setTimeout(() => window.frankieState.hide(), 3000);
                    }
                }
            }
        });
    });
    
    // Observe changes to verdict card
    const verdictContainer = document.getElementById('verdict_card_container');
    if (verdictContainer) {
        observer.observe(verdictContainer, { 
            subtree: true, 
            characterData: true, 
            childList: true 
        });
    }
    </script>
    """)

    # Theme toggle (Light Mode / Dark Mode)
    with gr.Row():
        with gr.Column():
            theme_mode = gr.Radio(
                choices=["Light Mode", "Dark Mode"],
                value="Light Mode",
                label="",
                elem_id="mode_toggle",
                interactive=True,
            )

    # Use js parameter - the function receives the radio value and sets theme
    theme_mode.change(
        fn=lambda x: None,
        inputs=theme_mode,
        outputs=None,
        js="(mode) => { document.body.dataset.theme = mode.toLowerCase().includes('dark') ? 'dark-mode' : 'light-mode'; }",
    )

    # Main layout: Dark spine (left) + Light results (right)
    with gr.Row(elem_id="shell", equal_height=True):
        # =====================================================
        # LEFT: DARK SPINE - "Give me something"
        # =====================================================
        with gr.Column(scale=4, elem_id="left_spine"):
            gr.HTML(
                '<div class="spine_label">STEP 1 — YOUR CODE</div><div class="spine_title">Paste or type your code below</div><div class="spine_hint">Works with Python, JavaScript, TypeScript, Go, and most languages</div>'
            )

            code = gr.Code(
                value="", language="python", label="", lines=12, show_label=False
            )

            ctx = gr.Textbox(
                label="File name (helps with context)",
                placeholder="Example: app.py, server.js, main.go",
                lines=1,
                elem_id="filename_box",
            )

            # Review Mode selector - Quick/Deep/Compliance lens
            gr.HTML(
                '<div id="review_mode_container"><div class="review_mode_header">Review Mode</div></div>'
            )
            review_mode = gr.Radio(
                choices=["⚡ Quick", "🔬 Deep", "📋 Compliance"],
                value="🔬 Deep",
                label="",
                elem_id="review_mode",
                interactive=True,
            )
            gr.HTML("""
            <div class="mode_descriptions">
                <strong>Quick:</strong> Fast scan for critical issues (2-5s)<br>
                <strong>Deep:</strong> Full security gate with blast radius (default)<br>
                <strong>Compliance:</strong> PII/GDPR lens for audit workflows
            </div>
            """)

            gr.HTML(
                '<div class="spine_label" style="margin-top: 18px;">STEP 2 — RUN ANALYSIS</div>'
            )

            with gr.Row(elem_id="action_buttons"):
                btn = gr.Button("🔍 Analyze My Code", elem_id="review_btn", scale=2)
                sample_btn = gr.Button("📝 Try Example", elem_id="sample_btn", scale=1)
                clear_btn = gr.Button("🗑️ Clear", elem_id="clear_btn", scale=1)

            # Quick examples for testing - clickable samples
            gr.Examples(
                examples=EXAMPLE_SNIPPETS,
                inputs=[code, ctx],
                label="🎯 Quick Examples (click to load)",
                examples_per_page=5,
            )

            with gr.Accordion(
                "⚙️ Fine-Tune Categories (Optional)", open=False, elem_id="customize_acc"
            ):
                gr.HTML(
                    '<div class="beginner_tip">🎯 <strong>New to security review?</strong> The defaults work great. Expand this only if you need specific checks.</div>'
                )
                gr.HTML(
                    '<div class="config_section_title">What should Frankie look for?</div>'
                )
                with gr.Row():
                    sec = gr.Checkbox(
                        label="🔐 Security Vulnerabilities",
                        value=True,
                        info="SQL injection, XSS, SSRF, prompt injection",
                    )
                    comp = gr.Checkbox(
                        label="📋 Compliance & Privacy",
                        value=True,
                        info="PII exposure, GDPR, audit gaps",
                    )
                with gr.Row():
                    logic = gr.Checkbox(
                        label="🧠 Logic Errors",
                        value=False,
                        info="Race conditions, null handling, exceptions",
                    )
                    perf = gr.Checkbox(
                        label="⚡ Performance Issues",
                        value=False,
                        info="N+1 queries, memory leaks, blocking I/O",
                    )

        # =====================================================
        # RIGHT: LIGHT PANEL - "Here's what I found"
        # =====================================================
        with gr.Column(scale=6, elem_id="right_panel"):
            gr.HTML(
                '<div class="results_label">STEP 3 — YOUR RESULTS</div><div class="results_title">Security Analysis Report</div>'
            )

            empty_state = gr.HTML("""
            <div id="empty_state">
                <div class="empty_icon">🔍</div>
                <div class="empty_title">Ready to analyze your code</div>
                <div class="empty_text">Paste code on the left, choose your review mode, then click <strong>Analyze My Code</strong></div>
                <div class="empty_hint">💡 New here? Click "Try Example" to see Frankie in action</div>
            </div>
            """)

            summ = gr.HTML("", elem_id="verdict_card_container")

            with gr.Tabs():
                with gr.Tab("📊 Overview", id="tab_overview"):
                    det = gr.Markdown("")
                with gr.Tab("🔧 Fixes", id="tab_fixes"):
                    fixes_tab = gr.Markdown(
                        "<div style='text-align:center;color:#A89F91;padding:40px;'>\n<p style='font-size:1.25rem;'>🔧</p>\n<p><strong>Fixes will show here</strong></p>\n<p style='font-size:0.875rem;'>Run an analysis to see prioritized recommendations</p>\n</div>"
                    )
                with gr.Tab("📋 Audit", id="tab_audit"):
                    advanced_tab = gr.Markdown(
                        "<div style='text-align:center;color:#A89F91;padding:40px;'>\n<p style='font-size:1.25rem;'>📋</p>\n<p><strong>Audit data will show here</strong></p>\n<p style='font-size:0.875rem;'>Decision records and compliance data for your review</p>\n</div>"
                    )
                    audit_json = gr.JSON(label="Audit Record (JSON)", visible=False)

    # Footer with trust signals
    gr.HTML("""
    <div class="footer">
        <div class="footer_links">
            <a href="https://github.com/adarian-dewberry/code-review-agent">GitHub</a>
            <a href="https://github.com/adarian-dewberry/code-review-agent/blob/main/POLICIES.md">Policy v2</a>
            <a href="https://github.com/adarian-dewberry/code-review-agent/blob/main/SECURITY.md">Trust & Safety</a>
        </div>
        <p>Human review always recommended · Your code is never stored</p>
    </div>
    """)

    # Session state for audit record (replaces global variable for multi-tenant isolation)
    audit_state = gr.State(value=None)
    session_id_state = gr.State(value=generate_session_id)

    # Wire up sample button with loading indication
    def load_sample_with_state():
        """Load sample code and return to clear any previous results."""
        code_val, ctx_val = load_sample()
        empty_html = """
        <div id="empty_state">
            <div class="empty_icon">📝</div>
            <div class="empty_title">Example loaded</div>
            <div class="empty_text">Click <strong>Analyze My Code</strong> to see Frankie in action</div>
        </div>
        """
        return (
            code_val,
            ctx_val,
            empty_html,  # Show helpful message
            "",  # Clear summary
            "",  # Clear details
            "",  # Clear fixes
            gr.update(visible=False),  # Hide export btn
            gr.update(visible=False),  # Hide export md btn
        )

    sample_btn.click(
        fn=load_sample_with_state,
        outputs=[
            code,
            ctx,
            empty_state,
            summ,
            det,
            fixes_tab,
        ],
    )

    # Wire up clear button
    def clear_all():
        """Reset the entire form to start fresh."""
        empty_html = """
        <div id="empty_state">
            <div class="empty_icon">🔍</div>
            <div class="empty_title">Ready to analyze your code</div>
            <div class="empty_text">Paste code on the left, choose your review mode, then click <strong>Analyze My Code</strong></div>
            <div class="empty_hint">💡 New here? Click "Try Example" to see Frankie in action</div>
        </div>
        """
        return (
            "",  # Clear code
            "",  # Clear filename
            empty_html,  # Reset empty state
            "",  # Clear summary
            "",  # Clear details
            "",  # Clear fixes
            gr.update(value=None, visible=False),  # Clear and hide audit JSON
            None,  # Clear audit state
        )

    clear_btn.click(
        fn=clear_all,
        outputs=[
            code,
            ctx,
            empty_state,
            summ,
            det,
            fixes_tab,
            audit_json,
            audit_state,
        ],
    )

    # Wire up review button - show Frankie during review, hide empty state when results arrive
    def run_with_frankie(
        code_val,
        sec_val,
        comp_val,
        logic_val,
        perf_val,
        ctx_val,
        review_mode_val,
        session_id,
    ):
        # Adjust categories based on review mode
        # Quick mode: security only, fast
        # Deep mode: security + compliance (default)
        # Compliance mode: compliance focus with security
        if "Quick" in review_mode_val:
            sec_val, comp_val, logic_val, perf_val = True, False, False, False
        elif "Compliance" in review_mode_val:
            sec_val, comp_val, logic_val, perf_val = True, True, False, False

        # First yield: show Frankie loader in scanning state, hide export controls
        frankie_html = get_frankie_loader()
        # Trigger JS to ensure modal visibility and animation
        frankie_script = "<script>if(window.frankieState) { window.frankieState.setFrankieState('scanning'); console.log('Frankie scanning started'); } else { console.log('frankieState not ready'); }</script>"
        yield (
            "",  # empty_state
            frankie_html + frankie_script,  # summ - combined HTML and script
            "",  # det - clear details
            "*Generating fix recommendations...*",  # fixes_tab
            gr.update(value=None, visible=False),  # audit_json
            gr.update(visible=False),  # export_btn
            gr.update(visible=False),  # export_md_btn
            None,  # audit_state
        )

        # Run the actual review (now returns 4-tuple with audit_record)
        summ_result, det_result, fixes_result, audit_record = review_code(
            code_val,
            sec_val,
            comp_val,
            logic_val,
            perf_val,
            ctx_val,
            review_mode_val,
            session_id,
        )

        # Final yield: show results with Frankie still visible (will auto-hide after 3 seconds)
        yield (
            "",  # empty_state
            get_frankie_loader()
            + summ_result,  # summ - keep Frankie visible with results
            det_result,  # det
            fixes_result,  # fixes_tab
            gr.update(value=audit_record, visible=bool(audit_record)),  # audit_json
            audit_record,  # audit_state
        )

    btn.click(
        fn=run_with_frankie,
        inputs=[code, sec, comp, logic, perf, ctx, review_mode, session_id_state],
        outputs=[
            empty_state,
            summ,
            det,
            fixes_tab,
            audit_json,
            audit_state,
        ],
        api_name="review",
    )


# =============================================================================
# HEALTH CHECK ENDPOINT
# For monitoring and uptime checks
# =============================================================================


def get_health_status() -> dict[str, Any]:
    """
    Health check for monitoring.
    Returns status of all dependencies.
    """
    status: dict[str, Any] = {
        "status": "healthy",
        "version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {},
    }

    # Check API key configured
    if ANTHROPIC_API_KEY:
        status["components"]["api_key"] = "configured"
    else:
        status["components"]["api_key"] = "missing"
        status["status"] = "degraded"

    # Cache stats
    cache_stats = review_cache.stats()
    status["components"]["cache"] = {
        "status": "healthy",
        "hit_rate": f"{cache_stats['hit_rate']:.1%}",
        "size": cache_stats["size"],
    }

    # Rate limiter status
    status["components"]["rate_limiter"] = {
        "status": "healthy",
        "limit": f"{RATE_LIMIT_REQUESTS}/{RATE_LIMIT_WINDOW}s",
    }

    return status


if __name__ == "__main__":
    # Launch main demo
    demo.launch()
