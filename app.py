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

import base64
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
from pathlib import Path
from typing import Any

import anthropic
import gradio as gr
import httpx

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
.findings_table td {
  padding: 12px 12px;
  border-bottom: 1px solid var(--border);
  vertical-align: middle;
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
   EXPORT BUTTONS
   ================================================================= */
#export_btn button, #export_md_btn button {
  background: linear-gradient(180deg, #4A9F5E 0%, var(--pass) 50%, #1E7B34 100%) !important;
  color: white !important;
  border: none !important;
  border-radius: var(--radiusXs) !important;
  padding: 10px 16px !important;
  font-weight: 600 !important;
  font-size: var(--font-sm) !important;
  cursor: pointer !important;
  box-shadow: 0 2px 0 #1A6B2E, 0 3px 8px rgba(40,167,69,0.2) !important;
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
}

#frankie_inline_container {
  position: relative;
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
  margin: 0 auto 32px;
  overflow: visible;
  flex-shrink: 0;
  filter: drop-shadow(0 6px 14px rgba(0,0,0,0.2));
}

.frankie_silhouette {
  width: 100%;
  height: 100%;
  animation: frankieBreath 4s ease-in-out infinite;
}

.frankie_mascot_img {
  width: 100%;
  height: auto;
  display: block;
  object-fit: contain;
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

/* Gentle breathing/nodding motion for sitting dog */
@keyframes frankieBreath {
  0%, 100% { 
    transform: scale(1) rotateZ(0deg);
  }
  25% {
    transform: scale(1.02) rotateZ(-1deg);
  }
  50% {
    transform: scale(1.03) rotateZ(0deg);
  }
  75% {
    transform: scale(1.02) rotateZ(1deg);
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
  .frankie_silhouette {
    animation: none !important;
  }
  
  #frankie_inline_container {
    animation: none !important;
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
body[data-theme="dark-mode"] .muted,
body[data-theme="dark-mode"] .text2 {
  color: rgba(250,248,244,0.8) !important;
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

/* =================================================================
   MOBILE RESPONSIVE - iOS and Android friendly
   ================================================================= */

/* Tablet breakpoint */
@media screen and (max-width: 1024px) {
  .gradio-container {
    max-width: 100% !important;
    padding: 0 12px !important;
  }

  #shell {
    flex-direction: column !important;
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

  .gradio-container {
    padding: 0 8px !important;
  }

  #brand_header {
    padding: 20px 16px 24px 16px !important;
    margin: -8px -8px 16px -8px !important;
  }

  #brand_title {
    font-size: 1.75em !important;
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

  #left_spine,
  #right_panel {
    padding: 16px !important;
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

  /* Frankie loader: smaller on mobile */
  #frankie_loader {
    padding: 32px 24px !important;
    max-width: 90% !important;
    margin: 16px !important;
  }

  .frankie_container {
    width: 100px !important;
    height: 68px !important;
  }

  /* Footer: stacked links */
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

    mascot_data_url = ""
    mascot_path = Path(__file__).parent / "media" / "frankie_mascot.png"

    try:
        if mascot_path.exists():
            with open(mascot_path, "rb") as img_file:
                img_base64 = base64.b64encode(img_file.read()).decode("utf-8")
                mascot_data_url = f"data:image/png;base64,{img_base64}"
        else:
            logger.warning("Mascot image not found at %s", mascot_path)
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Failed to load mascot image: %s", exc)

    return f"""
    <div id="frankie_overlay" style="display: flex; opacity: 1;">
        <div id="frankie_inline_container" class="frankie-state-scanning">
            <div id="frankie_loader">
                <div class="frankie_container" aria-live="polite" aria-label="Code review in progress - Frankie's watching your code">
                    <div class="frankie_ball"></div>
                    <div class="frankie_silhouette">
                        <img src="{mascot_data_url}" alt="Frankie the security dog" class="frankie_mascot_img" />
                    </div>
                </div>
                <div class="frankie_title">Frankie's Watching Your Code</div>
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
    
    // Watch for verdict card appearance to trigger state transitions
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.type === 'childList' || mutation.type === 'characterData') {
                const verdictCard = document.getElementById('verdict_card_container');
                if (verdictCard && verdictCard.textContent.trim() !== '' && !verdictCard.textContent.includes('Frankie')) {
                    if (window.frankieState.currentState !== 'monitoring') {
                        window.frankieState.transitionToFound();
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
                    with gr.Row():
                        export_btn = gr.Button(
                            "📥 Export JSON", visible=False, elem_id="export_btn"
                        )
                        export_md_btn = gr.Button(
                            "📄 Export Markdown", visible=False, elem_id="export_md_btn"
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
            export_btn,
            export_md_btn,
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
            gr.update(visible=False),  # Hide export btn
            gr.update(visible=False),  # Hide export md btn
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
            export_btn,
            export_md_btn,
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

        # Final yield: show results, transition Frankie to monitoring, show export controls
        yield (
            "",  # empty_state
            summ_result,  # summ
            det_result,  # det
            fixes_result,  # fixes_tab
            gr.update(value=audit_record, visible=bool(audit_record)),  # audit_json
            gr.update(visible=bool(audit_record)),  # export_btn
            gr.update(visible=bool(audit_record)),  # export_md_btn
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
            export_btn,
            export_md_btn,
            audit_state,
        ],
        api_name="review",
    )

    # Wire up export JSON button
    def do_export_json(audit_record):
        """Return audit record for JSON component."""
        return audit_record

    export_btn.click(
        fn=do_export_json,
        inputs=[audit_state],
        outputs=audit_json,
        api_name="export_audit",
    )

    # Wire up export Markdown button
    def do_export_markdown(audit_record):
        """Generate markdown export of the audit record."""
        if not audit_record:
            return "No audit record available."

        md = f"""# Security Audit Report

**Decision ID:** {audit_record.get("decision_id", "N/A")}
**Timestamp:** {audit_record.get("timestamp_utc", "N/A")}
**Verdict:** {audit_record.get("verdict", "N/A")}

## Policy Information

- **Version:** {audit_record.get("policy", {}).get("policy_version", "N/A")}
- **URL:** {audit_record.get("policy", {}).get("policy_url", "N/A")}

## Decision Drivers

"""
        for driver in audit_record.get("decision_drivers", []):
            md += f"""### {driver.get("finding_id", "N/A")}: {driver.get("title", "Untitled")}
- **Severity:** {driver.get("severity", "N/A")}
- **Confidence:** {driver.get("confidence", 0):.0%}
- **Location:** {driver.get("location", "N/A")}
- **CWE:** {driver.get("cwe") or "N/A"}
- **OWASP:** {driver.get("owasp") or "N/A"}

"""
        md += """---

*Generated by Code Review Agent (Frankie)*
"""
        return md

    export_md_btn.click(
        fn=do_export_markdown,
        inputs=[audit_state],
        outputs=det,
        api_name="export_markdown",
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


# Create a simple health endpoint using Gradio's API
with gr.Blocks() as health_app:
    health_output = gr.JSON(label="Health Status")
    health_btn = gr.Button("Check Health")
    health_btn.click(fn=get_health_status, outputs=health_output, api_name="health")


if __name__ == "__main__":
    # Launch main demo
    # Health endpoint available at /api/health
    demo.launch()
