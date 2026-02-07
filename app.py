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

import json
import os
import re
import uuid
import random
from datetime import datetime, timezone

import anthropic
import gradio as gr
import httpx

# Strip whitespace from API key (common issue with copy/paste in HF secrets)
ANTHROPIC_API_KEY = (os.getenv("ANTHROPIC_API_KEY") or "").strip()
MODEL = "claude-sonnet-4-20250514"
SCHEMA_VERSION = "1.0"
TOOL_VERSION = "0.2.1"


# =============================================================================
# CURATED UI COPY - Do not generate new copy here
# IMPORTANT: Only select from predefined copy. Humor and tone are intentional.
# =============================================================================

EASTER_EGGS = {
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
        if verdict not in egg.get("allowed_verdicts", []):
            continue

        # Check audience match
        if audience_lower not in egg.get("audience", []):
            continue

        # Check confidence threshold if specified
        min_conf = egg.get("min_confidence", 0.0)
        if confidence < min_conf:
            continue

        candidates.append(egg)

    if not candidates:
        return None

    # Probabilistic selection - prefer no message over forced humor
    for egg in candidates:
        if random.random() < egg.get("probability", 0.2):
            return egg["copy"]

    return None


# Verdict UI copy - calm, human-readable, no jokes on BLOCK
# IMPORTANT: Do not generate new UI copy here.
# Only select from predefined copy in EASTER_EGGS or UI_COPY.
UI_COPY = {
    "BLOCK": {
        "headline": "Unsafe to merge or deploy",
        "subtext": "This code contains high-risk patterns that are commonly exploited.",
        "confidence_text": "High confidence",
        "alt_subtext": None,  # No jokes allowed
    },
    "REVIEW_REQUIRED": {
        "headline": "Human review recommended",
        "subtext": "Some patterns could become risky depending on how this code is used.",
        "confidence_text": "Medium-High confidence",
        "alt_subtext": None,  # Easter egg can replace this
    },
    "PASS": {
        "headline": "No issues found",
        "subtext": "This code follows safe patterns based on the signals we checked.",
        "confidence_text": "High confidence",
        "alt_subtext": None,  # Easter egg can replace this
    },
}

# Policy rules for decision accountability
POLICY = {
    "version": "v1",
    "block_rules": [
        {"rule_id": "BR-001", "description": "Block if any CRITICAL with confidence >= 0.8", "severity": "CRITICAL", "min_confidence": 0.8},
    ],
    "review_rules": [
        {"rule_id": "RR-001", "description": "Review required if any HIGH with confidence >= 0.7", "severity": "HIGH", "min_confidence": 0.7},
        {"rule_id": "RR-002", "description": "Review required if any CRITICAL with confidence < 0.8", "severity": "CRITICAL", "min_confidence": 0.0, "max_confidence": 0.8},
    ],
}

# Structured prompt with JSON schema for consistent output
SYSTEM_PROMPT = """You are an expert code reviewer producing PR-ready reports. Return a complete analysis as JSON.

<output_schema>
{
  "findings": [
    {
      "id": "F-001",
      "root_cause": "The underlying issue (group related findings)",
      "title": "Brief issue title",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 0.0-1.0,
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

2. EVIDENCE: Show exact line with caret (^) pointing to the vulnerability:
   query = f"SELECT * FROM users WHERE id = {user_id}"
                                          ^ untrusted input in SQL string

3. LOCATION: Use descriptive format - "chat():2" or "get_user():5", not "unknown:2"

4. BLAST RADIUS ESTIMATION (for HIGH/CRITICAL findings):
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
    "security": """Focus on: SQL injection, command injection, XSS, SSRF, path traversal, 
auth bypass, secrets exposure, insecure deserialization, prompt injection.
For prompt injection: use "instruction hierarchy" concept, flag heuristically, include escalation conditions.
For SQL injection: validate type + parameterize + handle errors.
Always estimate blast_radius for HIGH/CRITICAL findings.""",
    "compliance": """Focus on: PII exposure, missing consent, audit trail gaps, data retention,
encryption at rest/transit. Use CONDITIONAL language: "If table contains PII..."
Suggest CONTROLS not violations. Include escalation for when it becomes CRITICAL.
Set data_scope appropriately (pii, regulated, customer).""",
    "logic": """Focus on: Null/undefined handling, race conditions, off-by-one errors,
unhandled exceptions, infinite loops, resource leaks.
For errors: "don't leak internals" and "log safely without secrets".""",
    "performance": """Focus on: N+1 queries, unbounded loops, memory leaks, blocking I/O,
missing indexes, inefficient algorithms, cache misses.
Use DATABASE-SPECIFIC language (sqlite vs postgres vs mysql).""",
}


def generate_run_id():
    """Generate unique run ID."""
    return f"RUN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"


def generate_decision_id():
    """Generate unique decision ID."""
    return f"D-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:4]}"


def parse_findings(text):
    """Extract JSON findings from LLM response."""
    json_match = re.search(r'\{[\s\S]*"findings"[\s\S]*\}', text)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass
    return {"findings": []}


def review_code(code, sec, comp, logic, perf, ctx=""):
    """Run multi-pass code review with structured output."""
    if not code or not code.strip():
        return (
            "<div style='padding:20px;border-left:5px solid orange;background:#fff9e6'><h3>⚠️ No Code</h3><p>Paste code above.</p></div>",
            "",
        )

    if len(code) > 50000:
        return (
            "<div style='padding:20px;border-left:5px solid orange;background:#fff9e6'><h3>⚠️ Code Too Large</h3><p>Please limit to 50,000 characters.</p></div>",
            "",
        )

    if not any([sec, comp, logic, perf]):
        return (
            "<div style='padding:20px;border-left:5px solid orange;background:#fff9e6'><h3>⚠️ No Categories</h3><p>Select at least one.</p></div>",
            "",
        )

    if not ANTHROPIC_API_KEY:
        return (
            "<div style='padding:20px;border-left:5px solid red;background:#fff5f5'><h3>❌ API Key Missing</h3><p>Add ANTHROPIC_API_KEY in Settings → Secrets</p></div>",
            "",
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
        focus_areas = "\n".join([f"- {cat.upper()}: {CATEGORY_PROMPTS[cat]}" for cat in cats])
        
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

        resp = client.messages.create(
            model=MODEL,
            max_tokens=4000,
            temperature=0.0,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        
        result = parse_findings(resp.content[0].text)
        findings = result.get("findings", [])
        
        # Count by severity and confidence
        block_findings = [f for f in findings if f.get("severity") in ["CRITICAL", "HIGH"] and f.get("confidence", 0) >= 0.8]
        warn_findings = [f for f in findings if f.get("severity") in ["CRITICAL", "HIGH"] and f.get("confidence", 0) < 0.8]
        
        # Determine triggered rules for decision accountability
        triggered_block_rules = []
        triggered_review_rules = []
        
        for rule in POLICY["block_rules"]:
            for f in findings:
                if f.get("severity") == rule["severity"] and f.get("confidence", 0) >= rule["min_confidence"]:
                    triggered_block_rules.append({"rule": rule, "finding": f})
                    break
        
        for rule in POLICY["review_rules"]:
            max_conf = rule.get("max_confidence", 1.0)
            for f in findings:
                if f.get("severity") == rule["severity"] and rule["min_confidence"] <= f.get("confidence", 0) < max_conf:
                    triggered_review_rules.append({"rule": rule, "finding": f})
                    break
        
        # Decision logic with policy-based verdict
        if triggered_block_rules:
            verdict = "BLOCK"
            rec, color, bg = "🚫 BLOCK", "#dc3545", "#fff5f5"
        elif triggered_review_rules or len(block_findings) > 0:
            verdict = "REVIEW_REQUIRED"
            rec, color, bg = "⚠️ REVIEW REQUIRED", "#fd7e14", "#fff9e6"
        elif len(warn_findings) > 0:
            verdict = "REVIEW_REQUIRED"
            rec, color, bg = "⚡ CAUTION", "#ffc107", "#fffde6"
        else:
            verdict = "PASS"
            rec, color, bg = "✅ APPROVED", "#28a745", "#f0fff4"

        # Generate decision record for audit trail
        run_id = generate_run_id()
        decision_record = {
            "schema_version": SCHEMA_VERSION,
            "decision_id": generate_decision_id(),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "verdict": verdict,
            "policy": {
                "policy_version": POLICY["version"],
                "block_rules": [{"rule_id": r["rule"]["rule_id"], "description": r["rule"]["description"], "triggered": True} for r in triggered_block_rules],
                "review_rules": [{"rule_id": r["rule"]["rule_id"], "description": r["rule"]["description"], "triggered": True} for r in triggered_review_rules],
            },
            "decision_drivers": [
                {
                    "finding_id": f.get("id", "unknown"),
                    "title": f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "confidence": f.get("confidence", 0),
                    "location": f.get("location", ""),
                    "why_it_matters": f.get("why_it_matters", [f.get("description", "")])
                }
                for f in (block_findings + warn_findings)[:5]  # Top 5 drivers
            ],
            "override": {
                "allowed": True,
                "status": "none",
                "approver": None,
                "justification": None
            },
            "run_context": {
                "run_id": run_id,
                "mode": "manual",
                "source": "stdin",
                "files_reviewed": 1,
                "limits": {
                    "max_chars": 50000,
                    "truncated": len(code) > 50000,
                }
            }
        }
        
        # Extract blast radius summaries for HIGH/CRITICAL findings
        blast_radius_findings = []
        for f in findings:
            if f.get("severity") in ["CRITICAL", "HIGH"] and f.get("blast_radius"):
                blast_radius_findings.append({
                    "finding_id": f.get("id", "unknown"),
                    "blast_radius": f.get("blast_radius"),
                    "confidence": f.get("confidence", 0),
                })

        # Summary HTML with blast radius indicator
        has_high_blast = any(
            br.get("blast_radius", {}).get("data_scope") in ["pii", "regulated"] or
            br.get("blast_radius", {}).get("org_scope") in ["external-customers", "regulators"]
            for br in blast_radius_findings
        )
        blast_indicator = " · High Blast Radius" if has_high_blast else ""
        
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
        
        # Verdict display config
        verdict_display = {
            "BLOCK": {"css_class": "verdict-block", "dot_color": "#dc3545"},
            "REVIEW_REQUIRED": {"css_class": "verdict-review", "dot_color": "#CD8F7A"},
            "PASS": {"css_class": "verdict-pass", "dot_color": "#28a745"},
        }
        
        vd = verdict_display.get(verdict, verdict_display["PASS"])
        
        # Luxury summary card
        summary = f"""
<div style="padding: 24px; background: linear-gradient(135deg, #FAF8F4 0%, #E7DCCE 100%); border-left: 4px solid {vd['dot_color']}; border-radius: 12px; margin-bottom: 16px;">
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
        <span style="width: 12px; height: 12px; background: {vd['dot_color']}; border-radius: 50%;"></span>
        <span style="font-family: 'Inter', sans-serif; font-weight: 600; font-size: 0.85em; color: #2A2926; text-transform: uppercase; letter-spacing: 0.05em;">
            {verdict.replace('_', ' ')}
        </span>
    </div>
    <h2 style="font-family: 'Playfair Display', Georgia, serif; font-size: 1.5em; color: #2A2926; margin: 0 0 8px 0; font-weight: 500;">
        {base_copy['headline']}
    </h2>
    <p style="font-family: 'Inter', sans-serif; color: #6B6560; font-size: 0.95em; margin: 0 0 16px 0; line-height: 1.5;">
        {subtext}
    </p>
    <div style="display: flex; gap: 16px; flex-wrap: wrap; font-size: 0.85em; color: #6B6560;">
        <span style="background: rgba(220, 204, 179, 0.7); padding: 4px 12px; border-radius: 999px;">{base_copy['confidence_text']}</span>
        <span>{len(findings)} finding{'s' if len(findings) != 1 else ''}{blast_indicator}</span>
    </div>
</div>
<p style="font-size: 0.8em; color: #A89F91; margin-top: 8px;">
    Decision ID: {decision_record['decision_id']} · Policy: {POLICY['version']}
</p>
"""

        # Build detailed markdown report with progressive disclosure
        details = ""
        
        if not findings:
            details += """
## No issues found

This code follows safe patterns based on the signals we checked.

*This doesn't guarantee zero risk, but no concerning patterns were detected.*
"""
        else:
            # Layer 1: Plain language overview (Beginner-friendly)
            details += "## What we found\n\n"
            
            for i, f in enumerate(findings[:3]):  # Top 3 for overview
                sev = f.get("severity", "MEDIUM")
                border_color = {"CRITICAL": "#CD8F7A", "HIGH": "#A89F91", "MEDIUM": "#D8C5B2", "LOW": "#E7DCCE"}.get(sev, "#D8C5B2")
                
                # Plain language explanation
                plain_desc = f.get("description", "An issue was detected.")
                plain_impact = f.get("impact", "This could affect how the code behaves.")
                plain_rec = f.get("recommendation", "Review and address this issue.")
                
                details += f"""
<div style="border-left: 3px solid {border_color}; padding-left: 16px; margin-bottom: 20px;">

**{f.get('title', 'Issue')}**

{plain_desc}

**Why this matters:** {plain_impact}

**What to do:** {plain_rec}

</div>
"""
            
            if len(findings) > 3:
                details += f"\n*+ {len(findings) - 3} more finding{'s' if len(findings) - 3 != 1 else ''} in Advanced tab*\n"
            
            # Layer 2: Technical details (Intermediate)
            details += "\n---\n\n## Technical Details\n\n"
            
            # Group by root cause
            root_causes = {}
            for f in findings:
                rc = f.get("root_cause", f.get("title", "Other"))
                if rc not in root_causes:
                    root_causes[rc] = []
                root_causes[rc].append(f)
            
            for root_cause, items in root_causes.items():
                items = sorted(items, key=lambda x: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("severity", "LOW"), 4), -x.get("confidence", 0)))
                
                top_sev = items[0].get("severity", "MEDIUM")
                
                details += f"### Root Cause: {root_cause}\n\n"
                
                for f in items:
                    sev = f.get("severity", "UNKNOWN")
                    conf = f.get("confidence", 0)
                    conf_text = "High confidence" if conf >= 0.8 else "Medium confidence" if conf >= 0.5 else "Low confidence"
                    
                    details += f"**{f.get('title', 'Issue')}** · {sev} · {conf_text}\n\n"
                    
                    location = f.get("location") or (f"Line {f.get('line')}" if f.get("line") else None)
                    if location:
                        details += f"Location: `{location}`\n\n"
                    
                    if f.get("evidence"):
                        details += f"```\n{f.get('evidence')}\n```\n\n"
                    elif f.get("snippet"):
                        details += f"```python\n{f.get('snippet')}\n```\n\n"
                    
                    if f.get("tags"):
                        details += f"Tags: {', '.join(f.get('tags', []))}\n\n"
                    
                    # Blast radius for HIGH/CRITICAL
                    br = f.get("blast_radius")
                    if br and sev in ["CRITICAL", "HIGH"]:
                        details += "<details>\n<summary>Blast Radius Estimate</summary>\n\n"
                        details += f"- **Technical:** {br.get('technical_scope', 'unknown')}\n"
                        details += f"- **Data:** {br.get('data_scope', 'unknown')}\n"
                        details += f"- **Organizational:** {br.get('org_scope', 'unknown')}\n\n"
                        details += "</details>\n\n"
                    
                    if f.get("escalation") and sev in ["HIGH", "MEDIUM"]:
                        details += f"*Escalates to CRITICAL if: {f.get('escalation')}*\n\n"
                
                details += "---\n\n"
        
        # Decision accountability section (collapsible)
        if triggered_block_rules or triggered_review_rules:
            details += "<details>\n<summary>Decision Reasoning</summary>\n\n"
            details += "**Why this verdict was reached:**\n\n"
            for tr in triggered_block_rules:
                details += f"- **{tr['rule']['rule_id']}**: {tr['rule']['description']}\n"
            for tr in triggered_review_rules:
                details += f"- **{tr['rule']['rule_id']}**: {tr['rule']['description']}\n"
            details += "\n*Override allowed with human approval + justification*\n\n"
            details += "</details>\n\n"
        
        # Audit record (Advanced tab content)
        details += "<details>\n<summary>Audit Record (JSON)</summary>\n\n```json\n"
        details += json.dumps(decision_record, indent=2)
        details += "\n```\n</details>\n"

        return summary, details

    except anthropic.AuthenticationError as e:
        return (
            f"<div style='padding:20px;border-left:5px solid red;background:#fff5f5'><h3>❌ Authentication Error</h3><p>Invalid API key. Check ANTHROPIC_API_KEY in Settings → Secrets.</p><p>Details: {str(e)}</p></div>",
            "",
        )

    except anthropic.NotFoundError as e:
        return (
            f"<div style='padding:20px;border-left:5px solid red;background:#fff5f5'><h3>❌ Model Not Found</h3><p>Model {MODEL} not available. Details: {str(e)}</p></div>",
            "",
        )

    except anthropic.APIConnectionError as e:
        # Provide more detailed connection error info
        error_detail = str(e)
        if "SSL" in error_detail or "certificate" in error_detail.lower():
            hint = (
                "SSL/TLS certificate issue. The server may need updated certificates."
            )
        elif "timeout" in error_detail.lower():
            hint = "Connection timed out. Try again in a moment."
        else:
            hint = "Network connectivity issue. The Anthropic API may be temporarily unreachable."
        return (
            f"<div style='padding:20px;border-left:5px solid red;background:#fff5f5'><h3>❌ Connection Error</h3><p>{hint}</p><p><small>Details: {error_detail}</small></p></div>",
            "",
        )

    except anthropic.BadRequestError as e:
        return (
            f"<div style='padding:20px;border-left:5px solid red;background:#fff5f5'><h3>❌ Bad Request</h3><p>The API rejected the request.</p><p><small>Details: {str(e)}</small></p></div>",
            "",
        )

    except Exception as e:
        # Show more details to help debug
        return (
            f"<div style='padding:20px;border-left:5px solid red;background:#fff5f5'><h3>❌ Error</h3><p>An unexpected error occurred.</p><p><small>Error type: {type(e).__name__}: {str(e)}</small></p></div>",
            "",
        )


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
   DARK SPINE + LIGHT CANVAS
   Rule: Dark = input/focus | Light = results/explanation
   Rule: If it's clickable, it must look clickable
   ================================================================= */

:root {
  /* Light canvas (Ivory mode) */
  --bg: #FAF8F4;
  --panel: #E7DCCE;
  --panel2: #D8C5B2;
  --text: #2A2926;
  --text2: #1B1A18;
  --accent: #CD8F7A;
  --gold: #DCCCB3;

  /* Dark spine */
  --spine: #1B1A18;
  --spine2: #2A2926;
  --spineText: #FAF8F4;

  /* UI tokens */
  --radius: 18px;
  --radiusSm: 12px;
  --border: rgba(42,41,38,0.12);
  --shadow: 0 10px 30px rgba(27,26,24,0.10);
}

/* Noir mode */
body[data-theme="noir"] {
  --bg: #1B1A18;
  --panel: #2A2926;
  --panel2: #2A2926;
  --text: #FAF8F4;
  --text2: #FAF8F4;
  --border: rgba(250,248,244,0.14);
  --shadow: 0 12px 36px rgba(0,0,0,0.35);
  --spine: #121110;
  --spine2: #1B1A18;
}

/* Page */
.gradio-container {
  background: var(--bg) !important;
  color: var(--text2) !important;
  max-width: 1200px !important;
  margin: 0 auto !important;
  font-family: 'Inter', system-ui, sans-serif !important;
}

/* Header */
#brand_header {
  text-align: center;
  padding: 16px 0 24px 0;
}
#brand_title {
  font-family: 'Playfair Display', Georgia, serif;
  font-size: 2em;
  font-weight: 500;
  color: var(--text);
  margin: 0;
}
#brand_subtitle {
  font-size: 0.95em;
  color: rgba(107, 101, 96, 0.85);
  margin-top: 6px;
}
body[data-theme="noir"] #brand_subtitle {
  color: rgba(250,248,244,0.6);
}

/* Theme toggle pill */
#mode_toggle {
  display: flex;
  justify-content: center;
  margin-bottom: 20px;
}
#mode_toggle .wrap {
  background: var(--panel) !important;
  border: 1px solid var(--border) !important;
  border-radius: 999px !important;
  padding: 4px 6px !important;
}
#mode_toggle label {
  padding: 6px 16px !important;
  border-radius: 999px !important;
  font-weight: 600 !important;
  font-size: 0.85em !important;
  cursor: pointer !important;
  transition: all 0.2s !important;
}
#mode_toggle input:checked + label {
  background: var(--accent) !important;
  color: var(--bg) !important;
}
body[data-theme="noir"] #mode_toggle .wrap {
  background: var(--spine2) !important;
}

/* Two-panel layout */
#shell {
  gap: 0 !important;
}

/* LEFT: Dark spine */
#left_spine {
  background: var(--spine) !important;
  border-radius: var(--radius) 0 0 var(--radius) !important;
  padding: 24px !important;
  min-height: 520px !important;
  border: none !important;
}
#left_spine .block, #left_spine .form {
  background: transparent !important;
  border: none !important;
}

/* Spine labels */
.spine_label {
  color: rgba(250,248,244,0.6);
  font-size: 0.75em;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 4px;
}
.spine_title {
  color: var(--spineText);
  font-weight: 600;
  font-size: 1em;
  margin-bottom: 12px;
}

/* Code editor in spine */
#left_spine textarea, #left_spine .cm-editor {
  background: var(--spine2) !important;
  color: var(--spineText) !important;
  border: 1px solid rgba(250,248,244,0.1) !important;
  border-radius: var(--radiusSm) !important;
  font-family: 'JetBrains Mono', ui-monospace, monospace !important;
  font-size: 0.9em !important;
  min-height: 300px !important;
}
#left_spine textarea:focus, #left_spine .cm-editor.cm-focused {
  outline: none !important;
  box-shadow: 0 0 0 3px rgba(205,143,122,0.3) !important;
  border-color: var(--accent) !important;
}

/* Primary button */
#review_btn {
  margin-top: 16px !important;
}
#review_btn button {
  background: var(--accent) !important;
  color: var(--bg) !important;
  border: none !important;
  border-radius: 14px !important;
  padding: 14px 24px !important;
  font-weight: 600 !important;
  font-size: 1em !important;
  width: 100% !important;
  cursor: pointer !important;
  transition: all 0.2s !important;
}
#review_btn button:hover {
  filter: brightness(0.92) !important;
  transform: translateY(-1px) !important;
}

/* Sample button */
#sample_btn button {
  background: transparent !important;
  color: rgba(250,248,244,0.85) !important;
  border: 1px solid rgba(250,248,244,0.2) !important;
  border-radius: 14px !important;
  padding: 10px 16px !important;
  font-size: 0.9em !important;
}
#sample_btn button:hover {
  background: rgba(250,248,244,0.08) !important;
}

/* Filename input */
#filename_box input {
  background: rgba(250,248,244,0.06) !important;
  color: var(--spineText) !important;
  border: 1px solid rgba(250,248,244,0.15) !important;
  border-radius: var(--radiusSm) !important;
  padding: 10px 14px !important;
}
#filename_box input::placeholder {
  color: rgba(250,248,244,0.4) !important;
}
#filename_box label {
  color: rgba(250,248,244,0.7) !important;
  font-size: 0.85em !important;
}

/* Customize accordion - real affordance */
#customize_acc {
  margin-top: 16px !important;
  background: rgba(250,248,244,0.04) !important;
  border: 1px solid rgba(250,248,244,0.15) !important;
  border-radius: var(--radiusSm) !important;
}
#customize_acc .label-wrap {
  color: rgba(250,248,244,0.9) !important;
  font-weight: 600 !important;
  padding: 12px 14px !important;
}
#customize_acc .label-wrap:hover {
  background: rgba(250,248,244,0.06) !important;
}
#customize_acc .icon {
  color: rgba(250,248,244,0.6) !important;
}
#customize_acc .wrap {
  padding: 0 14px 14px 14px !important;
}
#customize_acc label {
  color: rgba(250,248,244,0.75) !important;
  font-size: 0.9em !important;
}
#customize_acc input[type="checkbox"] {
  accent-color: var(--accent) !important;
}

/* RIGHT: Light results panel */
#right_panel {
  background: rgba(231,220,206,0.35) !important;
  border: 1px solid var(--border) !important;
  border-left: none !important;
  border-radius: 0 var(--radius) var(--radius) 0 !important;
  padding: 24px !important;
  min-height: 520px !important;
}
body[data-theme="noir"] #right_panel {
  background: rgba(42,41,38,0.5) !important;
}
#right_panel .block, #right_panel .form {
  background: transparent !important;
  border: none !important;
}

/* Right panel labels */
.results_label {
  color: rgba(27,26,24,0.55);
  font-size: 0.75em;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 4px;
}
.results_title {
  color: var(--text);
  font-weight: 600;
  font-size: 1em;
  margin-bottom: 16px;
}
body[data-theme="noir"] .results_label {
  color: rgba(250,248,244,0.5);
}
body[data-theme="noir"] .results_title {
  color: var(--text);
}

/* Empty state */
#empty_state {
  background: rgba(250,248,244,0.7);
  border: 1px dashed rgba(42,41,38,0.18);
  border-radius: var(--radiusSm);
  padding: 40px 24px;
  text-align: center;
}
#empty_state .empty_title {
  font-weight: 600;
  color: var(--text);
  margin-bottom: 8px;
}
#empty_state .empty_text {
  color: rgba(27,26,24,0.6);
  font-size: 0.9em;
}
body[data-theme="noir"] #empty_state {
  background: rgba(42,41,38,0.6);
  border-color: rgba(250,248,244,0.12);
}
body[data-theme="noir"] #empty_state .empty_title {
  color: var(--text);
}
body[data-theme="noir"] #empty_state .empty_text {
  color: rgba(250,248,244,0.6);
}

/* Verdict card */
#verdict_card {
  background: rgba(250,248,244,0.8);
  border: 1px solid var(--border);
  border-radius: var(--radiusSm);
  padding: 20px;
  margin-bottom: 16px;
}
body[data-theme="noir"] #verdict_card {
  background: rgba(42,41,38,0.7);
}

/* Verdict pill */
.verdict_pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 6px 14px;
  border-radius: 999px;
  font-weight: 700;
  font-size: 0.8em;
  text-transform: uppercase;
  letter-spacing: 0.03em;
}
.verdict_pill.block { background: rgba(220,53,69,0.15); color: #dc3545; }
.verdict_pill.review { background: rgba(205,143,122,0.2); color: #B87D6A; }
.verdict_pill.pass { background: rgba(40,167,69,0.15); color: #28a745; }
.verdict_dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
.verdict_dot.block { background: #dc3545; }
.verdict_dot.review { background: var(--accent); }
.verdict_dot.pass { background: #28a745; }

/* Tabs */
#right_panel .tabs {
  margin-top: 8px;
}
#right_panel .tab-nav button {
  color: var(--text) !important;
  font-weight: 500 !important;
  border-radius: var(--radiusSm) var(--radiusSm) 0 0 !important;
}
#right_panel .tab-nav button.selected {
  background: rgba(250,248,244,0.6) !important;
}
body[data-theme="noir"] #right_panel .tab-nav button.selected {
  background: rgba(42,41,38,0.8) !important;
}

/* Footer */
.footer {
  text-align: center;
  padding: 24px 0;
  margin-top: 32px;
  border-top: 1px solid var(--border);
}
.footer a {
  color: var(--accent);
  text-decoration: none;
}
.footer p {
  font-size: 0.8em;
  color: rgba(107,101,96,0.7);
}
body[data-theme="noir"] .footer p {
  color: rgba(250,248,244,0.5);
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


def load_sample():
    """Load sample vulnerable code for demo."""
    return SAMPLE_CODE, "app.py"


def set_theme(mode: str):
    """Return JS to set theme on body element."""
    theme = "noir" if mode.lower() == "noir" else "light"
    return f'<script>document.body.dataset.theme="{theme}";</script>'


with gr.Blocks(title="Code Review Agent", theme=APP_THEME, css=APP_CSS) as demo:

    # Header
    gr.HTML('''
    <div id="brand_header">
        <div id="brand_title">Code Review Agent</div>
        <div id="brand_subtitle">Judgment-aware security analysis for AI-enabled systems</div>
    </div>
    ''')

    # Theme toggle (Ivory / Noir)
    with gr.Row():
        with gr.Column():
            theme_mode = gr.Radio(
                choices=["Ivory", "Noir"],
                value="Ivory",
                label="",
                elem_id="mode_toggle",
                interactive=True
            )
            theme_js = gr.HTML("")

    theme_mode.change(fn=set_theme, inputs=theme_mode, outputs=theme_js)

    # Main layout: Dark spine (left) + Light results (right)
    with gr.Row(elem_id="shell", equal_height=True):

        # =====================================================
        # LEFT: DARK SPINE - "Give me something"
        # =====================================================
        with gr.Column(scale=4, elem_id="left_spine"):

            gr.HTML('<div class="spine_label">Step 1</div><div class="spine_title">Paste your code</div>')

            code = gr.Code(
                value="",
                language="python",
                label="",
                lines=14,
                show_label=False
            )

            gr.HTML('<div class="spine_label" style="margin-top: 16px;">Step 2</div>')

            with gr.Row():
                btn = gr.Button("Review this code", elem_id="review_btn", scale=3)
                sample_btn = gr.Button("Try example", elem_id="sample_btn", scale=2)

            ctx = gr.Textbox(
                label="Filename (optional)",
                placeholder="e.g., app.py",
                lines=1,
                elem_id="filename_box"
            )

            with gr.Accordion("Customize review", open=False, elem_id="customize_acc"):
                gr.HTML('<p style="color: rgba(250,248,244,0.6); font-size: 0.85em; margin-bottom: 12px;">Choose what to check. Beginners can leave this alone.</p>')
                with gr.Row():
                    sec = gr.Checkbox(label="Security", value=True)
                    comp = gr.Checkbox(label="Compliance", value=True)
                with gr.Row():
                    logic = gr.Checkbox(label="Logic", value=False)
                    perf = gr.Checkbox(label="Performance", value=False)

        # =====================================================
        # RIGHT: LIGHT PANEL - "Here's what I found"
        # =====================================================
        with gr.Column(scale=6, elem_id="right_panel"):

            gr.HTML('<div class="results_label">Step 3</div><div class="results_title">Results</div>')

            empty_state = gr.HTML('''
            <div id="empty_state">
                <div class="empty_title">Your review will show up here</div>
                <div class="empty_text">Paste code on the left and click <strong>Review this code</strong></div>
            </div>
            ''')

            summ = gr.HTML("", elem_id="verdict_card_container")

            with gr.Tabs():
                with gr.Tab("Overview"):
                    det = gr.Markdown("")
                with gr.Tab("Fixes"):
                    fixes_tab = gr.Markdown("*Suggested fixes will appear after review*")
                with gr.Tab("Advanced"):
                    advanced_tab = gr.Markdown("*Decision records and audit data will appear after review*")

    # Footer
    gr.HTML('''
    <div class="footer">
        <p>
            <a href="https://github.com/adarian-dewberry/code-review-agent">GitHub</a>
            <span style="margin: 0 12px; opacity: 0.4;">·</span>
            Human review always recommended
        </p>
    </div>
    ''')

    # Wire up sample button
    sample_btn.click(fn=load_sample, outputs=[code, ctx])

    # Wire up review button - hide empty state when results arrive
    def run_and_clear(code_val, sec_val, comp_val, logic_val, perf_val, ctx_val):
        summ_result, det_result = review_code(code_val, sec_val, comp_val, logic_val, perf_val, ctx_val)
        # Hide empty state by returning empty string
        return "", summ_result, det_result

    btn.click(
        fn=run_and_clear,
        inputs=[code, sec, comp, logic, perf, ctx],
        outputs=[empty_state, summ, det],
        api_name="review"
    )

if __name__ == "__main__":
    demo.launch()
