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


with gr.Blocks(
    title="Code Review Agent",
    theme=gr.themes.Base(
        primary_hue=gr.themes.colors.orange,
        secondary_hue=gr.themes.colors.stone,
        neutral_hue=gr.themes.colors.stone,
        font=gr.themes.GoogleFont("Inter"),
        font_mono=gr.themes.GoogleFont("JetBrains Mono"),
    ),
    css="""
    /* =================================================================
       MODERN AI UX - Left to Right Flow
       Rule: Every screen answers one question at a time.
       Rule: Whitespace is direction, not emptiness.
       Rule: AI tools should feel like transformation, not configuration.
       ================================================================= */
    
    /* Base - Warm Ivory canvas */
    .gradio-container {
        background: #FAF8F4 !important;
        font-family: 'Inter', sans-serif !important;
        max-width: 1200px !important;
        margin: 0 auto !important;
    }
    
    /* Kill the "everything is a card" problem */
    .panel, .block, .form {
        background: transparent !important;
        border: none !important;
        box-shadow: none !important;
    }
    
    /* Typography - Playfair for headings only */
    h1, h2, h3 {
        font-family: 'Playfair Display', Georgia, serif !important;
        color: #2A2926 !important;
        letter-spacing: -0.01em !important;
        font-weight: 500 !important;
    }
    
    /* Body text - quiet, readable */
    p, span, label, .prose {
        color: #6B6560 !important;
        line-height: 1.6 !important;
        font-size: 0.95em !important;
    }
    
    /* Code input - THE dominant element on left */
    .code-input textarea {
        background: #F5F1EA !important;
        border: 2px solid #E7DCCE !important;
        border-radius: 12px !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.9em !important;
        padding: 16px !important;
        min-height: 320px !important;
    }
    .code-input textarea:focus {
        border-color: #CD8F7A !important;
        outline: none !important;
        box-shadow: 0 0 0 3px rgba(205, 143, 122, 0.15) !important;
    }
    
    /* Primary button - THE only strong color on left */
    .primary-btn {
        background: #CD8F7A !important;
        color: #FAF8F4 !important;
        border: none !important;
        border-radius: 10px !important;
        font-weight: 600 !important;
        font-size: 1em !important;
        padding: 14px 28px !important;
        cursor: pointer !important;
        transition: all 0.2s ease !important;
        width: 100% !important;
    }
    .primary-btn:hover {
        background: #B87D6A !important;
        transform: translateY(-1px) !important;
    }
    
    /* Options toggle - collapsed by default feel */
    .options-toggle {
        color: #A89F91 !important;
        font-size: 0.85em !important;
        cursor: pointer !important;
        padding: 8px 0 !important;
        border: none !important;
        background: none !important;
    }
    .options-toggle:hover {
        color: #CD8F7A !important;
    }
    
    /* Checkboxes - minimal */
    .checkbox-group label {
        font-size: 0.85em !important;
        color: #6B6560 !important;
    }
    input[type="checkbox"] {
        accent-color: #CD8F7A !important;
    }
    
    /* Right side - empty on purpose before results */
    .results-empty {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        min-height: 400px;
        color: #A89F91;
        text-align: center;
    }
    
    /* Results - transform the layout when they appear */
    .results-container {
        background: #FAF8F4 !important;
        padding: 0 !important;
    }
    
    /* Verdict card - big, clear, first thing you see */
    .verdict-card {
        padding: 28px 24px;
        border-radius: 16px;
        margin-bottom: 24px;
    }
    .verdict-block {
        background: linear-gradient(135deg, #FFF5F5 0%, #FAF8F4 100%);
        border-left: 5px solid #dc3545;
    }
    .verdict-review {
        background: linear-gradient(135deg, #FFFBF0 0%, #FAF8F4 100%);
        border-left: 5px solid #CD8F7A;
    }
    .verdict-pass {
        background: linear-gradient(135deg, #F0FFF4 0%, #FAF8F4 100%);
        border-left: 5px solid #28a745;
    }
    
    /* Findings - clean list, not cards */
    .finding-item {
        padding: 16px 0;
        border-bottom: 1px solid #E7DCCE;
    }
    .finding-item:last-child {
        border-bottom: none;
    }
    
    /* Collapsible details - hidden until asked */
    details {
        margin-top: 16px;
    }
    details summary {
        color: #A89F91 !important;
        cursor: pointer !important;
        font-size: 0.85em !important;
        padding: 8px 0 !important;
    }
    details summary:hover {
        color: #CD8F7A !important;
    }
    
    /* Footer - quiet */
    .footer {
        text-align: center;
        padding: 32px 0;
        margin-top: 48px;
        border-top: 1px solid #E7DCCE;
    }
    .footer a {
        color: #CD8F7A;
        text-decoration: none;
    }
    .footer p {
        font-size: 0.8em !important;
        color: #A89F91 !important;
    }
    """
) as demo:
    
    # Minimal header - not competing with content
    gr.HTML("""
    <div style="padding: 20px 0 32px 0; text-align: center;">
        <h1 style="font-family: 'Playfair Display', Georgia, serif; font-size: 1.8em; font-weight: 500; color: #2A2926; margin: 0;">
            Code Review Agent
        </h1>
    </div>
    """)

    with gr.Row(equal_height=False):
        
        # =====================================================
        # LEFT SIDE = "Give me something"
        # Rule: One obvious starting point
        # Rule: Code input is visually dominant
        # =====================================================
        with gr.Column(scale=1):
            
            # Code input - THE main thing
            code = gr.Code(
                label="",
                language="python",
                lines=18,
                show_label=False,
                placeholder="Paste your code here\n\nWe'll take a careful look before anything ships.",
                elem_classes=["code-input"]
            )
            
            # THE button - unmissable, directly under code
            btn = gr.Button(
                "Review this code",
                variant="primary",
                size="lg",
                elem_classes=["primary-btn"]
            )
            
            # Options - collapsed/hidden until needed
            with gr.Accordion("Customize review", open=False):
                ctx = gr.Textbox(
                    label="Filename",
                    placeholder="e.g., app.py",
                    lines=1,
                    show_label=True
                )
                gr.HTML("<p style='font-size: 0.8em; color: #A89F91; margin: 12px 0 8px 0;'>What to check</p>")
                with gr.Row():
                    sec = gr.Checkbox(label="Security", value=True)
                    comp = gr.Checkbox(label="Compliance", value=True)
                with gr.Row():
                    logic = gr.Checkbox(label="Logic", value=False)
                    perf = gr.Checkbox(label="Performance", value=False)
        
        # =====================================================
        # RIGHT SIDE = "Here's what I found"
        # Rule: Empty on purpose before analysis
        # Rule: Layout transforms when results appear
        # =====================================================
        with gr.Column(scale=1):
            
            # Summary - verdict first, big and clear
            summ = gr.HTML(
                value="""
                <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 380px; color: #A89F91; text-align: center; padding: 40px;">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#D8C5B2" stroke-width="1.5" style="margin-bottom: 16px;">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                        <polyline points="14 2 14 8 20 8"></polyline>
                        <line x1="16" y1="13" x2="8" y2="13"></line>
                        <line x1="16" y1="17" x2="8" y2="17"></line>
                        <polyline points="10 9 9 9 8 9"></polyline>
                    </svg>
                    <p style="font-size: 1em; color: #6B6560; margin: 0 0 8px 0;">
                        Paste code on the left
                    </p>
                    <p style="font-size: 0.85em; color: #A89F91; margin: 0;">
                        Click "Review this code" to begin
                    </p>
                </div>
                """,
                elem_classes=["results-container"]
            )
            
            # Details - appears after results, in order:
            # 1. Verdict (in summ above)
            # 2. Explanation + Findings (det below)
            # 3. Advanced (collapsed in det)
            det = gr.Markdown(elem_classes=["results-container"])

    # Footer - quiet, doesn't compete
    gr.HTML("""
    <div class="footer">
        <p style="margin: 0;">
            <a href="https://github.com/adarian-dewberry/code-review-agent">GitHub</a>
            <span style="color: #D8C5B2; margin: 0 12px;">·</span>
            Human review always recommended
        </p>
    </div>
    """)

    btn.click(
        review_code, [code, sec, comp, logic, perf, ctx], [summ, det], api_name="review"
    )

if __name__ == "__main__":
    demo.launch()
