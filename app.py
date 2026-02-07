"""
Code Review Agent - Multi-pass AI code review with structured findings
Risk Propagation & Blast Radius + Decision Accountability (V1+V2 ready)
"""

import json
import os
import re
import uuid
from datetime import datetime, timezone
import gradio as gr
import anthropic
import httpx

# Strip whitespace from API key (common issue with copy/paste in HF secrets)
ANTHROPIC_API_KEY = (os.getenv("ANTHROPIC_API_KEY") or "").strip()
MODEL = "claude-sonnet-4-20250514"
SCHEMA_VERSION = "1.0"
TOOL_VERSION = "0.2.0"

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
        
        # Verdict copy - human-readable, calm
        verdict_copy = {
            "BLOCK": {
                "headline": "Unsafe to merge or deploy",
                "subtext": "This code contains high-risk patterns that are commonly exploited.",
                "confidence_text": "High confidence",
                "css_class": "verdict-block",
                "dot_color": "#dc3545"
            },
            "REVIEW_REQUIRED": {
                "headline": "Human review recommended", 
                "subtext": "Some patterns could become risky depending on how this code is used.",
                "confidence_text": "Medium-High confidence",
                "css_class": "verdict-review",
                "dot_color": "#CD8F7A"
            },
            "PASS": {
                "headline": "No issues found",
                "subtext": "This code follows safe patterns based on the signals we checked.",
                "confidence_text": "High confidence",
                "css_class": "verdict-pass",
                "dot_color": "#28a745"
            }
        }
        
        vc = verdict_copy.get(verdict, verdict_copy["PASS"])
        
        # Luxury summary card
        summary = f"""
<div style="padding: 24px; background: linear-gradient(135deg, #FAF8F4 0%, #E7DCCE 100%); border-left: 4px solid {vc['dot_color']}; border-radius: 12px; margin-bottom: 16px;">
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
        <span style="width: 12px; height: 12px; background: {vc['dot_color']}; border-radius: 50%;"></span>
        <span style="font-family: 'Inter', sans-serif; font-weight: 600; font-size: 0.85em; color: #2A2926; text-transform: uppercase; letter-spacing: 0.05em;">
            {verdict.replace('_', ' ')}
        </span>
    </div>
    <h2 style="font-family: 'Playfair Display', Georgia, serif; font-size: 1.5em; color: #2A2926; margin: 0 0 8px 0; font-weight: 500;">
        {vc['headline']}
    </h2>
    <p style="font-family: 'Inter', sans-serif; color: #6B6560; font-size: 0.95em; margin: 0 0 16px 0; line-height: 1.5;">
        {vc['subtext']}
    </p>
    <div style="display: flex; gap: 16px; flex-wrap: wrap; font-size: 0.85em; color: #6B6560;">
        <span style="background: rgba(220, 204, 179, 0.7); padding: 4px 12px; border-radius: 999px;">{vc['confidence_text']}</span>
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
    /* Luxury Design System - Warm Ivory Base */
    .gradio-container {
        background: #FAF8F4 !important;
        font-family: 'Inter', sans-serif !important;
    }
    
    /* Typography - Headings */
    h1, h2, h3 {
        font-family: 'Playfair Display', Georgia, serif !important;
        color: #2A2926 !important;
        letter-spacing: -0.01em !important;
        font-weight: 500 !important;
    }
    
    /* Body text */
    p, span, label, .prose {
        color: #1B1A18 !important;
        line-height: 1.6 !important;
    }
    
    /* Cards and panels */
    .panel, .block, .form {
        background: #E7DCCE !important;
        border: none !important;
        border-radius: 12px !important;
    }
    
    /* Code blocks - editorial feel */
    pre, code, .code-block {
        background: rgba(216, 197, 178, 0.5) !important;
        border: 1px solid #E7DCCE !important;
        border-radius: 8px !important;
    }
    
    /* Primary button - Terracotta Rose */
    .primary {
        background: #CD8F7A !important;
        color: #FAF8F4 !important;
        border: none !important;
        border-radius: 10px !important;
        font-weight: 500 !important;
    }
    .primary:hover {
        background: #B87D6A !important;
    }
    
    /* Secondary button */
    .secondary {
        background: transparent !important;
        color: #2A2926 !important;
        border: 1px solid #A89F91 !important;
        border-radius: 10px !important;
    }
    
    /* Verdict cards */
    .verdict-pass {
        background: linear-gradient(135deg, #f0fff4 0%, #E7DCCE 100%) !important;
        border-left: 4px solid #28a745 !important;
    }
    .verdict-review {
        background: linear-gradient(135deg, #fffde6 0%, #E7DCCE 100%) !important;
        border-left: 4px solid #CD8F7A !important;
    }
    .verdict-block {
        background: linear-gradient(135deg, #fff5f5 0%, #E7DCCE 100%) !important;
        border-left: 4px solid #dc3545 !important;
    }
    
    /* Severity indicators - subtle left borders */
    .severity-critical { border-left: 3px solid #CD8F7A !important; }
    .severity-high { border-left: 3px solid #A89F91 !important; }
    .severity-medium { border-left: 3px solid #D8C5B2 !important; }
    
    /* Pills */
    .pill {
        background: rgba(220, 204, 179, 0.7) !important;
        color: #2A2926 !important;
        border-radius: 999px !important;
        padding: 4px 12px !important;
        font-size: 0.85em !important;
    }
    
    /* Subtle details */
    details summary {
        color: #2A2926 !important;
        cursor: pointer !important;
        padding: 8px 0 !important;
    }
    details summary:hover {
        color: #CD8F7A !important;
    }
    
    /* Input fields */
    textarea, input[type="text"] {
        background: #FAF8F4 !important;
        border: 1px solid #D8C5B2 !important;
        border-radius: 8px !important;
    }
    
    /* Checkboxes */
    input[type="checkbox"] {
        accent-color: #CD8F7A !important;
    }
    
    /* Mode selector */
    .mode-selector {
        display: flex;
        gap: 8px;
        margin-bottom: 16px;
    }
    .mode-btn {
        padding: 6px 16px;
        border-radius: 20px;
        font-size: 0.85em;
        cursor: pointer;
        transition: all 0.2s;
    }
    .mode-btn.active {
        background: #CD8F7A;
        color: #FAF8F4;
    }
    """
) as demo:
    # Header - Editorial style
    gr.HTML("""
    <div style="text-align: center; padding: 24px 0 16px 0; border-bottom: 1px solid #E7DCCE; margin-bottom: 24px;">
        <h1 style="font-family: 'Playfair Display', Georgia, serif; font-size: 2.2em; font-weight: 500; color: #2A2926; margin: 0; letter-spacing: -0.02em;">
            Code Review Agent
        </h1>
        <p style="font-family: 'Inter', sans-serif; color: #6B6560; font-size: 1em; margin-top: 8px;">
            Judgment-aware security analysis for AI-enabled systems
        </p>
    </div>
    """)

    with gr.Row():
        # Left column - Input
        with gr.Column(scale=1):
            gr.HTML("<h3 style='font-family: Playfair Display, serif; margin-bottom: 12px;'>Code to Review</h3>")
            code = gr.Code(label="", language="python", lines=14, show_label=False)
            ctx = gr.Textbox(label="Filename (optional)", placeholder="e.g., app.py", lines=1)
            
            gr.HTML("<p style='font-size: 0.9em; color: #6B6560; margin: 16px 0 8px 0;'>Analysis categories</p>")
            with gr.Row():
                sec = gr.Checkbox(label="Security", value=True)
                comp = gr.Checkbox(label="Compliance", value=True)
            with gr.Row():
                logic = gr.Checkbox(label="Logic", value=False)
                perf = gr.Checkbox(label="Performance", value=False)
            
            btn = gr.Button("Review Code", variant="primary", size="lg")
            
            # Mode selector
            mode = gr.Radio(
                choices=["Beginner", "Intermediate", "Advanced"],
                value="Intermediate",
                label="Detail level",
                info="Beginner: Plain language | Intermediate: Technical context | Advanced: Full audit"
            )
        
        # Right column - Results
        with gr.Column(scale=1):
            gr.HTML("<h3 style='font-family: Playfair Display, serif; margin-bottom: 12px;'>Analysis Results</h3>")
            summ = gr.HTML(value="""
            <div style="padding: 32px; background: #E7DCCE; border-radius: 12px; text-align: center;">
                <p style="color: #6B6560; font-size: 0.95em; margin: 0;">
                    Paste code and click <strong>Review Code</strong> to begin analysis
                </p>
            </div>
            """)
            
            with gr.Tabs():
                with gr.Tab("Overview"):
                    det = gr.Markdown()
                with gr.Tab("Fixes"):
                    fixes = gr.Markdown(value="*Suggested fixes will appear here after review*")
                with gr.Tab("Advanced"):
                    advanced = gr.Markdown(value="*Decision records and audit data will appear here*")

    # Footer
    gr.HTML("""
    <div style="text-align: center; padding: 24px 0; margin-top: 24px; border-top: 1px solid #E7DCCE;">
        <p style="font-size: 0.85em; color: #6B6560; margin: 0;">
            <a href="https://github.com/adarian-dewberry/code-review-agent" style="color: #CD8F7A; text-decoration: none;">GitHub</a>
            &nbsp;·&nbsp;
            Policy v1 &nbsp;·&nbsp; Schema v1.0
        </p>
        <p style="font-size: 0.75em; color: #A89F91; margin-top: 8px;">
            This tool provides heuristic analysis. Human review is always recommended.
        </p>
    </div>
    """)

    btn.click(
        review_code, [code, sec, comp, logic, perf, ctx], [summ, det], api_name="review"
    )

if __name__ == "__main__":
    demo.launch()
