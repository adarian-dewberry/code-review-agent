"""
Code Review Agent - Multi-pass AI code review with structured findings
"""

import json
import os
import re
import gradio as gr
import anthropic
import httpx

# Strip whitespace from API key (common issue with copy/paste in HF secrets)
ANTHROPIC_API_KEY = (os.getenv("ANTHROPIC_API_KEY") or "").strip()
MODEL = "claude-sonnet-4-20250514"

# Structured prompt with JSON schema for consistent output
SYSTEM_PROMPT = """You are an expert code reviewer. Analyze code and return findings as JSON.

<output_schema>
{
  "findings": [
    {
      "id": "unique-id",
      "title": "Brief issue title",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 0.0-1.0,
      "tags": ["security", "compliance", "logic", "performance"],
      "line": 123,
      "snippet": "3 lines of code around the issue",
      "description": "What the issue is",
      "impact": "Why it matters",
      "recommendation": "Specific fix with code example"
    }
  ]
}
</output_schema>

<rules>
1. DEDUPE: One finding per root cause. Use tags array for cross-cutting concerns.
2. COMPLIANCE: Say "Potential exposure → implement [control]" NOT "violated [regulation]"
3. EVIDENCE: Always include line number and 3-line code snippet
4. CONFIDENCE: Rate 0.0-1.0 based on certainty (context-dependent issues get lower scores)
5. FIXES: Provide LLM-specific fixes (use XML delimiters, schema validation, etc.)
</rules>"""

CATEGORY_PROMPTS = {
    "security": """Focus on: SQL injection, command injection, XSS, SSRF, path traversal, 
auth bypass, secrets exposure, insecure deserialization, prompt injection.""",
    "compliance": """Focus on: PII exposure, missing consent, audit trail gaps, data retention,
encryption at rest/transit. Suggest CONTROLS not violations.""",
    "logic": """Focus on: Null/undefined handling, race conditions, off-by-one errors,
unhandled exceptions, infinite loops, resource leaks.""",
    "performance": """Focus on: N+1 queries, unbounded loops, memory leaks, blocking I/O,
missing indexes, inefficient algorithms, cache misses.""",
}


def parse_findings(text):
    """Extract JSON findings from LLM response."""
    # Try to find JSON in the response
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
        
        # Decision logic: 0.8+ confidence threshold for BLOCK
        if any(f.get("severity") == "CRITICAL" and f.get("confidence", 0) >= 0.8 for f in findings):
            rec, color, bg = "🚫 BLOCK", "#dc3545", "#fff5f5"
        elif len(block_findings) > 0:
            rec, color, bg = "⚠️ REVIEW REQUIRED", "#fd7e14", "#fff9e6"
        elif len(warn_findings) > 0:
            rec, color, bg = "⚡ CAUTION", "#ffc107", "#fffde6"
        else:
            rec, color, bg = "✅ APPROVED", "#28a745", "#f0fff4"

        # Summary HTML
        summary = f"""<div style='padding:20px;border-left:5px solid {color};background:{bg};border-radius:5px'>
<h2 style='color:{color};margin:0'>{rec}</h2>
<p style='margin:10px 0 0 0'>High-confidence issues: {len(block_findings)} | Needs review: {len(warn_findings)} | Total: {len(findings)}</p>
</div>"""

        # Build detailed markdown report
        details = f"# Code Review Report\n\n**Verdict: {rec}**\n\n---\n\n"
        
        if not findings:
            details += "No issues found. ✨\n"
        else:
            for f in sorted(findings, key=lambda x: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("severity", "LOW"), 4), -x.get("confidence", 0))):
                sev = f.get("severity", "UNKNOWN")
                conf = f.get("confidence", 0)
                conf_pct = int(conf * 100)
                
                # Severity badge colors
                sev_colors = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
                badge = sev_colors.get(sev, "⚪")
                
                details += f"### {badge} {f.get('title', 'Issue')} [{sev}] ({conf_pct}% confidence)\n\n"
                
                if f.get("line"):
                    details += f"**Line {f.get('line')}**\n"
                
                if f.get("snippet"):
                    details += f"```python\n{f.get('snippet')}\n```\n\n"
                
                if f.get("tags"):
                    details += f"**Tags:** {', '.join(f.get('tags', []))}\n\n"
                
                details += f"**Issue:** {f.get('description', 'N/A')}\n\n"
                details += f"**Impact:** {f.get('impact', 'N/A')}\n\n"
                details += f"**Recommendation:**\n{f.get('recommendation', 'N/A')}\n\n"
                details += "---\n\n"

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


with gr.Blocks(title="Code Review Agent") as demo:
    gr.Markdown(
        "# 🛡️ Code Review Agent\n\nMulti-pass AI code review. [GitHub](https://github.com/adarian-dewberry/code-review-agent)"
    )

    with gr.Row():
        with gr.Column():
            code = gr.Code(label="Code", language="python", lines=12)
            ctx = gr.Textbox(label="File (optional)", lines=1)
            with gr.Row():
                sec = gr.Checkbox(label="🔒 Security", value=True)
                comp = gr.Checkbox(label="📋 Compliance", value=True)
            with gr.Row():
                logic = gr.Checkbox(label="🧠 Logic", value=False)
                perf = gr.Checkbox(label="⚡ Performance", value=False)
            btn = gr.Button("🔍 Review", variant="primary")
        with gr.Column():
            summ = gr.HTML(value="<p style='color:#666'>Results appear here</p>")
            det = gr.Markdown()

    btn.click(
        review_code, [code, sec, comp, logic, perf, ctx], [summ, det], api_name="review"
    )

if __name__ == "__main__":
    demo.launch()
