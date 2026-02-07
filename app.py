"""
Code Review Agent - Multi-pass AI code review
"""
import os
import re
import gradio as gr
import anthropic

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
MODEL = "claude-3-5-sonnet-20241022"

PROMPTS = {
    "security": """You are a security engineer. Review for SQL injection, prompt injection, data leaks, auth bypass.
Format: ## CRITICAL or ## HIGH with issue, risk, and fix.""",
    "compliance": """You are a GRC engineer. Review for GDPR/CCPA violations, missing audit trails, PII exposure.
Format: ## CRITICAL or ## HIGH with issue, regulation, and fix.""",
    "logic": """You are a software engineer. Review for unhandled exceptions, null pointers, edge cases.
Format: ## CRITICAL or ## HIGH with issue, failure scenario, and fix.""",
    "performance": """You are a performance engineer. Review for N+1 queries, memory leaks, inefficient algorithms.
Format: ## CRITICAL or ## HIGH with issue, impact, and fix."""
}

def review_code(code, sec, comp, logic, perf, ctx=""):
    """Run multi-pass code review."""
    if not code or not code.strip():
        return "<div style='padding:20px;border-left:5px solid orange;background:#fff9e6'><h3>⚠️ No Code</h3><p>Paste code above.</p></div>", ""
    
    if not any([sec, comp, logic, perf]):
        return "<div style='padding:20px;border-left:5px solid orange;background:#fff9e6'><h3>⚠️ No Categories</h3><p>Select at least one.</p></div>", ""
    
    if not ANTHROPIC_API_KEY:
        return "<div style='padding:20px;border-left:5px solid red;background:#fff5f5'><h3>❌ API Key Missing</h3><p>Add ANTHROPIC_API_KEY in Settings → Secrets</p></div>", ""
    
    cats = []
    if sec: cats.append("security")
    if comp: cats.append("compliance")
    if logic: cats.append("logic")
    if perf: cats.append("performance")
    
    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        results = []
        total_crit, total_high = 0, 0
        
        for cat in cats:
            prompt = f"{PROMPTS[cat]}\n\n# Code\n```python\n{code}\n```"
            resp = client.messages.create(
                model=MODEL,
                max_tokens=4000,
                temperature=0.0,
                messages=[{"role": "user", "content": prompt}]
            )
            text = resp.content[0].text
            crit = len(re.findall(r'^## CRITICAL', text, re.MULTILINE))
            high = len(re.findall(r'^## HIGH', text, re.MULTILINE))
            total_crit += crit
            total_high += high
            results.append({"cat": cat, "text": text, "crit": crit, "high": high})
        
        if total_crit > 0:
            rec, color, bg = "🚫 DO NOT MERGE", "#dc3545", "#fff5f5"
        elif total_high > 3:
            rec, color, bg = "⚠️ CAUTION", "#fd7e14", "#fff9e6"
        else:
            rec, color, bg = "✅ APPROVED", "#28a745", "#f0fff4"
        
        summary = f"<div style='padding:20px;border-left:5px solid {color};background:{bg};border-radius:5px'><h2 style='color:{color}'>{rec}</h2><p>Critical: {total_crit} | High: {total_high}</p></div>"
        
        details = f"# Review Report\n\n**{rec}**\n\n---\n\n"
        for r in results:
            details += f"## {r['cat'].title()}\n\n{r['text']}\n\n---\n\n"
        
        return summary, details
    
    except anthropic.AuthenticationError as e:
        return f"<div style='padding:20px;border-left:5px solid red;background:#fff5f5'><h3>❌ Authentication Error</h3><p>Invalid API key. Check ANTHROPIC_API_KEY in Settings → Secrets.</p><p>Details: {str(e)}</p></div>", ""
    
    except anthropic.NotFoundError as e:
        return f"<div style='padding:20px;border-left:5px solid red;background:#fff5f5'><h3>❌ Model Not Found</h3><p>Model {MODEL} not available. Details: {str(e)}</p></div>", ""
    
    except anthropic.APIConnectionError as e:
        return f"<div style='padding:20px;border-left:5px solid red;background:#fff5f5'><h3>❌ Connection Error</h3><p>Could not connect to Anthropic API. Details: {str(e)}</p></div>", ""
    
    except Exception as e:
        # Don't expose traceback in production
        return f"<div style='padding:20px;border-left:5px solid red;background:#fff5f5'><h3>❌ Error</h3><p>An unexpected error occurred. Please try again.</p><p><small>Error type: {type(e).__name__}</small></p></div>", ""

with gr.Blocks(title="Code Review Agent") as demo:
    gr.Markdown("# 🛡️ Code Review Agent\n\nMulti-pass AI code review. [GitHub](https://github.com/adarian-dewberry/code-review-agent)")
    
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
    
    btn.click(review_code, [code, sec, comp, logic, perf, ctx], [summ, det], api_name="review")

if __name__ == "__main__":
    demo.launch()
