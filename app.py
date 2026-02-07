"""
Code Review Agent
Multi-pass AI code review for security, compliance, and reliability
"""

import os
import re
from typing import Tuple

import anthropic
import gradio as gr

# Check for API key
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
if not ANTHROPIC_API_KEY:
    print("WARNING: ANTHROPIC_API_KEY not found in environment")
    ANTHROPIC_API_KEY = None

MODEL = "claude-sonnet-4-20250514"

# Embedded prompts (inline to avoid file loading issues)
SECURITY_PROMPT = """You are a senior security engineer reviewing code for security vulnerabilities.

Review the code below for security issues and format your response EXACTLY like this:

## CRITICAL
- [Issue description] (line X)
  Risk: [Impact details]
  Fix: ```python
  [corrected code]
```

## HIGH
- [Issue description] (line Y)
  Risk: [Impact details]
  Fix: ```python
  [corrected code]
```

Focus on:
- SQL injection
- Prompt injection (user input into LLM prompts)
- Data leaks in logs/errors
- Missing authentication checks
- Command injection

Only include severity sections where you found issues."""

COMPLIANCE_PROMPT = """You are a GRC engineer reviewing code for GDPR, CCPA, and EU AI Act compliance.

Review the code below and format your response EXACTLY like this:

## CRITICAL
- [Issue description] (line X)
  Regulation: GDPR Art. X
  Risk: [Compliance impact]
  Fix: ```python
  [corrected code]
```

## HIGH
- [Issue description] (line Y)
  Regulation: CCPA Section Y
  Risk: [Compliance impact]
  Fix: ```python
  [corrected code]
```

Focus on:
- PII processed without audit trail
- Missing consent tracking
- No data retention controls
- High-risk AI actions without human approval
- Missing data minimization

Only include severity sections where you found issues."""

LOGIC_PROMPT = """You are a senior software engineer reviewing code for logical correctness.

Review the code below and format your response EXACTLY like this:

## CRITICAL
- [Issue description] (line X)
  Failure scenario: [When this breaks]
  Fix: ```python
  [corrected code]
```

## HIGH
- [Issue description] (line Y)
  Failure scenario: [When this breaks]
  Fix: ```python
  [corrected code]
```

Focus on:
- Unhandled exceptions
- Null pointer dereferences
- Off-by-one errors
- Race conditions
- Missing edge case handling

Only include severity sections where you found issues."""

PERFORMANCE_PROMPT = """You are a performance engineer reviewing code for scalability issues.

Review the code below and format your response EXACTLY like this:

## CRITICAL
- [Issue description] (line X)
  Impact: [Performance impact with scale]
  Fix: ```python
  [corrected code]
```

## HIGH
- [Issue description] (line Y)
  Impact: [Performance impact]
  Fix: ```python
  [corrected code]
```

Focus on:
- N+1 query problems
- Missing pagination
- Inefficient algorithms
- Memory leaks
- Blocking operations in hot paths

Only include severity sections where you found issues."""

PROMPTS = {
    "security": SECURITY_PROMPT,
    "compliance": COMPLIANCE_PROMPT,
    "logic": LOGIC_PROMPT,
    "performance": PERFORMANCE_PROMPT,
}


def review_code(
    code: str,
    review_security: bool,
    review_compliance: bool,
    review_logic: bool,
    review_performance: bool,
    file_context: str = "",
) -> Tuple[str, str]:
    """
    Run code review based on selected categories.

    Returns:
        (summary_html, detailed_markdown)
    """

    # Validation
    if not code or not code.strip():
        return (
            """
        <div style="padding: 20px; border-left: 5px solid orange; background: #fff9e6;">
            <h3>⚠️ No Code Provided</h3>
            <p>Please paste your Python code in the editor above.</p>
        </div>
        """,
            "",
        )

    if not any([review_security, review_compliance, review_logic, review_performance]):
        return (
            """
        <div style="padding: 20px; border-left: 5px solid orange; background: #fff9e6;">
            <h3>⚠️ No Categories Selected</h3>
            <p>Please select at least one review category (Security, Compliance, Logic, or Performance).</p>
        </div>
        """,
            "",
        )

    # Check API key
    if not ANTHROPIC_API_KEY:
        return (
            """
        <div style="padding: 20px; border-left: 5px solid red; background: #fff5f5;">
            <h3>❌ API Key Missing</h3>
            <p><strong>The ANTHROPIC_API_KEY secret is not configured.</strong></p>
            <p>To fix this:</p>
            <ol>
                <li>Go to Space Settings → Variables and secrets</li>
                <li>Add a new secret named: <code>ANTHROPIC_API_KEY</code></li>
                <li>Paste your Anthropic API key (starts with sk-ant-...)</li>
                <li>Save and wait for Space to rebuild</li>
            </ol>
        </div>
        """,
            "",
        )

    # Collect selected categories
    categories = []
    if review_security:
        categories.append("security")
    if review_compliance:
        categories.append("compliance")
    if review_logic:
        categories.append("logic")
    if review_performance:
        categories.append("performance")

    results = []
    all_critical = 0
    all_high = 0

    try:
        # Initialize Anthropic client
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

        for category in categories:
            # Build prompt
            prompt = PROMPTS[category]
            context = f"File: {file_context}\n\n" if file_context else ""
            full_prompt = f"{prompt}\n\n{context}# Code to Review\n```python\n{code}\n```"

            # Call Claude
            response = client.messages.create(
                model=MODEL,
                max_tokens=4000,
                temperature=0.0,
                messages=[{"role": "user", "content": full_prompt}],
            )

            review_text = response.content[0].text

            # Parse severity counts
            critical_count = len(re.findall(r"^## CRITICAL", review_text, re.MULTILINE))
            high_count = len(re.findall(r"^## HIGH", review_text, re.MULTILINE))

            all_critical += critical_count
            all_high += high_count

            results.append(
                {
                    "category": category,
                    "text": review_text,
                    "critical": critical_count,
                    "high": high_count,
                }
            )

        # Generate summary
        if all_critical > 0:
            recommendation = "🚫 DO NOT MERGE"
            color = "#dc3545"
            bg_color = "#fff5f5"
        elif all_high > 3:
            recommendation = "⚠️ MERGE WITH CAUTION"
            color = "#fd7e14"
            bg_color = "#fff9e6"
        else:
            recommendation = "✅ APPROVED"
            color = "#28a745"
            bg_color = "#f0fff4"

        summary_html = f"""
        <div style="padding: 20px; border-left: 5px solid {color}; background: {bg_color}; margin-bottom: 20px; border-radius: 5px;">
            <h2 style="margin-top: 0; color: {color};">Review Summary</h2>
            <p style="font-size: 24px; font-weight: bold; margin: 10px 0;">{recommendation}</p>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-top: 15px;">
                <div>
                    <div style="font-size: 14px; color: #666;">Critical Issues</div>
                    <div style="font-size: 32px; font-weight: bold; color: #dc3545;">{all_critical}</div>
                </div>
                <div>
                    <div style="font-size: 14px; color: #666;">High Issues</div>
                    <div style="font-size: 32px; font-weight: bold; color: #fd7e14;">{all_high}</div>
                </div>
                <div>
                    <div style="font-size: 14px; color: #666;">Categories</div>
                    <div style="font-size: 18px; font-weight: bold; color: #333;">{', '.join(c.title() for c in categories)}</div>
                </div>
            </div>
        </div>
        """

        # Build detailed markdown
        detailed_md = "# 📋 Code Review Report\n\n"
        detailed_md += f"**Recommendation:** {recommendation}\n\n"
        detailed_md += "---\n\n"

        for result in results:
            detailed_md += f"## {result['category'].title()} Review\n\n"
            detailed_md += f"**Critical:** {result['critical']} | **High:** {result['high']}\n\n"
            detailed_md += result["text"] + "\n\n"
            detailed_md += "---\n\n"

        return summary_html, detailed_md

    except anthropic.APIError as e:
        error_html = f"""
        <div style="padding: 20px; border-left: 5px solid red; background: #fff5f5;">
            <h3>❌ Anthropic API Error</h3>
            <p><strong>Error:</strong> {str(e)}</p>
            <p>This usually means:</p>
            <ul>
                <li>Invalid API key</li>
                <li>API key doesn't have access to Claude Sonnet 4</li>
                <li>Rate limit exceeded</li>
            </ul>
        </div>
        """
        return error_html, f"**Error details:**\n```\n{str(e)}\n```"

    except Exception as e:
        error_html = f"""
        <div style="padding: 20px; border-left: 5px solid red; background: #fff5f5;">
            <h3>❌ Unexpected Error</h3>
            <p><strong>Error:</strong> {str(e)}</p>
            <p>Please report this issue on GitHub with the code you were trying to review.</p>
        </div>
        """
        return error_html, f"**Error details:**\n```\n{str(e)}\n```"


# Build Gradio interface
with gr.Blocks(title="Code Review Agent", theme=gr.themes.Soft()) as demo:
    gr.Markdown(
        """
    # 🛡️ Code Review Agent

    **Multi-pass AI code review for security, compliance, and reliability**

    Paste your Python code below and select review categories. The agent analyzes your code
    using Claude Sonnet 4 and provides detailed security, compliance, logic, and performance findings.

    Built by [AD Dewberry](https://adariandewberry.ai) • [GitHub](https://github.com/adarian-dewberry/code-review-agent) • Powered by [Anthropic Claude](https://anthropic.com)
    """
    )

    with gr.Row():
        with gr.Column(scale=1):
            code_input = gr.Code(
                label="📝 Code to Review",
                language="python",
                lines=15,
                placeholder='Paste your Python code here...\n\nExample:\ndef get_user(username):\n    query = f"SELECT * FROM users WHERE name = \'{username}\'"\n    return db.execute(query)',
            )

            file_context = gr.Textbox(
                label="📄 File Context (optional)",
                placeholder="e.g., user_auth.py, payment_processor.py",
                lines=1,
            )

            gr.Markdown("### Review Categories")

            with gr.Row():
                review_security = gr.Checkbox(
                    label="🔒 Security",
                    value=True,
                    info="SQL injection, prompt injection, data leaks",
                )
                review_compliance = gr.Checkbox(
                    label="📋 Compliance",
                    value=True,
                    info="GDPR, CCPA, audit trails",
                )

            with gr.Row():
                review_logic = gr.Checkbox(
                    label="🧠 Logic",
                    value=False,
                    info="Edge cases, null pointers, error handling",
                )
                review_performance = gr.Checkbox(
                    label="⚡ Performance",
                    value=False,
                    info="N+1 queries, memory leaks, scalability",
                )

            review_btn = gr.Button("🔍 Review Code", variant="primary", size="lg")

            gr.Markdown(
                """
            <details>
            <summary><strong>ℹ️ What each category checks</strong></summary>

            - **Security:** Prompt injection, SQL injection, data leaks, authentication bypass, command injection
            - **Compliance:** GDPR violations, missing audit trails, PII exposure, consent tracking, data retention
            - **Logic:** Unhandled exceptions, null pointers, edge cases, race conditions, off-by-one errors
            - **Performance:** N+1 query problems, memory leaks, inefficient algorithms, missing pagination, blocking operations

            </details>
            """
            )

        with gr.Column(scale=1):
            summary_output = gr.HTML(
                label="Summary",
                value="<p style='color: #666; padding: 20px;'>Results will appear here after you click Review Code.</p>",
            )
            detailed_output = gr.Markdown(label="Detailed Findings", value="")

    # Examples
    gr.Markdown("---")
    gr.Markdown("## 📚 Example Code (Click to Load)")

    gr.Examples(
        examples=[
            [
                """def get_user(username):
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return db.execute(query)""",
                "user_auth.py",
                True,
                False,
                False,
                False,
            ],
            [
                """def review_contract(contract_text):
    # Prompt injection vulnerability
    prompt = f"Review this contract: {contract_text}"
    return llm.generate(prompt)""",
                "contract_reviewer.py",
                True,
                True,
                False,
                False,
            ],
            [
                """def access_customer_email(customer_id):
    # Missing audit trail (GDPR violation)
    customer = Customer.objects.get(id=customer_id)
    return customer.email""",
                "customer_service.py",
                False,
                True,
                False,
                False,
            ],
            [
                """def get_vendor_contracts(vendor_ids):
    # N+1 query problem
    results = []
    for vendor_id in vendor_ids:
        vendor = Vendor.objects.get(id=vendor_id)
        contracts = Contract.objects.filter(vendor=vendor)
        results.append((vendor, contracts))
    return results""",
                "vendor_service.py",
                False,
                False,
                False,
                True,
            ],
        ],
        inputs=[
            code_input,
            file_context,
            review_security,
            review_compliance,
            review_logic,
            review_performance,
        ],
        label="Try these examples",
    )

    # Wire up the review button
    review_btn.click(
        fn=review_code,
        inputs=[
            code_input,
            review_security,
            review_compliance,
            review_logic,
            review_performance,
            file_context,
        ],
        outputs=[summary_output, detailed_output],
    )

# Launch
if __name__ == "__main__":
    demo.launch()
