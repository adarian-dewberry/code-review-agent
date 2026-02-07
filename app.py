"""
Code Review Agent - HuggingFace Space
Multi-pass AI code review for security, compliance, and reliability
"""

import gradio as gr
import anthropic
import os
from typing import Tuple, Optional
import re

# Initialize Anthropic client
anthropic_client = None

def get_client():
    global anthropic_client
    if anthropic_client is None:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if api_key:
            anthropic_client = anthropic.Anthropic(api_key=api_key)
    return anthropic_client

MODEL = "claude-sonnet-4-20250514"

# Embedded prompts
PROMPTS = {
    "security": """# Security Code Review

You are a senior security engineer conducting a thorough code review. Analyze the provided code for security vulnerabilities.

## Focus Areas
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Prompt Injection (for LLM-based code)
- Cross-Site Scripting (XSS) (CWE-79)
- Insecure Deserialization (CWE-502)
- Hardcoded Credentials (CWE-798)
- Path Traversal (CWE-22)
- Weak Cryptography (CWE-327)
- Missing Authentication/Authorization
- Data Exposure/Leaks

## Output Format
For each issue found, provide:
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Line**: Where the issue occurs
- **Issue**: Brief description
- **Risk**: What could happen if exploited
- **Fix**: Recommended remediation with code example

If no issues found, state "No security issues detected."
""",

    "compliance": """# Compliance Code Review

You are a compliance auditor reviewing code for regulatory requirements. Analyze the provided code for compliance gaps.

## Focus Areas
- GDPR: Data minimization, consent, right to erasure, audit trails
- CCPA: Consumer rights, data disclosure, opt-out mechanisms
- EU AI Act: Transparency, explainability, human oversight requirements
- SOC 2: Access controls, encryption, logging
- HIPAA: PHI handling, access controls, audit trails

## Output Format
For each issue found, provide:
- **Regulation**: Which regulation is affected
- **Requirement**: Specific requirement being violated
- **Issue**: What's missing or incorrect
- **Risk**: Compliance/legal risk
- **Remediation**: How to fix

If no compliance issues found, state "No compliance gaps detected."
""",

    "logic": """# Logic & Error Handling Review

You are a senior developer reviewing code for logic errors and robustness. Analyze the provided code for potential bugs.

## Focus Areas
- Null/None pointer errors
- Off-by-one errors
- Race conditions
- Unhandled exceptions
- Edge cases not covered
- Incorrect boolean logic
- Resource leaks (files, connections)
- Infinite loops
- Dead code

## Output Format
For each issue found, provide:
- **Severity**: HIGH / MEDIUM / LOW
- **Line**: Where the issue occurs
- **Issue**: Description of the logic error
- **Impact**: What could go wrong
- **Fix**: Corrected code

If no logic issues found, state "No logic errors detected."
""",

    "performance": """# Performance Code Review

You are a performance engineer reviewing code for efficiency issues. Analyze the provided code for performance problems.

## Focus Areas
- N+1 query problems
- Unnecessary loops/iterations
- Memory leaks
- Blocking I/O in async contexts
- Missing caching opportunities
- Inefficient data structures
- Repeated expensive operations
- Large object allocations in hot paths

## Output Format
For each issue found, provide:
- **Severity**: HIGH / MEDIUM / LOW
- **Line**: Where the issue occurs
- **Issue**: Description of the performance problem
- **Impact**: Performance implications
- **Optimization**: Improved code

If no performance issues found, state "No performance issues detected."
"""
}


def review_code(
    code: str,
    review_security: bool,
    review_compliance: bool,
    review_logic: bool,
    review_performance: bool,
    file_context: Optional[str] = None
) -> Tuple[str, str]:
    """Run code review based on selected categories."""
    
    if not code.strip():
        return "❌ **Error:** Please paste code to review", ""
    
    if not any([review_security, review_compliance, review_logic, review_performance]):
        return "❌ **Error:** Select at least one review category", ""
    
    client = get_client()
    if client is None:
        error_html = """
        <div style="padding: 20px; border-left: 5px solid orange; background: #fff8e1;">
            <h3>⚠️ API Key Not Configured</h3>
            <p>The ANTHROPIC_API_KEY secret is not set.</p>
            <p>This is a demo showing the interface. To enable full functionality:</p>
            <ol>
                <li>Fork this Space</li>
                <li>Add your ANTHROPIC_API_KEY in Settings → Secrets</li>
            </ol>
        </div>
        """
        demo_result = """# Demo Mode

The Code Review Agent interface is working! To get actual AI-powered reviews:

1. **Fork this Space** to your own HuggingFace account
2. **Add your Anthropic API key** in Settings → Secrets
3. **Restart the Space**

## What the full review provides:

- **Security**: SQL injection, prompt injection, XSS, auth bypass detection
- **Compliance**: GDPR, CCPA, EU AI Act, SOC 2 gap analysis
- **Logic**: Null pointers, edge cases, error handling issues
- **Performance**: N+1 queries, memory leaks, optimization opportunities
"""
        return error_html, demo_result
    
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
        for category in categories:
            prompt = PROMPTS[category]
            context = f"File: {file_context}\n\n" if file_context else ""
            full_prompt = f"{prompt}\n\n{context}# Code to Review\n```python\n{code}\n```"
            
            response = client.messages.create(
                model=MODEL,
                max_tokens=4000,
                temperature=0.0,
                messages=[{"role": "user", "content": full_prompt}]
            )
            
            review_text = response.content[0].text
            
            critical_count = len(re.findall(r'\*\*Severity\*\*:\s*CRITICAL', review_text, re.IGNORECASE))
            high_count = len(re.findall(r'\*\*Severity\*\*:\s*HIGH', review_text, re.IGNORECASE))
            
            all_critical += critical_count
            all_high += high_count
            
            results.append({
                "category": category,
                "text": review_text,
                "critical": critical_count,
                "high": high_count
            })
        
        # Generate summary
        if all_critical > 0:
            recommendation = "🚫 DO NOT MERGE"
            color = "#dc3545"
        elif all_high > 3:
            recommendation = "⚠️ MERGE WITH CAUTION"
            color = "#fd7e14"
        elif all_high > 0:
            recommendation = "⚡ APPROVED WITH FIXES"
            color = "#ffc107"
        else:
            recommendation = "✅ APPROVED"
            color = "#28a745"
        
        summary_html = f"""
        <div style="padding: 20px; border-left: 5px solid {color}; background: #f8f9fa; margin-bottom: 20px; border-radius: 4px;">
            <h2 style="margin-top: 0; color: {color};">Review Summary</h2>
            <p style="font-size: 24px; font-weight: bold; margin: 10px 0;">{recommendation}</p>
            <ul style="margin: 0; padding-left: 20px;">
                <li><strong>Critical Issues:</strong> {all_critical}</li>
                <li><strong>High Issues:</strong> {all_high}</li>
                <li><strong>Categories Reviewed:</strong> {', '.join(c.title() for c in categories)}</li>
            </ul>
        </div>
        """
        
        detailed_md = "# Code Review Report\n\n"
        detailed_md += f"**Recommendation:** {recommendation}\n\n---\n\n"
        
        for result in results:
            emoji = {"security": "🔒", "compliance": "📋", "logic": "🧠", "performance": "⚡"}.get(result['category'], "📝")
            detailed_md += f"## {emoji} {result['category'].title()} Review\n\n"
            if result['critical'] > 0 or result['high'] > 0:
                detailed_md += f"**Issues Found:** {result['critical']} Critical, {result['high']} High\n\n"
            detailed_md += result['text'] + "\n\n---\n\n"
        
        return summary_html, detailed_md
    
    except Exception as e:
        error_html = f"""
        <div style="padding: 20px; border-left: 5px solid #dc3545; background: #fff5f5; border-radius: 4px;">
            <h3>❌ Review Failed</h3>
            <p><strong>Error:</strong> {str(e)}</p>
        </div>
        """
        return error_html, f"**Error details:**\n```\n{str(e)}\n```"


def create_interface():
    """Create Gradio web interface."""
    
    with gr.Blocks(title="Code Review Agent", theme=gr.themes.Soft()) as demo:
        gr.Markdown("""
        # 🛡️ Code Review Agent
        
        **Multi-pass AI code review for security, compliance, and reliability**
        
        Paste your code below and select review categories. The agent uses Claude Sonnet 4 to find vulnerabilities.
        
        [GitHub](https://github.com/adarian-dewberry/code-review-agent) • Built by AD Dewberry
        """)
        
        with gr.Row():
            with gr.Column(scale=1):
                code_input = gr.Code(
                    label="Code to Review",
                    language="python",
                    lines=18,
                    placeholder="Paste your Python code here..."
                )
                
                file_context = gr.Textbox(
                    label="File Context (optional)",
                    placeholder="e.g., app.py, user_auth.py",
                    lines=1
                )
                
                gr.Markdown("### Review Categories")
                with gr.Row():
                    review_security = gr.Checkbox(label="🔒 Security", value=True)
                    review_compliance = gr.Checkbox(label="📋 Compliance", value=True)
                with gr.Row():
                    review_logic = gr.Checkbox(label="🧠 Logic", value=False)
                    review_performance = gr.Checkbox(label="⚡ Performance", value=False)
                
                review_btn = gr.Button("🔍 Review Code", variant="primary", size="lg")
                
                gr.Markdown("""
                ---
                **🔒 Security**: SQL/prompt injection, XSS, secrets  
                **📋 Compliance**: GDPR, CCPA, EU AI Act, SOC 2  
                **🧠 Logic**: Null pointers, edge cases, errors  
                **⚡ Performance**: N+1 queries, memory leaks
                """)
            
            with gr.Column(scale=1):
                summary_output = gr.HTML(label="Summary")
                detailed_output = gr.Markdown(label="Detailed Findings")
        
        gr.Markdown("---\n### 📝 Examples (Click to Load)")
        
        gr.Examples(
            examples=[
                ['''def get_user(username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return db.execute(query)''', "user_auth.py", True, False, False, False],
                ['''def review_contract(text):
    prompt = f"Review this: {text}"
    return llm.generate(prompt)''', "contract.py", True, True, False, False],
                ['''def get_email(customer_id):
    customer = Customer.objects.get(id=customer_id)
    return customer.email''', "customer.py", False, True, False, False],
            ],
            inputs=[code_input, file_context, review_security, review_compliance, review_logic, review_performance],
        )
        
        review_btn.click(
            fn=review_code,
            inputs=[code_input, review_security, review_compliance, review_logic, review_performance, file_context],
            outputs=[summary_output, detailed_output]
        )
    
    return demo


if __name__ == "__main__":
    demo = create_interface()
    demo.launch()
