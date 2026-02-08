"""Streamlit demo for Code Review Agent.

Run:
  streamlit run demo/streamlit_app.py
"""

from __future__ import annotations

import os
import textwrap

import streamlit as st

from code_review_agent.agent import CodeReviewAgent
from code_review_agent.config import Config


SAMPLE_CODE = textwrap.dedent(
    """
    import sqlite3

    def get_vendor(vendor_name: str):
        conn = sqlite3.connect("db.sqlite")
        cursor = conn.cursor()
        query = f"SELECT * FROM vendors WHERE name = '{vendor_name}'"  # SQL injection
        return cursor.execute(query).fetchall()
    """
).strip()

SAMPLE_OUTPUT = textwrap.dedent(
    """
    # Code Review Report

    ## Summary
    - Recommendation: DO_NOT_MERGE
    - Critical Issues: 1

    ## Security Review
    ### CRITICAL
    - SQL injection vulnerability (line 6) | OWASP A03:2025 - Injection, CWE-89
      Risk: Attacker can extract entire database by manipulating vendor_name parameter
      Risk Level: CRITICAL
      Fix: Use parameterized queries and avoid string interpolation
    """
).strip()


st.set_page_config(page_title="Code Review Agent Demo", page_icon="🛡️", layout="wide")

st.title("🛡️ Code Review Agent – Live Demo")
st.caption("Shift-left security for AI-generated code. Catch risks before production.")

with st.sidebar:
    st.header("Configuration")
    api_key = st.text_input("ANTHROPIC_API_KEY", type="password")
    use_demo = st.checkbox("Demo mode (no API calls)", value=True)
    st.markdown("---")
    st.markdown(
        "**Tip**: Use demo mode to explore output without sending code to an LLM."
    )

st.subheader("Paste AI-generated code")
code_input = st.text_area("Code", value=SAMPLE_CODE, height=280)

col1, col2 = st.columns([1, 3])
with col1:
    run_review = st.button("Run Review", type="primary")
with col2:
    st.markdown(
        "**Privacy Notice:** Your code will be sent to Anthropic's Claude API when demo mode is off."
    )

if run_review:
    if use_demo:
        st.info("Running in demo mode. No external API calls were made.")
        st.code(SAMPLE_OUTPUT, language="markdown")
    else:
        if not api_key:
            st.error("Please provide ANTHROPIC_API_KEY or enable demo mode.")
        else:
            os.environ["ANTHROPIC_API_KEY"] = api_key
            with st.spinner("Reviewing code..."):
                config = Config.load()
                agent = CodeReviewAgent(config)
                result = agent.review(code_input, file_path=None)
            st.code(result.to_markdown(), language="markdown")

st.markdown("---")

st.subheader("What this demonstrates")
st.markdown(
    """
- **Plug-and-play security** for rapid prototyping
- **OWASP + CWE mapping** for audit-ready findings
- **Risk levels** to prioritize fixes
- **Shift-left workflows** that reduce remediation cost
    """
)
