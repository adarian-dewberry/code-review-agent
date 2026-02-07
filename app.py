"""Hugging Face Spaces entry point for Code Review Agent.

This file launches the Streamlit demo.
"""

import streamlit as st

st.set_page_config(
    page_title="Code Review Agent",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Code Review Agent")
st.write("Multi-pass AI code review for security, compliance, and reliability")

# Temporarily show that HF Space is running
st.success("🚀 Hugging Face Space is running correctly!")

st.write("---")

# Load the real demo from demo/streamlit_app.py
try:
    # Import and run the actual demo
    import sys
    from pathlib import Path
    
    # Add demo to path
    sys.path.insert(0, str(Path(__file__).parent / "demo"))
    
    # Import main function from demo app
    from streamlit_app import main
    
    main()
except ImportError as e:
    st.warning(f"⚠️ Demo app not fully loaded: {e}")
    st.info("Check that demo/streamlit_app.py exists and has a main() function")
