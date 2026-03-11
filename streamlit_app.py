import streamlit as st

st.set_page_config(
    page_title="Security Agent - OWASP Code Analyzer",
    page_icon="🔒",
    layout="wide",
)

st.title("Security Agent — OWASP Code Analyzer 🔒")
st.markdown(
    """
    An AI-powered **Security Engineering Agent** that uses **ReAct (Reasoning and Acting)**
    to analyze Python code for vulnerabilities based on OWASP standards.

    ### How it works

    1. **Admin Page** — Upload OWASP/security documents and train the knowledge base
    2. **Home Page** — Paste your Python code and get a structured security review

    ### The ReAct Agent

    The agent follows a multi-step reasoning loop:

    ```
    Thought  → "I should check this code for SQL injection patterns"
    Action   → analyze_code (static pattern detection)
    Observe  → "Found SQL string concatenation on line 15"
    Thought  → "Let me search OWASP standards for this vulnerability"
    Action   → search_owasp_kb (vector search on security docs)
    Observe  → "OWASP A03:2021 - Injection..."
    ...
    Answer   → Structured security review with findings + fixes
    ```

    Use the **sidebar** to navigate between pages.
    """
)
