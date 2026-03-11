import streamlit as st
from langchain.callbacks.base import BaseCallbackHandler

from config import CHROMA_DB_PATH, MAX_CODE_LENGTH
from static_analysis import analyze_code, VULNERABILITY_PATTERNS
from agent import load_security_agent

st.set_page_config(page_title="Security Agent - Code Analyzer", page_icon="🔒")

st.title("Security Agent — Code Vulnerability Analyzer 🔒")
st.markdown(
    "Paste your **Python** code below. The system runs a **deterministic static analysis** "
    "first, then the **ReAct agent** enhances results with OWASP knowledge base context."
)


def _sanitize_code_input(code: str) -> str:
    """Escape ReAct control tokens in user code to mitigate prompt injection."""
    dangerous_tokens = [
        "Thought:", "Action:", "Action Input:", "Observation:",
        "Final Answer:", "</USER_CODE>", "<USER_CODE>",
    ]
    sanitized = code
    for token in dangerous_tokens:
        sanitized = sanitized.replace(token, f"# {token}")
    return sanitized


def _parse_static_findings(code: str) -> list[dict]:
    """Run static analysis and parse findings into structured dicts."""
    import re as _re
    findings = []
    lines = code.split("\n")
    for line_num, line in enumerate(lines, 1):
        for pattern in VULNERABILITY_PATTERNS:
            if pattern.regex.search(line):
                findings.append({
                    "line": line_num,
                    "code": line.strip(),
                    "description": pattern.description,
                    "owasp": pattern.owasp_ref,
                    "severity": _classify_severity(pattern.owasp_ref),
                })
    return findings


def _classify_severity(owasp_ref: str) -> str:
    """Map OWASP category to severity level."""
    critical = ["A03:2021"]  # Injection
    high = ["A07:2021", "A08:2021", "A02:2021"]  # Auth, Integrity, Crypto
    medium = ["A05:2021"]  # Misconfiguration
    owasp_code = owasp_ref.split(" - ")[0].strip()
    if owasp_code in critical:
        return "Critical"
    elif owasp_code in high:
        return "High"
    elif owasp_code in medium:
        return "Medium"
    return "Low"


SEVERITY_COLORS = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🔵",
}


# Check if knowledge base exists
if not CHROMA_DB_PATH.exists():
    st.error(
        "Knowledge base not found. Go to the **Admin** page to upload "
        "security documents and train the system."
    )
    st.stop()

# Load agent
agent_executor = load_security_agent()
if agent_executor is None:
    st.error("Could not load the security agent. Please train the knowledge base first.")
    st.stop()


# --- Streaming Callback ---
class StreamlitReActCallback(BaseCallbackHandler):
    """Shows ReAct reasoning steps in real-time."""

    def __init__(self, container):
        self.container = container
        self.step_count = 0

    def on_agent_action(self, action, **kwargs):
        self.step_count += 1
        self.container.markdown(
            f"**Step {self.step_count}:** 🔧 Using tool `{action.tool}`"
        )

    def on_tool_end(self, output, **kwargs):
        with self.container.expander(
            f"Observation {self.step_count}", expanded=False
        ):
            st.text(str(output)[:800])


# --- Code Input ---
st.subheader("Python Code to Analyze")

code_input = st.text_area(
    "Paste your Python code here:",
    height=300,
    max_chars=MAX_CODE_LENGTH,
    placeholder=(
        "# Example: paste code with potential vulnerabilities\n"
        "import os\n"
        "password = 'admin123'\n"
        "query = 'SELECT * FROM users WHERE id=' + user_input\n"
        "os.system(command)"
    ),
)

char_count = len(code_input) if code_input else 0
st.caption(f"{char_count}/{MAX_CODE_LENGTH} characters")

# --- Analysis ---
if st.button("🔍 Analyze Security", type="primary"):
    if not code_input or code_input.strip() == "":
        st.warning("Please paste some code before running the analysis.")
    else:
        # ========================================================
        # PHASE 1: Deterministic Static Analysis (instant, reliable)
        # ========================================================
        st.subheader("Phase 1 — Static Analysis Results")

        findings = _parse_static_findings(code_input)

        if findings:
            st.error(f"**{len(findings)} vulnerability pattern(s) detected**")

            # Build a clear table
            for f in findings:
                severity_icon = SEVERITY_COLORS.get(f["severity"], "⚪")
                st.markdown(
                    f"{severity_icon} **{f['severity']}** — Line {f['line']}: "
                    f"**{f['description']}**"
                )
                st.code(f["code"], language="python")
                st.caption(f"OWASP: {f['owasp']}")
                st.markdown("")

            # Summary table
            with st.expander("📊 Summary Table", expanded=True):
                table_data = []
                for f in findings:
                    table_data.append({
                        "Line": f["line"],
                        "Severity": f"{SEVERITY_COLORS.get(f['severity'], '')} {f['severity']}",
                        "Issue": f["description"],
                        "OWASP": f["owasp"],
                        "Code": f"`{f['code'][:60]}`",
                    })
                st.table(table_data)
        else:
            st.success("No common vulnerability patterns detected in static analysis.")

        st.markdown("---")

        # ========================================================
        # PHASE 2: ReAct Agent (LLM + RAG for deeper analysis)
        # ========================================================
        st.subheader("Phase 2 — ReAct Agent Analysis")
        st.caption("The agent uses reasoning + OWASP knowledge base for deeper context.")

        # Build a concise summary for the agent instead of raw code
        # (local models are bad at extracting multi-line code from prompts)
        sanitized_code = _sanitize_code_input(code_input)

        if findings:
            findings_summary = "\n".join(
                f"- Line {f['line']}: {f['description']} ({f['owasp']}) — `{f['code'][:80]}`"
                for f in findings
            )
            agent_query = (
                "The following Python code was analyzed. Static analysis found these issues:\n"
                f"{findings_summary}\n\n"
                "Search the OWASP knowledge base for detailed remediation guidance for each "
                "vulnerability found. Then provide a Final Answer with fix suggestions.\n\n"
                f"Full code:\n<USER_CODE>\n{sanitized_code}\n</USER_CODE>"
            )
        else:
            agent_query = (
                "Analyze this Python code for security vulnerabilities. "
                "Static analysis found no patterns, but check for logic issues:\n"
                f"<USER_CODE>\n{sanitized_code}\n</USER_CODE>"
            )

        reasoning_container = st.container()
        reasoning_container.markdown("### 🧠 Agent Reasoning (live)")

        with st.spinner("ReAct agent is analyzing..."):
            try:
                callback = StreamlitReActCallback(reasoning_container)
                result = agent_executor.invoke(
                    {"input": agent_query},
                    config={"callbacks": [callback]},
                )

                # Display the final answer
                st.subheader("Agent Recommendations")
                output = result["output"]
                if "Agent stopped" in output:
                    st.warning(
                        "The agent reached its iteration limit. "
                        "The static analysis results above are still valid."
                    )
                else:
                    st.markdown(output)

                # Display ReAct trace
                if result.get("intermediate_steps"):
                    with st.expander(
                        "📋 Full ReAct Trace (all steps)", expanded=False
                    ):
                        for i, (action, observation) in enumerate(
                            result["intermediate_steps"], 1
                        ):
                            st.markdown(f"**Step {i} — Tool:** `{action.tool}`")
                            st.markdown(
                                f"**Input:** `{str(action.tool_input)[:300]}`"
                            )
                            st.code(str(observation)[:1000], language=None)
                            st.markdown("---")

            except Exception:
                st.warning(
                    "The ReAct agent could not complete its analysis. "
                    "The static analysis results above are still valid. "
                    "Make sure Ollama is running with the correct model."
                )

st.markdown("---")
st.markdown(
    "**Phase 1** uses deterministic regex patterns (always reliable). "
    "**Phase 2** uses a ReAct agent (LLM + OWASP RAG) for deeper context and fix suggestions."
)
