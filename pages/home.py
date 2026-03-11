import streamlit as st
from langchain.callbacks.base import BaseCallbackHandler

from config import CHROMA_DB_PATH, MAX_CODE_LENGTH
from agent import load_security_agent

st.set_page_config(page_title="Security Agent - Code Analyzer", page_icon="🔒")

st.title("Security Agent — Code Vulnerability Analyzer 🔒")
st.markdown(
    "Paste your **Python** code below. The **ReAct agent** will analyze it for security "
    "vulnerabilities using OWASP standards and best practices."
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
        # Wrap code in USER_CODE tags for prompt injection mitigation
        sanitized_code = _sanitize_code_input(code_input)
        agent_query = (
            "Analyze this Python code for security vulnerabilities:\n"
            f"<USER_CODE>\n{sanitized_code}\n</USER_CODE>"
        )

        # Create containers for streaming and results
        reasoning_container = st.container()
        reasoning_container.markdown("### 🧠 Agent Reasoning (live)")

        with st.spinner("Agent is analyzing your code..."):
            try:
                callback = StreamlitReActCallback(reasoning_container)
                result = agent_executor.invoke(
                    {"input": agent_query},
                    config={"callbacks": [callback]},
                )

                # Display the final answer
                st.subheader("Security Analysis Results")
                st.markdown(result["output"])

                # Display ReAct reasoning steps (full detail)
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
                st.error("An error occurred during analysis.")
                st.warning(
                    "Make sure Ollama is running and the LLM model is available. "
                    "Also verify the knowledge base has been trained."
                )

st.markdown("---")
st.markdown(
    "This agent uses **ReAct (Reasoning and Acting)** — it reasons about potential "
    "vulnerabilities, acts by consulting tools and the OWASP knowledge base, "
    "observes results, and continues until it can deliver a structured review."
)
