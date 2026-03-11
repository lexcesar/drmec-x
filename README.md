# Security Agent — OWASP Code Analyzer 🔒

## About

An AI-powered **Security Engineering Agent** that uses **ReAct (Reasoning and Acting)** to analyze source code for vulnerabilities based on OWASP standards and security best practices.

The agent doesn't just answer questions — it **reasons** about your code, **acts** by searching the security knowledge base and analyzing patterns, **observes** results, and continues reasoning until it delivers a complete security review.

### Features

- **ReAct Agent**: Multi-step reasoning loop (Thought → Action → Observation → ...) for thorough analysis
- **OWASP Knowledge Base**: Upload security standards (OWASP Top 10, CWE, etc.) as the agent's knowledge source
- **Code Pattern Analysis**: Static checks for common vulnerability patterns (SQL injection, hardcoded credentials, XSS, etc.)
- **Structured Review**: Results organized by Vulnerabilities, OWASP References, Fix Suggestions, and Security Policy
- **Agent Transparency**: View the agent's complete reasoning process step by step
- **Multiple Languages**: Supports Python, JavaScript, Java, C/C++, Go

### Tech Stack

- **Python**: Core language
- **Streamlit**: Interactive web UI
- **Ollama**: Local LLM inference (llama3)
- **LangChain**: ReAct agent framework with tools
- **ChromaDB**: Vector database for security knowledge base
- **Sentence Transformers**: Text embeddings (all-MiniLM-L6-v2)

---

## How to Run

### Prerequisites

- Python 3.9+
- [Ollama](https://ollama.com) installed and running

### 1. Clone the Repository

```bash
git clone https://github.com/dnegrone/drmec-x.git
cd drmec-x
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Download the LLM Model

```bash
ollama pull llama3
```

Make sure the Ollama service is running in the background.

### 5. Run the Application

```bash
streamlit run streamlit_app.py
```

The app will open at http://localhost:8501.

---

## Usage

### 1. Set Up Knowledge Base (Admin Page)

1. Navigate to the **Admin** page via the sidebar
2. Upload OWASP/security documents (PDF, Markdown, or text files)
3. Click **"Train System with Current Data"** to index the documents

### 2. Analyze Code (Home Page)

1. Navigate to the **Home** page
2. Select the programming language
3. Paste your code in the editor
4. Click **"Analyze Security"**
5. View the structured security review
6. Expand **"Agent Reasoning Process"** to see the ReAct steps

### ReAct Agent Flow

The agent follows a multi-step reasoning process:

```
Thought: I need to analyze this code for security vulnerabilities.
Action: analyze_code_patterns (static vulnerability detection)
Observation: Found hardcoded credentials on line 8...

Thought: Let me check the OWASP knowledge base for relevant standards.
Action: search_owasp_kb (vector search on security docs)
Observation: OWASP A07:2021 - Identification and Authentication Failures...

Thought: I should suggest fixes for the identified issues.
Action: suggest_fix (knowledge-base-powered fix recommendations)
Observation: Replace hardcoded credentials with environment variables...

Final Answer: Structured security review with vulnerabilities, references, and fixes.
```

---

## Agent Tools

| Tool | Description |
|------|-------------|
| `search_owasp_kb` | Searches the OWASP/security knowledge base via vector similarity |
| `analyze_code_patterns` | Static pattern matching for common vulnerabilities |
| `suggest_fix` | Generates fix recommendations from the knowledge base |
| `generate_security_policy` | Creates a security policy based on findings |

---

## License

MIT License

## Contact

Alexander Costa - https://alexcesar.com
