"""Security analysis tools for the ReAct agent.

Each tool performs retrieval or deterministic computation — things
the LLM cannot do on its own.
"""

import re
from functools import lru_cache

from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import SentenceTransformerEmbeddings

from config import CHROMA_DB_PATH, EMBEDDING_MODEL_NAME, RETRIEVER_K


@lru_cache(maxsize=1)
def _get_embeddings():
    """Load embedding model once (singleton)."""
    return SentenceTransformerEmbeddings(model_name=EMBEDDING_MODEL_NAME)


@lru_cache(maxsize=1)
def _get_retriever():
    """Load ChromaDB retriever once (singleton)."""
    embeddings = _get_embeddings()
    db = Chroma(persist_directory=str(CHROMA_DB_PATH), embedding_function=embeddings)
    return db.as_retriever(search_kwargs={"k": RETRIEVER_K})


def invalidate_retriever_cache():
    """Call after admin reindexes the knowledge base."""
    _get_retriever.cache_clear()
    _get_embeddings.cache_clear()


def _format_docs(docs, max_per_doc=500):
    """Format retrieved documents with source attribution."""
    if not docs:
        return "No relevant documents found in the knowledge base."
    results = []
    for i, doc in enumerate(docs, 1):
        source = doc.metadata.get("source", "Unknown")
        page = doc.metadata.get("page", "N/A")
        source_name = source.split("/")[-1] if "/" in source else source
        content = doc.page_content[:max_per_doc]
        results.append(f"[Source {i}: {source_name}, Page {page}]\n{content}")
    return "\n\n---\n\n".join(results)


# ---------------------------------------------------------------------------
# Tool 1: search_owasp_kb — RAG retrieval on security standards
# ---------------------------------------------------------------------------

def search_owasp_kb(query: str) -> str:
    """Search the OWASP/security knowledge base for relevant standards and best practices.

    Use this tool when you need to find specific security standards, vulnerability
    descriptions, or best practices. Pass keywords about the security topic.

    Args:
        query: Keywords about the security topic (e.g., "SQL injection prevention").
    """
    try:
        retriever = _get_retriever()
        docs = retriever.invoke(query)
        return _format_docs(docs)
    except Exception as e:
        return f"Error searching knowledge base: {e}"


# ---------------------------------------------------------------------------
# Tool 2: analyze_code — deterministic regex pattern matching
# ---------------------------------------------------------------------------

VULNERABILITY_PATTERNS = [
    (r"(password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*['\"][^'\"]+['\"]",
     "Hardcoded credential or secret detected",
     "A07:2021 - Identification and Authentication Failures"),

    (r"(exec|eval|compile)\s*\(",
     "Use of dangerous function (exec/eval/compile) — potential code injection",
     "A03:2021 - Injection"),

    (r"(SELECT|INSERT|UPDATE|DELETE).*(\+|%s|\.format|f['\"])",
     "Possible SQL injection via string concatenation/formatting",
     "A03:2021 - Injection"),

    (r"subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True",
     "Shell command execution with shell=True — potential command injection",
     "A03:2021 - Injection"),

    (r"pickle\.(loads?|dumps?)\s*\(",
     "Use of pickle — potential deserialization vulnerability",
     "A08:2021 - Software and Data Integrity Failures"),

    (r"yaml\.load\s*\((?!.*Loader)[^)]*\)",
     "Unsafe YAML loading without explicit Loader",
     "A08:2021 - Software and Data Integrity Failures"),

    (r"os\.(system|popen)\s*\(",
     "Direct OS command execution — potential command injection",
     "A03:2021 - Injection"),

    (r"verify\s*=\s*False",
     "SSL verification disabled — vulnerable to MITM attacks",
     "A02:2021 - Cryptographic Failures"),

    (r"(md5|sha1)\s*\(",
     "Use of weak hashing algorithm (MD5/SHA1)",
     "A02:2021 - Cryptographic Failures"),

    (r"random\.(random|randint|choice)\s*\(",
     "Use of non-cryptographic random — use secrets module for security",
     "A02:2021 - Cryptographic Failures"),

    (r"innerHTML\s*=|\.html\s*\(|document\.write\s*\(",
     "Potential XSS vulnerability — direct HTML injection",
     "A03:2021 - Injection"),

    (r"http://",
     "Unencrypted HTTP URL detected — use HTTPS",
     "A02:2021 - Cryptographic Failures"),

    (r"DEBUG\s*=\s*True|debug\s*=\s*True",
     "Debug mode enabled — should be disabled in production",
     "A05:2021 - Security Misconfiguration"),

    (r"CORS.*\*|Access-Control-Allow-Origin.*\*",
     "Wildcard CORS policy — overly permissive",
     "A05:2021 - Security Misconfiguration"),
]


def analyze_code(code: str) -> str:
    """Analyze source code for common security vulnerability patterns using static checks.

    Use this tool to perform pattern-based static analysis on the submitted code.
    It checks for hardcoded credentials, dangerous functions, SQL injection patterns,
    and other known insecure patterns.

    Args:
        code: The source code to analyze.
    """
    findings = []
    lines = code.split("\n")

    for line_num, line in enumerate(lines, 1):
        for pattern, description, owasp_ref in VULNERABILITY_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(
                    f"Line {line_num}: {description}\n"
                    f"  OWASP: {owasp_ref}\n"
                    f"  Code: `{line.strip()}`"
                )

    if not findings:
        return "No common vulnerability patterns detected through static analysis."

    return f"Found {len(findings)} potential issue(s):\n\n" + "\n\n".join(findings)


# ---------------------------------------------------------------------------
# Tool 3: get_cve_details — RAG retrieval for specific CVE/CWE identifiers
# ---------------------------------------------------------------------------

def get_cve_details(identifier: str) -> str:
    """Look up details about a specific CVE, CWE, or OWASP category from the knowledge base.

    Use this tool when you have identified a specific vulnerability type and need
    detailed information about it (description, impact, affected systems).

    Args:
        identifier: A CVE ID (e.g., "CWE-89"), OWASP category (e.g., "A03:2021"),
                    or vulnerability name (e.g., "SQL Injection").
    """
    try:
        retriever = _get_retriever()
        docs = retriever.invoke(f"details about {identifier} vulnerability")
        return _format_docs(docs)
    except Exception as e:
        return f"Error looking up {identifier}: {e}"


# ---------------------------------------------------------------------------
# Tool 4: search_remediation — targeted RAG for fix/mitigation guidance
# ---------------------------------------------------------------------------

def search_remediation(vulnerability_type: str) -> str:
    """Search the knowledge base specifically for remediation and fix guidance.

    Use this tool after identifying vulnerabilities to find concrete fix
    recommendations, secure coding patterns, and mitigation strategies.

    Args:
        vulnerability_type: The type of vulnerability to find fixes for
                           (e.g., "SQL injection fix parameterized queries").
    """
    try:
        retriever = _get_retriever()
        query = f"remediation fix prevention mitigation for {vulnerability_type}"
        docs = retriever.invoke(query)
        return _format_docs(docs)
    except Exception as e:
        return f"Error searching remediation guidance: {e}"
