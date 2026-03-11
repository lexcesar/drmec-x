"""Security analysis tools for the ReAct agent.

Each tool performs retrieval or deterministic computation — things
the LLM cannot do on its own.
"""

from functools import lru_cache
from pathlib import Path

from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import SentenceTransformerEmbeddings

from config import CHROMA_DB_PATH, EMBEDDING_MODEL_NAME, RETRIEVER_K
from static_analysis import analyze_code  # noqa: F401 — re-exported for agent.py


@lru_cache(maxsize=1)
def get_embeddings():
    """Load embedding model once (singleton)."""
    return SentenceTransformerEmbeddings(model_name=EMBEDDING_MODEL_NAME)


@lru_cache(maxsize=1)
def _get_retriever():
    """Load ChromaDB retriever once (singleton)."""
    embeddings = get_embeddings()
    db = Chroma(persist_directory=str(CHROMA_DB_PATH), embedding_function=embeddings)
    return db.as_retriever(search_kwargs={"k": RETRIEVER_K})


def invalidate_retriever_cache():
    """Call after admin reindexes the knowledge base."""
    _get_retriever.cache_clear()
    get_embeddings.cache_clear()


def _format_docs(docs, max_per_doc=1500):
    """Format retrieved documents with source attribution."""
    if not docs:
        return "No relevant documents found in the knowledge base."
    results = []
    for i, doc in enumerate(docs, 1):
        source = doc.metadata.get("source", "Unknown")
        page = doc.metadata.get("page", "N/A")
        source_name = Path(source).name
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
        return "Error searching knowledge base. Ensure the knowledge base is trained."


# ---------------------------------------------------------------------------
# Tool 2: analyze_code — imported from static_analysis module
# ---------------------------------------------------------------------------


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
        return f"Error looking up {identifier}. Ensure the knowledge base is trained."


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
        return "Error searching remediation guidance. Ensure the knowledge base is trained."
