"""Tests for RAG-based tools with mocked retriever.

Uses sys.modules patching to avoid requiring langchain/chromadb at import time.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Mock langchain modules before importing tools
sys.modules["langchain_community"] = MagicMock()
sys.modules["langchain_community.vectorstores"] = MagicMock()
sys.modules["langchain_community.embeddings"] = MagicMock()

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools import _format_docs


def _make_mock_doc(content, source="OWASP-Top10.pdf", page=1):
    """Create a mock LangChain Document."""
    doc = MagicMock()
    doc.page_content = content
    doc.metadata = {"source": source, "page": page}
    return doc


class TestFormatDocs:
    def test_empty_list(self):
        result = _format_docs([])
        assert "No relevant documents" in result

    def test_single_doc(self):
        doc = _make_mock_doc("SQL injection is a vulnerability", "owasp.pdf", 5)
        result = _format_docs([doc])
        assert "owasp.pdf" in result
        assert "Page 5" in result
        assert "SQL injection" in result

    def test_multiple_docs(self):
        docs = [
            _make_mock_doc("First doc content", "a.pdf", 1),
            _make_mock_doc("Second doc content", "b.pdf", 2),
        ]
        result = _format_docs(docs)
        assert "Source 1" in result
        assert "Source 2" in result

    def test_truncation(self):
        doc = _make_mock_doc("x" * 1000, "long.pdf", 1)
        result = _format_docs([doc], max_per_doc=50)
        # Content in result should be truncated
        assert "x" * 50 in result
        assert "x" * 100 not in result

    def test_source_path_extraction(self):
        doc = _make_mock_doc("content", "/full/path/to/owasp.pdf", 3)
        result = _format_docs([doc])
        assert "owasp.pdf" in result
        assert "/full/path/to/" not in result


class TestSearchOwaspKb:
    @patch("tools._get_retriever")
    def test_returns_formatted_results(self, mock_get_retriever):
        from tools import search_owasp_kb

        mock_retriever = MagicMock()
        mock_retriever.invoke.return_value = [
            _make_mock_doc("A03:2021 Injection description", "OWASP.pdf", 8)
        ]
        mock_get_retriever.return_value = mock_retriever

        result = search_owasp_kb("SQL injection")
        assert "OWASP.pdf" in result
        assert "A03:2021" in result

    @patch("tools._get_retriever")
    def test_empty_results(self, mock_get_retriever):
        from tools import search_owasp_kb

        mock_retriever = MagicMock()
        mock_retriever.invoke.return_value = []
        mock_get_retriever.return_value = mock_retriever

        result = search_owasp_kb("nonexistent topic")
        assert "No relevant documents" in result

    @patch("tools._get_retriever")
    def test_handles_exception(self, mock_get_retriever):
        from tools import search_owasp_kb

        mock_get_retriever.side_effect = Exception("DB not found")
        result = search_owasp_kb("test")
        assert "Error" in result


class TestGetCveDetails:
    @patch("tools._get_retriever")
    def test_returns_cve_info(self, mock_get_retriever):
        from tools import get_cve_details

        mock_retriever = MagicMock()
        mock_retriever.invoke.return_value = [
            _make_mock_doc("CWE-89: SQL Injection", "CWE-DB.pdf", 12)
        ]
        mock_get_retriever.return_value = mock_retriever

        result = get_cve_details("CWE-89")
        assert "CWE-89" in result
        assert "CWE-DB.pdf" in result


class TestSearchRemediation:
    @patch("tools._get_retriever")
    def test_returns_fix_guidance(self, mock_get_retriever):
        from tools import search_remediation

        mock_retriever = MagicMock()
        mock_retriever.invoke.return_value = [
            _make_mock_doc(
                "Use parameterized queries to prevent SQL injection",
                "OWASP.pdf",
                9,
            )
        ]
        mock_get_retriever.return_value = mock_retriever

        result = search_remediation("SQL injection fix Python")
        assert "parameterized queries" in result

    @patch("tools._get_retriever")
    def test_handles_exception(self, mock_get_retriever):
        from tools import search_remediation

        mock_get_retriever.side_effect = Exception("Connection error")
        result = search_remediation("test")
        assert "Error" in result


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
