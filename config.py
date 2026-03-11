"""Shared configuration for the Security Agent."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

# Paths
CHROMA_DB_PATH = PROJECT_ROOT / "chroma_db"
DOCS_DIR = PROJECT_ROOT / "knowledge-base"

# Models
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
LLM_MODEL_NAME = "llama3"

# RAG Parameters
CHUNK_SIZE = 1000
CHUNK_OVERLAP = 200
RETRIEVER_K = 5

# Code Input
MAX_CODE_LENGTH = 4500

# Supported file extensions for knowledge base
SUPPORTED_EXTENSIONS = (".pdf", ".md", ".txt")
