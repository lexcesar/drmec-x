"""Shared configuration for the Security Agent."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

# Paths
CHROMA_DB_PATH = PROJECT_ROOT / "chroma_db"
DOCS_DIR = PROJECT_ROOT / "knowledge-base"

# Models
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
LLM_MODEL_NAME = "llama3.1:8b"

# RAG Parameters
CHUNK_SIZE = 2000
CHUNK_OVERLAP = 300
RETRIEVER_K = 3

# Code Input
MAX_CODE_LENGTH = 10000 # modified for testing purposes

# Supported file extensions for knowledge base
SUPPORTED_EXTENSIONS = (".pdf", ".md", ".txt")
