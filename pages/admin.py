import re
import streamlit as st
import shutil
import os
from langchain_community.document_loaders import PyPDFLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma

from config import (
    DOCS_DIR,
    CHROMA_DB_PATH,
    CHUNK_SIZE,
    CHUNK_OVERLAP,
    SUPPORTED_EXTENSIONS,
)
from tools import invalidate_retriever_cache, get_embeddings

st.set_page_config(page_title="Admin | Security Agent", page_icon="⚙️")

st.title("Knowledge Base Administration ⚙️")
st.markdown("Manage the OWASP and security standards documents that power the agent.")

# --- Authentication ---
if "admin_auth" not in st.session_state:
    st.session_state["admin_auth"] = False

if not st.session_state["admin_auth"]:
    password = st.text_input("Enter admin password to continue:", type="password")
    if password and password == os.environ.get("ADMIN_PASSWORD", "admin"):
        st.session_state["admin_auth"] = True
        st.rerun()
    elif password:
        st.error("Incorrect password.")
    st.stop()

# Ensure knowledge base directory exists
DOCS_DIR.mkdir(parents=True, exist_ok=True)


def index_documents(reset_db: bool = False) -> None:
    """Index documents from the knowledge base directory into ChromaDB."""
    with st.spinner("Indexing documents... This may take a moment."):
        if reset_db and CHROMA_DB_PATH.exists():
            st.info("Resetting knowledge base...")
            try:
                shutil.rmtree(CHROMA_DB_PATH)
                st.success("Previous knowledge base deleted.")
            except Exception:
                st.error("Failed to delete existing knowledge base.")
                return

        documents = []
        for filepath in DOCS_DIR.iterdir():
            try:
                if filepath.suffix == ".pdf":
                    loader = PyPDFLoader(str(filepath))
                    documents.extend(loader.load())
                elif filepath.suffix in (".md", ".txt"):
                    loader = TextLoader(str(filepath), encoding="utf-8")
                    documents.extend(loader.load())
            except Exception:
                st.warning(f"Could not load: {filepath.name}")

        if not documents:
            st.warning("No valid documents found to index. Upload documents first.")
            return

        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP
        )
        chunks = text_splitter.split_documents(documents)

        embeddings = get_embeddings()

        # ChromaDB 1.0+ auto-persists — no db.persist() needed
        Chroma.from_documents(
            chunks, embeddings, persist_directory=str(CHROMA_DB_PATH)
        )

        st.success(f"Knowledge base updated with {len(chunks)} text chunks!")

        # Invalidate caches so agent picks up new knowledge
        invalidate_retriever_cache()
        try:
            from agent import load_security_agent
            load_security_agent.clear()
        except Exception:
            pass


# --- Upload Section ---
st.subheader("Upload Security Standards Documents")

uploaded_files = st.file_uploader(
    "Upload PDF, Markdown, or text files (OWASP, CWE, security guides, etc.)",
    type=["pdf", "md", "txt"],
    accept_multiple_files=True,
    key="doc_uploader",
)

if uploaded_files:
    for uploaded_file in uploaded_files:
        safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', uploaded_file.name)
        if not safe_name.lower().endswith(SUPPORTED_EXTENSIONS):
            st.error(f"Unsupported file type: {uploaded_file.name}")
            continue
        file_path = DOCS_DIR / safe_name
        if not file_path.resolve().is_relative_to(DOCS_DIR.resolve()):
            st.error(f"Invalid filename: {uploaded_file.name}")
            continue
        if file_path.exists():
            st.warning(f"'{safe_name}' already exists and will be replaced.")
        file_path.write_bytes(uploaded_file.getbuffer())
        st.success(f"'{safe_name}' uploaded successfully.")
    st.cache_data.clear()
    st.rerun()


# --- Document List ---
st.subheader("Documents in Knowledge Base")


files_in_dir = [f.name for f in DOCS_DIR.iterdir() if f.suffix in SUPPORTED_EXTENSIONS]

if not files_in_dir:
    st.info("No documents found. Upload OWASP/security standard files to get started.")
else:
    for file_name in files_in_dir:
        col1, col2 = st.columns([0.8, 0.2])
        with col1:
            st.write(file_name)
        with col2:
            if st.button("Delete", key=f"delete_{file_name}"):
                file_to_delete = DOCS_DIR / file_name
                try:
                    file_to_delete.unlink()
                    st.success(f"'{file_name}' deleted.")
                    st.rerun()
                except Exception:
                    st.error(f"Failed to delete '{file_name}'.")

st.markdown("---")

# --- Training Actions ---
st.subheader("Knowledge Base Actions")

col_retrain, col_reset = st.columns(2)

with col_retrain:
    if st.button(
        "Train System with Current Data",
        help="Index all documents in the knowledge base.",
        key="btn_retrain",
    ):
        index_documents(reset_db=False)

with col_reset:
    if st.button(
        "Reset ALL Knowledge",
        help="WARNING: Deletes all knowledge and rebuilds from scratch.",
        type="secondary",
        key="btn_reset",
    ):
        st.session_state["confirm_reset_active"] = True

    if st.session_state.get("confirm_reset_active", False):
        st.warning("Are you sure? This will erase all current knowledge!")
        col_confirm, col_cancel = st.columns(2)
        with col_confirm:
            if st.button("Yes, Reset", key="btn_confirm_reset"):
                index_documents(reset_db=True)
                st.success("Knowledge base reset and retrained!")
                st.session_state["confirm_reset_active"] = False
                st.rerun()
        with col_cancel:
            if st.button("Cancel", key="btn_cancel_reset"):
                st.info("Reset cancelled.")
                st.session_state["confirm_reset_active"] = False
                st.rerun()

st.markdown("---")
st.info(
    "After uploading or deleting documents, click 'Train System with Current Data' "
    "to update the agent's knowledge base."
)
