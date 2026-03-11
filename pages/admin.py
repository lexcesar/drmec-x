import streamlit as st
import shutil
from langchain_community.document_loaders import PyPDFLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import SentenceTransformerEmbeddings
from langchain_community.vectorstores import Chroma

from config import (
    DOCS_DIR,
    CHROMA_DB_PATH,
    EMBEDDING_MODEL_NAME,
    CHUNK_SIZE,
    CHUNK_OVERLAP,
    SUPPORTED_EXTENSIONS,
)
from tools import invalidate_retriever_cache

st.set_page_config(page_title="Admin | Security Agent", page_icon="⚙️")

st.title("Knowledge Base Administration ⚙️")
st.markdown("Manage the OWASP and security standards documents that power the agent.")

# Ensure knowledge base directory exists
DOCS_DIR.mkdir(parents=True, exist_ok=True)


def indexar_documentos(reset_db=False):
    """Index documents from the knowledge base directory into ChromaDB."""
    with st.spinner("Indexing documents... This may take a moment."):
        if reset_db and CHROMA_DB_PATH.exists():
            st.info("Resetting knowledge base...")
            try:
                shutil.rmtree(CHROMA_DB_PATH)
                st.success("Previous knowledge base deleted.")
            except Exception as e:
                st.error(f"Error deleting knowledge base: {e}")
                return

        documentos = []
        for filepath in DOCS_DIR.iterdir():
            try:
                if filepath.suffix == ".pdf":
                    loader = PyPDFLoader(str(filepath))
                    documentos.extend(loader.load())
                elif filepath.suffix in (".md", ".txt"):
                    loader = TextLoader(str(filepath), encoding="utf-8")
                    documentos.extend(loader.load())
            except Exception as e:
                st.warning(f"Could not load: {filepath.name}. Error: {e}")

        if not documentos:
            st.warning("No valid documents found to index. Upload documents first.")
            return

        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP
        )
        chunks = text_splitter.split_documents(documentos)

        embeddings = SentenceTransformerEmbeddings(model_name=EMBEDDING_MODEL_NAME)

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
        file_path = DOCS_DIR / uploaded_file.name
        if file_path.exists():
            st.warning(f"'{uploaded_file.name}' already exists and will be replaced.")
        file_path.write_bytes(uploaded_file.getbuffer())
        st.success(f"'{uploaded_file.name}' uploaded successfully.")
    st.cache_data.clear()
    st.rerun()


# --- Document List ---
st.subheader("Documents in Knowledge Base")


@st.cache_data(ttl=300)
def get_files_in_dir(directory_str):
    """List files with supported extensions."""
    directory = DOCS_DIR
    return [f.name for f in directory.iterdir() if f.suffix in SUPPORTED_EXTENSIONS]


get_files_in_dir.clear()
files_in_dir = get_files_in_dir(str(DOCS_DIR))

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
                    get_files_in_dir.clear()
                    st.rerun()
                except Exception as e:
                    st.error(f"Error deleting '{file_name}': {e}")

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
        indexar_documentos(reset_db=False)

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
                indexar_documentos(reset_db=True)
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
