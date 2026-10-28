"""Target document ingestion and indexing pipeline for ReadyHai using BGE-M3."""

import os
import json
from pathlib import Path
from typing import List, Optional
from langchain_core.documents import Document
from langchain_community.vectorstores import FAISS
from langchain_text_splitters import RecursiveCharacterTextSplitter

from .embeddings import get_bge_m3_embeddings

SUPPORTED_EXTENSIONS = {
    ".rs", ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".java",
    ".json", ".yaml", ".yml", ".toml", ".md", ".sarif", ".html"
}

IGNORE_DIRS = {
    ".git", "node_modules", "target", "dist", "build", ".venv",
    "vendor", ".next", ".cache", "__pycache__"
}


def load_target_files(target_dir: str) -> List[Document]:
    """Recursively load source code, specs, and reports from a ReadyHai target."""
    docs: List[Document] = []
    base_path = Path(target_dir).resolve()

    if not base_path.exists():
        raise FileNotFoundError(f"Target path does not exist: {base_path}")

    if base_path.is_file():
        try:
            content = base_path.read_text(encoding="utf-8", errors="replace")
            docs.append(Document(
                page_content=content,
                metadata={"source": str(base_path.name), "path": str(base_path), "kind": "file"}
            ))
        except Exception as e:
            print(f"Warning: Failed reading {base_path}: {e}")
        return docs

    for root, dirs, files in os.walk(base_path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in SUPPORTED_EXTENSIONS:
                file_path = Path(root) / f
                try:
                    content = file_path.read_text(encoding="utf-8", errors="replace")
                    if not content.strip():
                        continue
                    
                    kind = "code"
                    if ext in (".json", ".yaml", ".yml", ".toml"):
                        kind = "spec_or_config"
                    elif ext in (".md", ".sarif"):
                        kind = "report_or_doc"

                    rel_path = file_path.relative_to(base_path)
                    docs.append(Document(
                        page_content=content,
                        metadata={
                            "source": str(rel_path),
                            "path": str(file_path),
                            "kind": kind,
                            "extension": ext
                        }
                    ))
                except Exception as e:
                    print(f"Warning: Failed reading {file_path}: {e}")

    return docs


def build_bge_m3_index(
    target_dir: str,
    index_output_dir: str,
    chunk_size: int = 2500,
    chunk_overlap: int = 300,
    backend: Optional[str] = None
) -> FAISS:
    """Chunks documents using BGE-M3's long-sequence window and builds a FAISS index."""
    raw_docs = load_target_files(target_dir)
    if not raw_docs:
        raise ValueError(f"No valid documents found in {target_dir}")

    # BGE-M3 natively supports 8192 tokens. Chunk size of 2500 chars easily preserves
    # complete functions, schemas, and endpoint definitions without boundary breakage.
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        separators=["\nclass ", "\nfn ", "\npub fn ", "\ndef ", "\n## ", "\n\n", "\n", " "]
    )
    
    chunked_docs = splitter.split_documents(raw_docs)
    for idx, doc in enumerate(chunked_docs):
        doc.metadata["chunk_id"] = idx

    print(f"Loaded {len(raw_docs)} files, split into {len(chunked_docs)} chunks using BGE-M3 sequence window.")

    embeddings = get_bge_m3_embeddings(backend=backend)
    vectorstore = FAISS.from_documents(chunked_docs, embeddings)

    os.makedirs(index_output_dir, exist_ok=True)
    vectorstore.save_local(index_output_dir)
    print(f"FAISS index successfully saved to: {index_output_dir}")

    return vectorstore
