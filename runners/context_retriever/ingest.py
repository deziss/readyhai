"""Target document ingestion and indexing pipeline for ReadyHai using BGE-M3.

Files are collected by `files.load_files` (no symlinks, size caps, redacted before anything else),
chunked, embedded, and written with `store.save_index` (no pickle).
"""

from typing import List, Optional

from .embeddings import embedding_model_name, get_bge_m3_embeddings
from .files import IGNORE_DIRS, SUPPORTED_EXTENSIONS, load_files  # noqa: F401  (re-exported)
from .store import save_index

EMBED_BATCH = 64


def load_target_files(target_dir: str):
    """Recursively load source code, specs, and reports from a ReadyHai target as LangChain Documents."""
    from langchain_core.documents import Document

    return [
        Document(page_content=r.text, metadata={"source": r.rel, "kind": r.kind, "extension": r.ext})
        for r in load_files(target_dir)
    ]


def build_bge_m3_index(
    target_dir: str,
    index_output_dir: str,
    chunk_size: int = 2500,
    chunk_overlap: int = 300,
    backend: Optional[str] = None,
):
    """Chunk with BGE-M3's long-sequence window, embed, and persist (JSONL + .npy + manifest)."""
    from langchain_text_splitters import RecursiveCharacterTextSplitter

    raw_docs = load_target_files(target_dir)
    if not raw_docs:
        raise ValueError(f"No valid documents found in {target_dir}")

    # BGE-M3 natively supports 8192 tokens; 2500 chars keeps whole functions/schemas/endpoints together.
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        separators=["\nclass ", "\nfn ", "\npub fn ", "\ndef ", "\n## ", "\n\n", "\n", " "],
    )
    chunks = splitter.split_documents(raw_docs)
    for idx, doc in enumerate(chunks):
        doc.metadata["chunk_id"] = idx
    print(f"Loaded {len(raw_docs)} files, split into {len(chunks)} chunks.")

    embeddings = get_bge_m3_embeddings(backend=backend)
    texts: List[str] = [c.page_content for c in chunks]
    vectors: List[List[float]] = []
    for i in range(0, len(texts), EMBED_BATCH):
        vectors.extend(embeddings.embed_documents(texts[i : i + EMBED_BATCH]))

    save_index(
        index_output_dir,
        texts,
        [c.metadata for c in chunks],
        vectors,
        backend=(backend or "env"),
        model=embedding_model_name(backend),
    )
    print(f"Index saved to {index_output_dir} (chunks.jsonl + vectors.npy + manifest.json; no pickle).")
