"""Index persistence WITHOUT pickle.

LangChain's FAISS.save_local()/load_local() store the docstore as a pickle (index.pkl); loading one needs the
library's dangerous-deserialization opt-in flag, i.e. an index directory from anywhere can run code on load. This
module never reads a pickle. The index directory holds only:

    chunks.jsonl    one JSON object per chunk: {"text": ..., "metadata": {...}}
    vectors.npy     float32 matrix (numpy.load(allow_pickle=False))
    manifest.json   format version, embedding backend/model, dimensions, sha256 of both files

At query time the FAISS index is REBUILT from those files (FAISS.from_embeddings): no document is
re-embedded, and nothing executable is ever deserialised. A legacy index.pkl is refused with a
re-index hint instead of being loaded.
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Sequence

FORMAT = "readyhai-index-v2"
CHUNKS = "chunks.jsonl"
VECTORS = "vectors.npy"
MANIFEST = "manifest.json"


class IndexError_(RuntimeError):
    """Raised for a missing, corrupt, legacy or mismatching index."""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def _json_safe(meta: Dict[str, Any]) -> Dict[str, Any]:
    return {str(k): v for k, v in meta.items() if isinstance(v, (str, int, float, bool)) or v is None}


def save_index(index_dir: str, texts: Sequence[str], metadatas: Sequence[Dict[str, Any]], vectors, backend: str, model: str) -> None:
    import numpy as np

    arr = np.asarray(vectors, dtype=np.float32)
    if arr.ndim != 2 or arr.shape[0] != len(texts) or len(texts) != len(metadatas) or arr.shape[0] == 0:
        raise IndexError_(f"cannot save: {len(texts)} chunks vs vector matrix {arr.shape}")
    d = Path(index_dir)
    d.mkdir(parents=True, exist_ok=True)
    lines = "\n".join(json.dumps({"text": t, "metadata": _json_safe(m)}, ensure_ascii=False) for t, m in zip(texts, metadatas))
    _atomic_write(d / CHUNKS, (lines + "\n").encode("utf-8"))
    tmp_npy = d / f".{VECTORS}.{os.getpid()}.tmp"
    try:
        with open(tmp_npy, "wb") as fh:
            np.save(fh, arr, allow_pickle=False)
        os.replace(tmp_npy, d / VECTORS)
    finally:
        if tmp_npy.exists():
            tmp_npy.unlink()
    manifest = {
        "format": FORMAT,
        "embedding_backend": backend,
        "embedding_model": model,
        "chunks": int(arr.shape[0]),
        "dimensions": int(arr.shape[1]),
        "sha256": {CHUNKS: _sha256(d / CHUNKS), VECTORS: _sha256(d / VECTORS)},
    }
    _atomic_write(d / MANIFEST, json.dumps(manifest, indent=2).encode("utf-8"))


def read_index(index_dir: str):
    """(texts, metadatas, vectors, manifest) after verifying format and checksums. Pickle is never read."""
    d = Path(index_dir)
    if not d.is_dir():
        raise IndexError_(f"Index directory {d} not found. Run `index` first.")
    if not (d / MANIFEST).exists():
        legacy = [n for n in ("index.pkl", "index.faiss") if (d / n).exists()]
        if legacy:
            raise IndexError_(
                f"{d} is a legacy index ({', '.join(legacy)}). Its docstore is a pickle, which is not loaded "
                "because unpickling can execute code. Re-run `index` to rebuild it in the safe format."
            )
        raise IndexError_(f"{d} has no {MANIFEST}; run `index` first.")
    try:
        manifest = json.loads((d / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise IndexError_(f"unreadable {MANIFEST}: {e}") from e
    if manifest.get("format") != FORMAT:
        raise IndexError_(f"unsupported index format {manifest.get('format')!r}; re-run `index`.")
    for name in (CHUNKS, VECTORS):
        p = d / name
        if not p.is_file() or p.is_symlink():
            raise IndexError_(f"{name} is missing or a symlink")
        if _sha256(p) != manifest.get("sha256", {}).get(name):
            raise IndexError_(f"{name} does not match the checksum in {MANIFEST} (corrupt or modified); re-run `index`.")
    import numpy as np

    vectors = np.load(d / VECTORS, allow_pickle=False)
    texts: List[str] = []
    metas: List[Dict[str, Any]] = []
    with open(d / CHUNKS, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                row = json.loads(line)
                texts.append(str(row["text"]))
                metas.append(dict(row.get("metadata") or {}))
    if vectors.ndim != 2 or vectors.shape[0] != len(texts) or vectors.shape != (manifest["chunks"], manifest["dimensions"]):
        raise IndexError_("vector matrix and chunk list disagree; re-run `index`.")
    return texts, metas, vectors, manifest


def load_index(index_dir: str, embeddings, expect_model: str = ""):
    """Rebuild a FAISS vector store from the safe files. No pickle, no re-embedding of documents."""
    from langchain_community.vectorstores import FAISS

    texts, metas, vectors, manifest = read_index(index_dir)
    if expect_model and manifest.get("embedding_model") and manifest["embedding_model"] != expect_model:
        raise IndexError_(
            f"index was built with embedding model {manifest['embedding_model']!r} but queries use {expect_model!r}; "
            "vectors from different models are not comparable. Re-run `index` or set READYHAI_EMBEDDING_MODEL."
        )
    return FAISS.from_embeddings(list(zip(texts, vectors.tolist())), embeddings, metadatas=metas)
