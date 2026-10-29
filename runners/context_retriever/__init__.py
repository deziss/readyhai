"""ReadyHai LangGraph BGE-M3 Long Context Retriever package.

Heavy dependencies (langchain, faiss, torch...) are imported lazily, so the pure helpers
(`safety`, `config`, `files`) can be imported and unit-tested without them.
"""

__all__ = [
    "get_bge_m3_embeddings",
    "ReadyHaiLongContextTransformer",
    "ReadyHaiContextRetrieverGraph",
    "build_bge_m3_index",
    "load_target_files",
]

_LAZY = {
    "get_bge_m3_embeddings": ".embeddings",
    "ReadyHaiLongContextTransformer": ".reorderer",
    "ReadyHaiContextRetrieverGraph": ".graph",
    "build_bge_m3_index": ".ingest",
    "load_target_files": ".ingest",
}


def __getattr__(name):
    if name in _LAZY:
        import importlib

        return getattr(importlib.import_module(_LAZY[name], __name__), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
