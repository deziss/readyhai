"""BGE-M3 Embeddings provider supporting 8192-token long context.

Supports three provider backends:
1. "ollama": Connects to local Ollama instance running `bge-m3:latest`.
2. "huggingface": Uses local PyTorch / sentence-transformers `BAAI/bge-m3`.
3. "openai_compatible": Connects to a vLLM or TEI endpoint serving `BAAI/bge-m3` (READYHAI_VLLM_URL, no default).

OPENAI_API_KEY is sent only to api.openai.com; other endpoints get READYHAI_EMBEDDING_API_KEY or "EMPTY".
"""

import os
from typing import Optional

from .config import api_key_for, openai_compatible_base_url


def embedding_model_name(backend: Optional[str] = None) -> str:
    b = (backend or os.environ.get("READYHAI_EMBEDDING_BACKEND", "ollama")).lower()
    if b == "ollama":
        return os.environ.get("READYHAI_EMBEDDING_MODEL", "bge-m3:latest")
    return os.environ.get("READYHAI_EMBEDDING_MODEL", "BAAI/bge-m3")


def get_bge_m3_embeddings(
    backend: Optional[str] = None,
    base_url: Optional[str] = None,
    device: Optional[str] = None,
):
    """Instantiate and return BGE-M3 embeddings.

    BGE-M3 features: 8,192-token context, 1,024-dim dense vectors, multi-lingual and code aware.
    """
    selected_backend = (backend or os.environ.get("READYHAI_EMBEDDING_BACKEND", "ollama")).lower()

    if selected_backend == "ollama":
        from langchain_ollama import OllamaEmbeddings

        endpoint = base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        return OllamaEmbeddings(base_url=endpoint, model=embedding_model_name("ollama"))

    if selected_backend == "huggingface":
        from langchain_huggingface import HuggingFaceEmbeddings

        target_device = device or os.environ.get("READYHAI_DEVICE", "cpu")
        return HuggingFaceEmbeddings(
            model_name=embedding_model_name("huggingface"),
            model_kwargs={"device": target_device},
            encode_kwargs={"normalize_embeddings": True},
        )

    if selected_backend in ("openai_compatible", "vllm", "tei"):
        from langchain_openai import OpenAIEmbeddings

        endpoint = base_url or openai_compatible_base_url(required=True)
        return OpenAIEmbeddings(
            base_url=endpoint,
            model=embedding_model_name(selected_backend),
            api_key=api_key_for(endpoint, "READYHAI_EMBEDDING_API_KEY"),
            check_embedding_ctx_length=False,
        )

    raise ValueError(
        f"Unsupported embedding backend '{selected_backend}'. Choose from: 'ollama', 'huggingface', 'openai_compatible'."
    )
