"""BGE-M3 Embeddings provider supporting 8192-token long context.

Supports three provider backends:
1. "ollama": Connects to local Ollama instance running `bge-m3:latest`.
2. "huggingface": Uses local PyTorch / sentence-transformers `BAAI/bge-m3`.
3. "openai_compatible": Connects to a vLLM or TEI endpoint serving `BAAI/bge-m3`.
"""

import os
from typing import Optional
from langchain_core.embeddings import Embeddings


def get_bge_m3_embeddings(
    backend: Optional[str] = None,
    base_url: Optional[str] = None,
    device: Optional[str] = None,
) -> Embeddings:
    """Instantiate and return BGE-M3 embeddings.
    
    BGE-M3 features:
    - Maximum sequence length: 8,192 tokens.
    - Dense vector dimension: 1,024.
    - Multi-lingual and code representation.
    """
    selected_backend = backend or os.environ.get("READYHAI_EMBEDDING_BACKEND", "ollama").lower()
    
    if selected_backend == "ollama":
        from langchain_ollama import OllamaEmbeddings
        endpoint = base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        model = os.environ.get("READYHAI_EMBEDDING_MODEL", "bge-m3:latest")
        return OllamaEmbeddings(
            base_url=endpoint,
            model=model,
        )

    elif selected_backend == "huggingface":
        from langchain_huggingface import HuggingFaceEmbeddings
        model_name = os.environ.get("READYHAI_EMBEDDING_MODEL", "BAAI/bge-m3")
        target_device = device or os.environ.get("READYHAI_DEVICE", "cpu")
        return HuggingFaceEmbeddings(
            model_name=model_name,
            model_kwargs={"device": target_device},
            encode_kwargs={"normalize_embeddings": True},
        )

    elif selected_backend in ("openai_compatible", "vllm", "tei"):
        from langchain_openai import OpenAIEmbeddings
        endpoint = base_url or os.environ.get("READYHAI_VLLM_URL", "http://10.10.110.42:13320/v1")
        model = os.environ.get("READYHAI_EMBEDDING_MODEL", "BAAI/bge-m3")
        return OpenAIEmbeddings(
            base_url=endpoint,
            model=model,
            api_key=os.environ.get("OPENAI_API_KEY", "EMPTY"),
            check_embedding_ctx_length=False,
        )

    else:
        raise ValueError(
            f"Unsupported embedding backend '{selected_backend}'. Choose from: 'ollama', 'huggingface', 'openai_compatible'."
        )
