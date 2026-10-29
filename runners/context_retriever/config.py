"""Endpoint and credential resolution (stdlib only).

Two rules:
  * no baked-in LAN address: a base URL must be configured (READYHAI_VLLM_URL, OLLAMA_BASE_URL ...),
  * OPENAI_API_KEY is only ever sent to the official OpenAI host. Any other base URL (a LAN vLLM/TEI box,
    a proxy) gets a key only when one is configured explicitly for it (READYHAI_LLM_API_KEY /
    READYHAI_EMBEDDING_API_KEY), otherwise the placeholder "EMPTY".
"""

import os
from typing import Optional
from urllib.parse import urlparse

OFFICIAL_OPENAI_HOSTS = {"api.openai.com"}


class ConfigError(RuntimeError):
    pass


def openai_compatible_base_url(required: bool = True) -> Optional[str]:
    url = (os.environ.get("READYHAI_VLLM_URL") or "").strip()
    if url:
        return url
    if required:
        raise ConfigError(
            "READYHAI_VLLM_URL is not set. Export the base URL of your OpenAI-compatible endpoint, "
            "e.g. http://localhost:8000/v1 (there is deliberately no default address)."
        )
    return None


def api_key_for(base_url: str, explicit_env: str) -> str:
    """Key for an OpenAI-compatible client talking to `base_url`."""
    explicit = (os.environ.get(explicit_env) or "").strip()
    if explicit:
        return explicit
    host = (urlparse(base_url).hostname or "").lower()
    if host in OFFICIAL_OPENAI_HOSTS:
        return (os.environ.get("OPENAI_API_KEY") or "").strip() or "EMPTY"
    return "EMPTY"
