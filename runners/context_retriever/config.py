"""Endpoint and credential resolution (stdlib only).

Rules:
  * no baked-in LAN address: a base URL must be configured. READYHAI_LLM_URL is the variable (the same one
    the Rust side reads); READYHAI_VLLM_URL is its deprecated alias, read when READYHAI_LLM_URL is unset,
  * OPENAI_API_KEY is only ever sent to the official OpenAI host. Any other base URL (a LAN vLLM/TEI box,
    a proxy) gets a key only when one is configured explicitly for it (READYHAI_EMBEDDING_API_KEY for
    embeddings, READYHAI_LLM_API_KEY for chat and, as a fallback, for embeddings sent to the same host as
    READYHAI_LLM_URL), otherwise the placeholder "EMPTY",
  * READYHAI_LLM_MODEL may be a comma-separated list: the first model is primary, the rest are fallbacks.
"""

import os
from typing import List, Optional
from urllib.parse import urlparse

OFFICIAL_OPENAI_HOSTS = {"api.openai.com"}
DEFAULT_LLM_MODEL = "qwen3.8-flash-next"


class ConfigError(RuntimeError):
    pass


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def openai_compatible_base_url(required: bool = True) -> Optional[str]:
    url = _env("READYHAI_LLM_URL") or _env("READYHAI_VLLM_URL")
    if url:
        return url
    if required:
        raise ConfigError(
            "READYHAI_LLM_URL is not set. Export the base URL of your OpenAI-compatible endpoint, "
            "e.g. http://localhost:8000/v1 (there is deliberately no default address)."
        )
    return None


def llm_models() -> List[str]:
    """READYHAI_LLM_MODEL (or READYHAI_LLM_MODELS), comma-separated, trimmed, de-duplicated, order kept."""
    raw = _env("READYHAI_LLM_MODEL") or _env("READYHAI_LLM_MODELS")
    models: List[str] = []
    for m in raw.split(","):
        m = m.strip()
        if m and m not in models:
            models.append(m)
    return models or [DEFAULT_LLM_MODEL]


def _host(url: Optional[str]) -> str:
    return (urlparse(url or "").hostname or "").lower()


def api_key_for(base_url: str, explicit_env: str) -> str:
    """Key for an OpenAI-compatible client talking to `base_url`."""
    explicit = _env(explicit_env)
    if explicit:
        return explicit
    host = _host(base_url)
    # the generic key belongs to the configured LLM endpoint: it is not sent to any other host
    generic = _env("READYHAI_LLM_API_KEY")
    if generic and host and host == _host(openai_compatible_base_url(required=False)):
        return generic
    if host in OFFICIAL_OPENAI_HOSTS:
        return _env("OPENAI_API_KEY") or "EMPTY"
    return "EMPTY"
