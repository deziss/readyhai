# LLM Module (`src/llm`)

## Responsibility
Provides multi-provider LLM integrations (OpenAI-compatible, Anthropic Messages), runtime configuration resolution, network boundary guards, secret redaction, and strict single-shot JSON structured querying with token/time budgeting and timeout degradation.

## Architecture & Submodules
- `catalog.rs`: Provider catalog descriptors (`ollama`, `vllm`, `openai`, `anthropic`, `openrouter`), timing/token constants, and provider lookup.
- `config.rs`: `LlmConfig` runtime resolution from environment variables, URL validation, container loopback mapping, and off-box cloud guards.
- `client.rs`: `ChatClient` trait, `OpenAiClient`, `AnthropicClient`, request builders, exponential backoff retries, and authentication.
- `redact.rs`: High-performance regex and structural JSON secret/credential scrubbing before sending data off-box.
- `probe.rs`: HTTP `/models` reachability checks, 1-token latency benchmarks, and model listing.
- `budget.rs`: Per-run `Budget` accounting, `ask_json` / `ask_typed` structured querying, disk caching, and progressive timeout degradation.
- `untrusted.rs`: Fencing and prompt injection defense utilities for untrusted web inputs.
- `mock.rs`: Lightweight in-process OpenAI-compatible test fixture server.
- `mod.rs`: Clean re-export facade maintaining 100% backward compatibility for existing callers.
- `tests.rs`: Comprehensive test suite containing 49 unit tests.

## Security & Architectural Invariants
1. **No Accidental Cloud Egress**: Cloud providers or public host IPs require explicit `READYHAI_LLM_ALLOW_CLOUD=1`.
2. **Deterministic Redaction**: Keys matching sensitive patterns (`token`, `password`, `secret`, `bearer`, `cookie`, `key`) are redacted before prompts leave the host.
3. **Budget Caps**: All calls enforce strict time and token limits with progressive downgrade floors.
4. **Single Responsibility**: Every file is bounded within 100–370 lines.
