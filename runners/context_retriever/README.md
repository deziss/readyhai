# ReadyHai LangGraph BGE-M3 Long Context Retriever

Autonomous Codebase & Security Audit Retrieval Runner for ReadyHai.

## Why this exists in ReadyHai

ReadyHai conducts deep audits across massive codebases (100k+ lines), sprawling OpenAPI specs (thousands of routes), and extensive SAST/SCA/secret scan reports (Grype, Semgrep, Lynis, Gitleaks). 

Standard RAG systems chop files into 200–500 token micro-chunks, stripping function context, types, and route definitions. Moreover, feeding huge context into LLMs triggers the **"Lost in the Middle"** phenomenon, where the model misses crucial vulnerabilities located in middle paragraphs.

This runner pairs:
1. **BGE-M3 Embeddings (`BAAI/bge-m3`)**: Supports native **8,192-token sequence lengths**, multi-linguality, and code syntax. Allows large semantic chunks (2,500+ chars) preserving complete functions and OpenAPI paths.
2. **`LongContextReorder`**: Mitigates "Lost in the Middle" by placing highest-scoring findings at the start and end of prompt context.
3. **LangGraph StateGraph**: Provides a structured 4-stage pipeline (`analyze_query` -> `retrieve_bge_m3` -> `reorder_and_compress` -> `synthesize_evidence`).

## Architecture & Workflow

```text
       ┌────────────────────────┐
       │     User Query         │
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │   analyze_query_node   │  (Normalizes intent & endpoints)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │  retrieve_bge_m3_node  │  (BGE-M3 MMR dense + diverse retrieval)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │ reorder_and_compress   │  (LongContextReorder + extremity weighting)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │  synthesize_evidence   │  (4-Pillar ReadyHai Evidence Ledger)
       └────────────────────────┘
```

## Quick Start

### 1. Install Dependencies
```bash
pip install -r runners/context_retriever/requirements.txt
```

### 2. Configure BGE-M3 Provider
Configure your preferred embedding provider via environment variables:

```bash
# Option A: Local Ollama (recommended if running Ollama locally)
export READYHAI_EMBEDDING_BACKEND="ollama"
export OLLAMA_BASE_URL="http://localhost:11434"
export READYHAI_EMBEDDING_MODEL="bge-m3:latest"

# Option B: any OpenAI-compatible endpoint (vLLM / TEI). There is no built-in address:
export READYHAI_EMBEDDING_BACKEND="vllm"
export READYHAI_VLLM_URL="http://<your-host>:8000/v1"
export READYHAI_EMBEDDING_MODEL="BAAI/bge-m3"
# OPENAI_API_KEY is sent ONLY to api.openai.com. A LAN/other endpoint gets a key only if you set one
# explicitly: READYHAI_EMBEDDING_API_KEY (embeddings) / READYHAI_LLM_API_KEY (chat synthesis).

# Option C: Hugging Face (local CPU/GPU)
export READYHAI_EMBEDDING_BACKEND="huggingface"
export READYHAI_EMBEDDING_MODEL="BAAI/bge-m3"
```

### 3. Index a Target Repository or OpenAPI Spec
```bash
python -m runners.context_retriever.main index \
  --target ./targets/sample-service \
  --index-dir ./data/sample_bge_m3_index
```

The index directory contains `chunks.jsonl`, `vectors.npy` and `manifest.json` (sha256 checksums) and
**no pickle**. Files are collected without following symlinks (FIFOs, oversized files and symlinked
directories are skipped), and their content is redacted (`DB_PASSWORD=...`, tokens, keys) before it is
chunked, embedded or stored. An index written by an older build (`index.pkl`) is refused with a re-index
hint instead of being unpickled.

### 4. Run LangGraph Query Context Retrieval
```bash
python -m runners.context_retriever.main query \
  --query "Where are the authentication checks and token validations?" \
  --index-dir ./data/sample_bge_m3_index \
  --max-chunks 8
```

At query time the FAISS index is rebuilt from `vectors.npy` + `chunks.jsonl` (documents are not
re-embedded). Retrieved chunks are untrusted: each one is redacted and wrapped in `<data>...</data>`
inside the user message (never the system prompt), and the system prompt tells the model to treat
them as inert data. LLM synthesis is advisory; if the LLM call fails the retrieved evidence is still
shown together with the error. Chat synthesis needs `READYHAI_VLLM_URL` (and optionally
`READYHAI_LLM_MODEL`); without it only retrieval runs.

### Tests (no heavy dependencies needed)
```bash
python3 -m unittest discover -s runners/context_retriever/tests -t . -v
```
