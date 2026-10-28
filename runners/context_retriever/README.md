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

# Option B: Local vLLM / TEI LAN endpoint
export READYHAI_EMBEDDING_BACKEND="vllm"
export READYHAI_VLLM_URL="http://10.10.110.42:13320/v1"
export READYHAI_EMBEDDING_MODEL="BAAI/bge-m3"

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

### 4. Run LangGraph Query Context Retrieval
```bash
python -m runners.context_retriever.main query \
  --query "Where are the authentication checks and token validations?" \
  --index-dir ./data/sample_bge_m3_index \
  --max-chunks 8
```
