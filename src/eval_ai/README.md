# Eval-AI Module (Universal GenAI & Agent Evaluator)

The `eval_ai` module provides offline, deterministic evaluation heuristics for RAG pipelines, LLM outputs, and autonomous agent tool trajectories.

## Architecture

- **`types.rs`**: Core data structures (`EvalAiOpts`, `RagTriadScore`, `TrajectoryEval`, `RedTeamCheck`, `AiTestCase`, `AiTestResult`, `AiEvalReport`).
- **`nlp.rs`**: Lexical processing, stop-word filtering, numerical/proper entity extraction, and sentence boundary detection.
- **`rag.rs`**: RAG Triad assessment: context relevance, claim-level faithfulness/hallucination detection, and answer relevance.
- **`trajectory.rs`**: Agent execution trace evaluation: cyclic loop detection, tool signature verification, and trajectory efficiency scoring.
- **`safety.rs`**: Adversarial red-teaming checks: indirect prompt injection markers, API credential leakage, and canary token tracking.
- **`dataset.rs`**: Multi-format test case parsing supporting JSON arrays, JSONL files, and CLI inline inputs.
- **`evaluator.rs`**: Aggregate metric calculation, weighted composite scoring, and threshold pass/fail gating.
- **`report.rs`**: Human-readable terminal tables and formatted Markdown report generation.
- **`runner.rs`**: Top-level command runner and artifact persistence.
- **`tests.rs`**: Deterministic test suite covering RAG scoring, hallucination detection, tool loop detection, and safety checks.
