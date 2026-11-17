//! Universal GenAI & Agent Evaluator (readyhai eval-ai).
//! Evaluates RAG pipelines, LLM outputs, and AI agent trajectories:
//! 1. RAG Quality Triad: Context Relevance, Groundedness / Faithfulness (Hallucination detection), Answer Relevance.
//! 2. Agent Trajectory & Tool-Calling Validation: Schema conformance, cyclic loop detection, efficiency scoring.
//! 3. Adversarial Red-Teaming: Indirect prompt injection detection, system prompt extraction, sensitive data leakage.
//! 4. 100% Offline & Deterministic: runs mathematical heuristics without requiring external cloud LLMs.

#![allow(unused_imports)]

pub mod dataset;
pub mod evaluator;
pub mod nlp;
pub mod rag;
pub mod report;
pub mod runner;
pub mod safety;
pub mod trajectory;
pub mod types;

#[cfg(test)]
mod tests;

pub use dataset::load_cases;
pub use evaluator::evaluate_cases;
pub use nlp::{
    extract_content_words, extract_numerical_entities, extract_proper_nouns, split_sentences,
};
pub use rag::evaluate_rag_triad;
pub use runner::run;
pub use safety::evaluate_safety;
pub use trajectory::evaluate_trajectory;
pub use types::{
    AiEvalReport, AiTestCase, AiTestResult, EvalAiOpts, HallucinationDetail, RagTriadScore,
    RedTeamCheck, TrajectoryEval,
};
