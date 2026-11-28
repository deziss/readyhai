//! RAG Quality Triad evaluation: Context Relevance, Faithfulness, and Answer Relevance.
//!
//! These scores are lexical, not semantic: they compare stopword-filtered tokens, numbers and
//! capitalised entities between query, retrieved context and response. No embedding model and no
//! LLM judge is involved, so they are a cheap approximation. Every score is an `Option`, and a
//! metric whose denominator is zero (no retrieved context, blank answer, empty query) is reported
//! as not measured instead of defaulting to a perfect 1.0. `method` carries the caveat into the
//! serialized report.

use super::nlp::{
    extract_content_words, extract_numerical_entities, extract_proper_nouns, split_sentences,
};
use super::types::{HallucinationDetail, RagTriadScore};

/// What the numeric scores actually are, recorded next to them so the label cannot be mistaken
/// for an embedding-based or LLM-judged RAG metric.
pub const RAG_METHOD: &str = "stopword-filtered token/number/entity overlap, no embedding model";

/// Evaluates RAG Quality Triad:
/// 1. Context Relevance: overlap and density of query concepts in retrieved context passages.
/// 2. Faithfulness: verifies claim-by-claim that facts, numbers, and entities in response exist in context.
/// 3. Answer Relevance: verifies the response answers the query without topic drift or evasiveness.
pub fn evaluate_rag_triad(
    query: &str,
    context: Option<&str>,
    response: &str,
    expected: Option<&str>,
) -> RagTriadScore {
    let query_words = extract_content_words(query);
    let resp_words = extract_content_words(response);

    // 1. Context Relevance - needs retrieved context *and* query terms; either one missing leaves
    //    the score with a zero denominator, which is not a measurement.
    let context_relevance = match context {
        Some(ctx) if !query_words.is_empty() => {
            let ctx_words = extract_content_words(ctx);
            let matched_query_terms = query_words
                .iter()
                .filter(|w| ctx_words.contains(*w))
                .count();
            let query_coverage = matched_query_terms as f64 / query_words.len() as f64;

            // Sentence density
            let ctx_sentences = split_sentences(ctx);
            let relevant_sentences = ctx_sentences
                .iter()
                .filter(|s| {
                    let sw = extract_content_words(s);
                    query_words.iter().any(|qw| sw.contains(qw))
                })
                .count();
            let density = if ctx_sentences.is_empty() {
                query_coverage
            } else {
                (relevant_sentences as f64 / ctx_sentences.len() as f64).min(1.0)
            };

            Some((0.70 * query_coverage + 0.30 * density).clamp(0.0, 1.0))
        }
        _ => None,
    };

    // 2. Faithfulness / Hallucination Detection. Grounding needs retrieved context, and a claim
    //    needs at least one sentence with content words in the answer.
    let mut hallucinations = Vec::new();
    let faithfulness = if let Some(ctx) = context {
        let ctx_words = extract_content_words(ctx);
        let ctx_numbers = extract_numerical_entities(ctx);
        let ctx_nouns = extract_proper_nouns(ctx);
        let ctx_lower = ctx.to_ascii_lowercase();

        let resp_sentences = split_sentences(response);
        let mut supported_sentences = 0;
        let mut evaluated_sentences = 0;

        for s in &resp_sentences {
            let s_words = extract_content_words(s);
            if s_words.is_empty() {
                continue;
            }
            evaluated_sentences += 1;

            let s_numbers = extract_numerical_entities(s);
            let s_nouns = extract_proper_nouns(s);

            let mut ungrounded = Vec::new();

            // Check numbers / quantities asserted in sentence
            for num in &s_numbers {
                if !ctx_numbers.contains(num) && !ctx_lower.contains(num) {
                    ungrounded.push(format!("numerical entity '{num}'"));
                }
            }

            // Check named proper entities asserted in sentence
            for noun in &s_nouns {
                if !ctx_nouns.contains(noun) && !ctx_lower.contains(noun) {
                    ungrounded.push(format!("entity '{noun}'"));
                }
            }

            // Check general keyword overlap: at least 30% of content words should exist in context
            let matched_words = s_words.iter().filter(|w| ctx_words.contains(*w)).count();
            let overlap_ratio = matched_words as f64 / s_words.len() as f64;

            if !ungrounded.is_empty() {
                hallucinations.push(HallucinationDetail {
                    claim: s.clone(),
                    reason: "Sentence asserts numbers or entities not present in retrieved context"
                        .into(),
                    ungrounded_terms: ungrounded,
                });
            } else if overlap_ratio < 0.25 && s_words.len() >= 4 {
                hallucinations.push(HallucinationDetail {
                    claim: s.clone(),
                    reason: format!(
                        "Low lexical support ({:.0}% overlap with context)",
                        overlap_ratio * 100.0
                    ),
                    ungrounded_terms: vec!["unsupported claim".into()],
                });
            } else {
                supported_sentences += 1;
            }
        }

        if evaluated_sentences == 0 {
            None // no claim in the answer could be checked against the context
        } else {
            Some((supported_sentences as f64 / evaluated_sentences as f64).clamp(0.0, 1.0))
        }
    } else {
        None
    };

    // 3. Answer Relevance
    let evasive_patterns = &[
        "i don't know",
        "i do not know",
        "i am unable to answer",
        "i cannot answer",
        "no information provided",
        "as an ai",
        "not mentioned in the context",
    ];
    let resp_lower = response.to_ascii_lowercase();
    let is_evasive = evasive_patterns.iter().any(|p| resp_lower.contains(p));

    // An empty query and an empty expected answer leave nothing to compare against, so the
    // score is not measured; a blank response, by contrast, is measurable and simply irrelevant.
    let mut answer_relevance = if response.trim().is_empty() {
        Some(0.0)
    } else {
        let term_overlap = (!query_words.is_empty()).then(|| {
            let matched = query_words
                .iter()
                .filter(|w| resp_words.contains(*w))
                .count();
            (matched as f64 / query_words.len() as f64).min(1.0)
        });
        let expected_overlap = expected.and_then(|exp| {
            let exp_words = extract_content_words(exp);
            (!exp_words.is_empty()).then(|| {
                let matched = exp_words.iter().filter(|w| resp_words.contains(*w)).count();
                (matched as f64 / exp_words.len() as f64).min(1.0)
            })
        });
        weighted_mean(&[(0.50, term_overlap), (0.50, expected_overlap)])
    };
    if is_evasive && context.is_some() {
        answer_relevance = answer_relevance.map(|v| (v * 0.40).clamp(0.0, 1.0));
    }

    // Composite RAG score: weighted mean over the metrics that were actually measured.
    let composite_score = weighted_mean(&[
        (0.40, faithfulness),
        (0.35, answer_relevance),
        (0.25, context_relevance),
    ]);

    let mut not_evaluated = Vec::new();
    for (name, value) in [
        ("context_relevance", context_relevance),
        ("faithfulness", faithfulness),
        ("answer_relevance", answer_relevance),
    ] {
        if value.is_none() {
            not_evaluated.push(name.to_string());
        }
    }

    RagTriadScore {
        context_relevance,
        faithfulness,
        answer_relevance,
        composite_score,
        hallucination_count: hallucinations.len(),
        hallucinations,
        not_evaluated,
        method: RAG_METHOD.to_string(),
    }
}

/// Weighted mean over the measurements that exist; `None` when none of them do.
fn weighted_mean(parts: &[(f64, Option<f64>)]) -> Option<f64> {
    let mut total = 0.0;
    let mut weight_sum = 0.0;
    for (weight, value) in parts {
        if let Some(v) = value {
            total += weight * v;
            weight_sum += weight;
        }
    }
    if weight_sum > 0.0 {
        Some((total / weight_sum).clamp(0.0, 1.0))
    } else {
        None
    }
}
