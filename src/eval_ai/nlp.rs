//! Deterministic NLP tokenization and entity extraction heuristics.

use std::collections::HashSet;

const STOP_WORDS: &[&str] = &[
    "a", "an", "the", "and", "or", "in", "on", "at", "to", "for", "with", "is", "was", "are",
    "were", "be", "been", "being", "have", "has", "had", "do", "does", "did", "of", "by", "that",
    "this", "it", "as", "from", "can", "could", "will", "would", "should", "about", "what",
    "which", "who", "whom", "where", "when", "why", "how", "i", "you", "he", "she", "they", "we",
    "my", "your", "their", "our", "its", "me", "him", "her", "us", "them", "not", "no", "but",
    "if", "then", "else", "so", "than", "too", "very", "just", "into", "also", "any", "some",
];

pub fn is_stop_word(w: &str) -> bool {
    STOP_WORDS.contains(&w.to_ascii_lowercase().as_str())
}

/// Tokenize text into lowercased content words (length >= 2, non-stopwords).
pub fn extract_content_words(text: &str) -> HashSet<String> {
    text.split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
        .filter(|w| w.len() >= 2 && !is_stop_word(w))
        .map(|w| w.to_ascii_lowercase())
        .collect()
}

/// Extract numbers, currency amounts, percentages, and dates from text.
pub fn extract_numerical_entities(text: &str) -> HashSet<String> {
    let mut entities = HashSet::new();
    for token in text.split_whitespace() {
        let clean = token.trim_matches(|c: char| !c.is_alphanumeric() && c != '$' && c != '%');
        if clean.is_empty() {
            continue;
        }
        // Has a digit or currency symbol
        if clean.chars().any(|c| c.is_ascii_digit()) || clean.starts_with('$') {
            entities.insert(clean.to_ascii_lowercase());
        }
    }
    entities
}

/// Extract capitalized proper noun candidates (excluding sentence starters if common).
pub fn extract_proper_nouns(text: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    for sentence in split_sentences(text) {
        let mut words = sentence.split_whitespace();
        let _first = words.next(); // skip first word of sentence to reduce title-case noise
        for w in words {
            let clean = w.trim_matches(|c: char| !c.is_alphanumeric());
            if clean.len() >= 3
                && clean.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
                && !is_stop_word(clean)
            {
                set.insert(clean.to_ascii_lowercase());
            }
        }
    }
    set
}

/// Split text into sentences by punctuation and newlines.
pub fn split_sentences(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        for c in line.chars() {
            cur.push(c);
            if c == '.' || c == '?' || c == '!' {
                let trimmed = cur.trim().to_string();
                if !trimmed.is_empty() {
                    out.push(trimmed);
                }
                cur.clear();
            }
        }
        let trimmed = cur.trim().to_string();
        if !trimmed.is_empty() {
            out.push(trimmed);
        }
        cur.clear();
    }
    out
}
