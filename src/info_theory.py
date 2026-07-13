#!/usr/bin/env python3
"""
Information-Theoretic & Similarity-Based Detection
==================================================
Detection layers for the RAG Security Audit tool that do not rely on regex
pattern matching:

  Information-theoretic:
    - Shannon entropy (identifies high-entropy payloads / random padding)
    - Compression ratio via zlib (low ratio => repetitive / injected blocks)
    - Character-distribution uniformity (benford-style anomaly scoring)
    - n-gram surprisal (unexpected token transitions)

  Similarity-based:
    - Cosine similarity (bag-of-words TF vectors)
    - Jaccard similarity (token-set overlap)
    - Near-duplicate detection (cluster docs that are > threshold similar)
    - Corpus outlier detection (document dissimilar to all others)

All features operate on plain strings / token lists so they are unit-testable
without touching the filesystem.
"""

import math
import zlib
from collections import Counter

# Characters whose per-character Shannon entropy is treated as noise floor.
_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,;:!?'\n\t"


def tokenize(text: str) -> list[str]:
    """Tokenize text into lowercase word tokens."""
    return __import__("re").findall(r"\w+", text.lower())


def shannon_entropy(text: str) -> float:
    """Shannon entropy (bits/char) of a string. Empty string => 0.0."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def compression_ratio(text: str) -> float:
    """zlib compression ratio (compressed_bytes / raw_bytes).

    Low ratio (< ~0.3) suggests highly repetitive / low-information content
    (a tell of padded or templated injection payloads). 1.0 for empty input.
    """
    if not text:
        return 1.0
    compressed = zlib.compress(text.encode("utf-8"), level=9)
    return len(compressed) / len(text.encode("utf-8"))


def character_uniformity(text: str) -> float:
    """Chi-square-style uniformity score in [0, 1].

    1.0 means a perfectly uniform character distribution (random/encoded
    content), 0.0 means all characters identical. Computed over the full
    byte alphabet seen in the text.
    """
    if not text:
        return 0.0
    n = len(text)
    counts = Counter(text)
    k = len(counts)
    if k <= 1:
        return 0.0
    expected = n / k
    chi = sum((c - expected) ** 2 / expected for c in counts.values())
    # Max chi-square for n chars spread over k buckets.
    max_chi = (n - expected) ** 2 / expected + (k - 1) * (0 - expected) ** 2 / expected
    if max_chi == 0:
        return 0.0
    return max(0.0, min(1.0, 1.0 - chi / max_chi))


def ngram_surprisal(text: str, n: int = 2) -> float:
    """Mean negative log-probability of character n-grams (bits).

    Higher surprisal => less predictable / more anomalous character sequence.
    Returns 0.0 for text shorter than n.
    """
    if len(text) < n:
        return 0.0
    grams = [text[i:i + n] for i in range(len(text) - n + 1)]
    counts = Counter(grams)
    total = len(grams)
    # Add-1 smoothing to avoid log(0).
    vocab = len(counts)
    surprisal = 0.0
    for c in counts.values():
        p = (c + 1) / (total + vocab)
        surprisal += c * (-math.log2(p))
    return surprisal / total


# --- Similarity helpers ------------------------------------------------------

def _tf_vector(tokens: list[str]) -> dict[str, float]:
    """Term-frequency vector from a token list."""
    counts = Counter(tokens)
    total = sum(counts.values()) or 1
    return {t: c / total for t, c in counts.items()}


def cosine_similarity(a: list[str], b: list[str]) -> float:
    """Cosine similarity between two token lists in [0, 1]."""
    va, vb = _tf_vector(a), _tf_vector(b)
    common = set(va) & set(vb)
    if not common:
        return 0.0
    dot = sum(va[k] * vb[k] for k in common)
    na = math.sqrt(sum(v * v for v in va.values()))
    nb = math.sqrt(sum(v * v for v in vb.values()))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def jaccard_similarity(a: list[str], b: list[str]) -> float:
    """Jaccard similarity between two token sets in [0, 1]."""
    set_a, set_b = set(a), set(b)
    union = set_a | set_b
    if not union:
        return 0.0
    return len(set_a & set_b) / len(union)


def detect_near_duplicates(docs: list[dict], threshold: float = 0.85,
                           metric: str = "cosine") -> list[tuple[int, int, float]]:
    """Find near-duplicate document pairs exceeding a similarity threshold.

    Args:
        docs: list of {"name", "content"} dicts.
        threshold: minimum similarity to report a pair.
        metric: "cosine" or "jaccard".

    Returns:
        list of (i, j, similarity) tuples for i < j.
    """
    sim_fn = cosine_similarity if metric == "cosine" else jaccard_similarity
    pairs = []
    tokenized = [tokenize(d["content"]) for d in docs]
    for i in range(len(docs)):
        for j in range(i + 1, len(docs)):
            sim = sim_fn(tokenized[i], tokenized[j])
            if sim >= threshold:
                pairs.append((i, j, round(sim, 4)))
    return pairs


def detect_corpus_outliers(docs: list[dict], threshold: float = 0.25,
                           metric: str = "cosine") -> list[tuple[int, float]]:
    """Detect documents dissimilar to the rest of the corpus.

    A doc is an outlier when its *maximum* similarity to any other doc is
    below ``threshold`` (i.e. it shares little content with the corpus).

    Returns:
        list of (index, max_similarity) tuples for outlier docs.
    """
    sim_fn = cosine_similarity if metric == "cosine" else jaccard_similarity
    tokenized = [tokenize(d["content"]) for d in docs]
    outliers = []
    for i in range(len(docs)):
        best = 0.0
        for j in range(len(docs)):
            if i == j:
                continue
            sim = sim_fn(tokenized[i], tokenized[j])
            if sim > best:
                best = sim
        if best < threshold:
            outliers.append((i, round(best, 4)))
    return outliers
