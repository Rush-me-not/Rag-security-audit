#!/usr/bin/env python3
"""Tests for information-theoretic & similarity-based detection (info_theory.py)."""

import math

from info_theory import (
    character_uniformity,
    compression_ratio,
    cosine_similarity,
    detect_corpus_outliers,
    detect_near_duplicates,
    jaccard_similarity,
    ngram_surprisal,
    shannon_entropy,
    tokenize,
)


# --- Information-theoretic ---------------------------------------------------

def test_shannon_entropy_empty():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_uniform_max():
    # All-distinct characters maximize entropy (log2 of length).
    s = "abcdef"
    assert abs(shannon_entropy(s) - math.log2(len(s))) < 1e-9


def test_shannon_entropy_repeated_low():
    # A single repeated char has zero entropy.
    assert shannon_entropy("aaaaaa") == 0.0


def test_compression_ratio_empty_is_one():
    assert compression_ratio("") == 1.0


def test_compression_ratio_repetitive_low():
    # Highly repetitive text compresses well => low ratio.
    ratio = compression_ratio("payload payload payload " * 50)
    assert ratio < 0.5


def test_character_uniformity_bounds():
    assert 0.0 <= character_uniformity("abc") <= 1.0
    assert character_uniformity("") == 0.0
    assert character_uniformity("a") == 0.0


def test_character_uniformity_uniform_high():
    # Many distinct chars => high uniformity score.
    assert character_uniformity("abcdefghijklmnop") > 0.9


def test_ngram_surprisal_short():
    assert ngram_surprisal("a", n=2) == 0.0


def test_ngram_surprisal_repetitive_low():
    # Repeated bigrams are predictable => low surprisal.
    assert ngram_surprisal("abababababab") < ngram_surprisal("qwkzmvn")


# --- Similarity --------------------------------------------------------------

def test_tokenize_lowercase():
    assert tokenize("Hello, World!") == ["hello", "world"]


def test_cosine_identical_is_one():
    toks = tokenize("the quick brown fox")
    assert abs(cosine_similarity(toks, toks) - 1.0) < 1e-9


def test_cosine_disjoint_is_zero():
    assert cosine_similarity(tokenize("apple banana"), tokenize("zebra yoga")) == 0.0


def test_jaccard_identical_is_one():
    a = tokenize("the cat sat")
    assert abs(jaccard_similarity(a, a) - 1.0) < 1e-9


def test_jaccard_disjoint_is_zero():
    assert jaccard_similarity(tokenize("dog"), tokenize("cat")) == 0.0


def test_detect_near_duplicates_finds_pair():
    docs = [
        {"name": "a", "content": "refund policy password reset vpn security"},
        {"name": "b", "content": "refund policy password reset vpn security"},
        {"name": "c", "content": "completely unrelated topic about gardening tomatoes"},
    ]
    pairs = detect_near_duplicates(docs, threshold=0.85)
    assert (0, 1, pairs[0][2]) in [(0, 1, s) for s in [p[2] for p in pairs]]
    assert all((i, j) != (0, 2) and (i, j) != (1, 2) for i, j, _ in pairs)


def test_detect_corpus_outliers():
    docs = [
        {"name": "a", "content": "security policy password reset vpn firewall"},
        {"name": "b", "content": "security policy password reset vpn firewall"},
        {"name": "c", "content": "recipe for banana bread with cinnamon sugar flour"},
    ]
    outliers = detect_corpus_outliers(docs, threshold=0.25)
    idxs = [i for i, _ in outliers]
    assert 2 in idxs  # the off-topic doc is the outlier


def test_detect_corpus_outliers_short_corpus():
    # A single document can never have a dissimilar peer.
    docs = [{"name": "a", "content": "x y z"}]
    assert detect_corpus_outliers(docs, threshold=0.25) == []
