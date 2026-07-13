#!/usr/bin/env python3
"""Tests for the statistical scoring & ablation framework (scoring.py)."""

import math

from scoring import AblationStudy, EnsembleScorer, LayerSignal, sigmoid


def _signal(layer, high=0, medium=0, low=0, raw=0.0):
    return LayerSignal(layer=layer, severity_counts={"HIGH": high, "MEDIUM": medium, "LOW": low}, raw_score=raw)


def test_sigmoid_bounds():
    assert 0.0 <= sigmoid(-5) < 0.5 < sigmoid(5) <= 1.0
    assert abs(sigmoid(0) - 0.5) < 1e-9


def test_sigmoid_numerically_stable_large_negative():
    # Overflow would raise; stable sigmoid returns a tiny positive value.
    assert 0.0 < sigmoid(-1000) < 1e-100


def test_layer_signal_weighting():
    s = _signal("injection", high=1, medium=1, low=1)
    # HIGH*3 + MEDIUM*2 + LOW*1 + raw
    assert s.signal == 6.0
    assert _signal("x").signal == 0.0


def test_ensemble_scorer_safe_when_no_signals():
    scorer = EnsembleScorer()
    res = scorer.score_document("doc.txt", [_signal("injection")])
    assert res.risk_score == 0.5  # bias 0 => sigmoid(0)
    assert res.decision == "SAFE"
    assert not res.is_flagged


def test_ensemble_scorer_malicious_high_severity():
    scorer = EnsembleScorer(threshold=0.5)
    res = scorer.score_document("doc.txt", [_signal("injection", high=3)])
    assert res.risk_score >= 0.8
    assert res.decision == "MALICIOUS"
    assert "injection" in res.triggered_layers


def test_ensemble_scorer_weight_influence():
    clean = [_signal("quality", low=1)]
    heavy = EnsembleScorer(weights={"quality": 3.0})
    light = EnsembleScorer(weights={"quality": 0.1})
    rh = heavy.score_document("d", clean).risk_score
    rl = light.score_document("d", clean).risk_score
    assert rh > rl


def test_ensemble_scorer_corpus():
    corpus = [
        {"name": "a.txt", "signals": [_signal("injection", high=2)]},
        {"name": "b.txt", "signals": [_signal("quality", low=0)]},
    ]
    results = EnsembleScorer().score_corpus(corpus)
    assert len(results) == 2
    assert results[0].risk_score > results[1].risk_score


def test_ablation_removes_layer_contribution():
    corpus = [{"name": "a.txt", "signals": [_signal("injection", high=1)]}]
    scorer = EnsembleScorer()
    study = AblationStudy(scorer)
    out = study.run(corpus)
    assert out["baseline_flagged"] >= 1
    # Removing the only triggered layer must reduce flagged count to 0.
    inj = out["layers"].get("injection")
    assert inj is not None
    assert inj["flagged_docs"] == 0
    assert inj["flagged_delta"] == out["baseline_flagged"]


def test_ablation_ranking_present():
    corpus = [
        {"name": "a.txt", "signals": [_signal("injection", high=1), _signal("obfuscation", medium=1)]},
    ]
    out = AblationStudy(EnsembleScorer()).run(corpus)
    assert set(out["ranking"]) == {"injection", "obfuscation"}
    assert out["ranking"][0] in {"injection", "obfuscation"}


def test_ablation_contribution_pct_zero_baseline():
    # No layers triggered => no flagged baseline => 0% contributions.
    corpus = [{"name": "a.txt", "signals": [_signal("quality", low=0)]}]
    out = AblationStudy(EnsembleScorer()).run(corpus)
    for info in out["layers"].values():
        assert info["contribution_pct"] == 0.0
