#!/usr/bin/env python3
"""
Statistical Risk Scoring & Ablation Study Framework
===================================================
Combines the individual detection layers (injection regex, obfuscation,
structural, content-quality, info-theoretic, similarity) into a single
calibrated risk score per document.

Components:
  - ``sigmoid`` — maps a raw evidence logit into a [0, 1] probability.
  - ``EnsembleScorer`` — weighted ensemble of detection layers using
    per-layer weights, producing a calibrated risk score.
  - ``AblationStudy`` — measures how much each layer contributes by
    disabling it and recomputing scores (drop in AUC / detection rate).
"""

import math
from dataclasses import dataclass, field
from typing import Callable, Optional


def sigmoid(x: float) -> float:
    """Numerically stable logistic sigmoid in [0, 1]."""
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


# Default layer weights for the ensemble. Tunable via CLI / ablation.
DEFAULT_WEIGHTS: dict[str, float] = {
    "injection": 1.0,
    "obfuscation": 0.9,
    "structural": 0.7,
    "quality": 0.6,
    "info_theory": 0.8,
    "similarity": 0.5,
}


@dataclass
class LayerSignal:
    """Raw signal emitted by one detection layer for one document."""
    layer: str
    severity_counts: dict[str, int] = field(default_factory=dict)
    raw_score: float = 0.0

    @property
    def signal(self) -> float:
        """Convert severity counts + raw score into a single logit-like value.

        HIGH=3, MEDIUM=2, LOW=1 weighted contribution, plus the raw_score.
        """
        sev = self.severity_counts or {}
        weighted = sev.get("HIGH", 0) * 3 + sev.get("MEDIUM", 0) * 2 + sev.get("LOW", 0) * 1
        return weighted + self.raw_score


@dataclass
class RiskResult:
    """Per-document ensemble risk result."""
    doc_name: str
    risk_score: float
    layer_scores: dict[str, float] = field(default_factory=dict)
    triggered_layers: list[str] = field(default_factory=list)
    decision: str = "SAFE"

    @property
    def is_flagged(self) -> bool:
        return self.decision != "SAFE"


class EnsembleScorer:
    """Weighted ensemble that fuses detection-layer signals into a risk score.

    For each document, every layer contributes a logit ``w_l * signal_l``.
    The summed logit passes through a sigmoid to yield the final risk in
    [0, 1]. A linear decision threshold (default 0.5) produces SAFE /
    SUSPICIOUS / MALICIOUS labels.
    """

    def __init__(self, weights: Optional[dict[str, float]] = None,
                 threshold: float = 0.5):
        self.weights = dict(DEFAULT_WEIGHTS)
        if weights:
            self.weights.update(weights)
        self.threshold = threshold
        # Learned bias (logit shift). 0 keeps sigmoid centered.
        self.bias: float = 0.0

    def score_document(self, doc_name: str, signals: list[LayerSignal]) -> RiskResult:
        """Compute the ensemble risk score for a single document."""
        logit = self.bias
        layer_scores: dict[str, float] = {}
        triggered: list[str] = []

        for sgn in signals:
            w = self.weights.get(sgn.layer, 1.0)
            contrib = w * sgn.signal
            layer_scores[sgn.layer] = round(sigmoid(contrib), 4)
            logit += contrib
            if sgn.signal > 0:
                triggered.append(sgn.layer)

        risk = sigmoid(logit)
        if risk >= 0.8:
            decision = "MALICIOUS"
        elif risk >= self.threshold:
            decision = "SUSPICIOUS"
        else:
            decision = "SAFE"

        return RiskResult(
            doc_name=doc_name,
            risk_score=round(risk, 4),
            layer_scores=layer_scores,
            triggered_layers=triggered,
            decision=decision,
        )

    def score_corpus(self, corpus: list[dict]) -> list[RiskResult]:
        """Score a corpus of {"name", "signals"} dicts."""
        return [self.score_document(d["name"], d["signals"]) for d in corpus]


class AblationStudy:
    """Measure each detection layer's contribution by disabling it.

    An ablation run scores the corpus with the full ensemble (baseline) and
    then with one layer removed at a time. The difference in flagged-document
    count and mean risk is the layer's ablation contribution.
    """

    def __init__(self, scorer: EnsembleScorer):
        self.scorer = scorer
        self.available_layers = list(scorer.weights.keys())

    @staticmethod
    def _flagged(results: list[RiskResult]) -> int:
        return sum(1 for r in results if r.is_flagged)

    @staticmethod
    def _mean_risk(results: list[RiskResult]) -> float:
        if not results:
            return 0.0
        return sum(r.risk_score for r in results) / len(results)

    def _reduced_scorer(self, disabled: str) -> EnsembleScorer:
        """Return a copy of the scorer with one layer's weight set to 0."""
        reduced_weights = {k: (0.0 if k == disabled else v)
                           for k, v in self.scorer.weights.items()}
        new_scorer = EnsembleScorer(reduced_weights, threshold=self.scorer.threshold)
        new_scorer.bias = self.scorer.bias
        return new_scorer

    def run(self, corpus: list[dict]) -> dict:
        """Run the ablation study over the corpus.

        Returns a dict with baseline results and per-layer ablation deltas.
        """
        baseline = self.scorer.score_corpus(corpus)
        baseline_flagged = self._flagged(baseline)
        baseline_risk = self._mean_risk(baseline)

        layers_ran = set()
        for doc in corpus:
            for sgn in doc["signals"]:
                layers_ran.add(sgn.layer)
        # Only ablate layers that are actually present in the corpus.
        layers = [l for l in self.available_layers if l in layers_ran]

        per_layer: dict[str, dict] = {}
        for layer in layers:
            reduced = self._reduced_scorer(layer).score_corpus(corpus)
            flagged = self._flagged(reduced)
            mean_risk = self._mean_risk(reduced)
            per_layer[layer] = {
                "flagged_docs": flagged,
                "mean_risk": round(mean_risk, 4),
                "flagged_delta": baseline_flagged - flagged,
                "mean_risk_delta": round(baseline_risk - mean_risk, 4),
                "contribution_pct": round(
                    (100.0 * (baseline_flagged - flagged) / baseline_flagged)
                    if baseline_flagged else 0.0, 2
                ),
            }

        return {
            "baseline_flagged": baseline_flagged,
            "baseline_mean_risk": round(baseline_risk, 4),
            "layers": per_layer,
            "ranking": sorted(
                per_layer.keys(),
                key=lambda l: per_layer[l]["flagged_delta"],
                reverse=True,
            ),
        }
