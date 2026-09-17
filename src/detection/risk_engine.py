"""
Hybrid Risk Engine

Combines multiple threat signals into a single risk score (0-100) and verdict.

Signals:
- Rule engine score (0-100)
- ML probability (0-1)
- IP intelligence score (0-100)
- Domain intelligence score (0-100)
- Threat intelligence score (0-100)

Design principles:
- Weights are CONFIGURABLE STARTING POINTS — they must be tuned on validation data
- Missing signals are handled gracefully (weights renormalized)
- Every decision includes a breakdown so analysts can audit
- Verdicts are stratified: BENIGN / SUSPICIOUS / HIGH_RISK / MALICIOUS
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, List
from loguru import logger


# ============================================
# CONFIGURATION
# ============================================
# ⚠️ IMPORTANT: These weights are heuristic starting points.
# They should be tuned via cross-validation on labelled data.
# The current values reflect domain intuition: ML and rules dominate,
# intelligence signals supplement.
# ============================================

DEFAULT_WEIGHTS = {
    'rule_score':     0.25,
    'ml_score':       0.35,
    'ip_score':       0.20,
    'domain_score':   0.10,
    'threat_score':   0.10,
}

# Verdict thresholds (0-100)
DEFAULT_THRESHOLDS = {
    'benign':     30,
    'suspicious': 60,
    'high_risk':  80,
    # > 80 = MALICIOUS
}

# Minimum signal weight — if a signal is missing, its weight
# is redistributed proportionally among the remaining signals
MIN_SIGNAL_WEIGHT = 0.0


# ============================================
# DATA CLASSES
# ============================================

@dataclass
class RiskInput:
    """Input to the Risk Engine — all values normalized to 0-100 scale"""
    rule_score: Optional[float] = None       # 0-100
    ml_probability: Optional[float] = None   # 0-1 (will be scaled)
    ip_score: Optional[float] = None         # 0-100
    domain_score: Optional[float] = None     # 0-100
    threat_score: Optional[float] = None     # 0-100

    def to_dict(self):
        return {
            'rule_score': self.rule_score,
            'ml_probability': self.ml_probability,
            'ip_score': self.ip_score,
            'domain_score': self.domain_score,
            'threat_score': self.threat_score,
        }


@dataclass
class RiskVerdict:
    """Output from the Risk Engine"""
    risk_score: float                         # 0-100
    verdict: str                              # BENIGN | SUSPICIOUS | HIGH_RISK | MALICIOUS
    confidence: float                         # 0-1
    contributions: Dict[str, float] = field(default_factory=dict)
    weights_used: Dict[str, float] = field(default_factory=dict)
    missing_signals: List[str] = field(default_factory=list)
    explanation: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            'risk_score': round(self.risk_score, 2),
            'verdict': self.verdict,
            'confidence': round(self.confidence, 4),
            'contributions': {k: round(v, 2) for k, v in self.contributions.items()},
            'weights_used': {k: round(v, 4) for k, v in self.weights_used.items()},
            'missing_signals': self.missing_signals,
            'explanation': self.explanation,
        }


# ============================================
# RISK ENGINE
# ============================================

class RiskEngine:
    """Hybrid risk scoring engine"""

    def __init__(self, weights=None, thresholds=None):
        """
        Args:
            weights: Optional custom weights (must sum to 1.0)
            thresholds: Optional custom thresholds
        """
        self.weights = self._validate_weights(weights or DEFAULT_WEIGHTS)
        self.thresholds = thresholds or DEFAULT_THRESHOLDS

    # ============================================
    # PUBLIC
    # ============================================

    def compute(self, risk_input: RiskInput) -> RiskVerdict:
        """
        Compute the final risk score and verdict.

        Handles missing signals by renormalizing weights.
        """
        # 1. Normalize all inputs to 0-100
        normalized = self._normalize_inputs(risk_input)

        # 2. Determine which signals are present
        present_signals = {
            k: v for k, v in normalized.items() if v is not None
        }
        missing_signals = [
            k for k, v in normalized.items() if v is None
        ]

        if not present_signals:
            logger.warning("Risk engine called with no valid signals")
            return RiskVerdict(
                risk_score=0.0,
                verdict='UNKNOWN',
                confidence=0.0,
                missing_signals=missing_signals,
                explanation=["No signals available to score"]
            )

        # 3. Renormalize weights for present signals
        adjusted_weights = self._renormalize_weights(
            present_signals.keys(),
            missing_signals
        )

        # 4. Compute weighted sum
        contributions = {}
        final_score = 0.0

        for signal, value in present_signals.items():
            weight = adjusted_weights.get(signal, 0.0)
            contribution = weight * value
            contributions[signal] = contribution
            final_score += contribution

        final_score = max(0.0, min(100.0, final_score))

        # 5. Determine verdict
        verdict = self._determine_verdict(final_score)

        # 6. Compute confidence
        confidence = self._compute_confidence(
            final_score, present_signals, missing_signals
        )

        # 7. Build explanation
        explanation = self._build_explanation(
            final_score, verdict, contributions, adjusted_weights, missing_signals
        )

        return RiskVerdict(
            risk_score=final_score,
            verdict=verdict,
            confidence=confidence,
            contributions=contributions,
            weights_used=adjusted_weights,
            missing_signals=missing_signals,
            explanation=explanation
        )

    # ============================================
    # NORMALIZATION
    # ============================================

    def _normalize_inputs(self, ri: RiskInput) -> dict:
        """
        Normalize all inputs to 0-100 scale.
        Returns dict with None for missing/unavailable signals.
        """
        result = {
            'rule_score':    self._clip(ri.rule_score, 0, 100),
            'ml_score':      self._scale_ml(ri.ml_probability),
            'ip_score':      self._clip(ri.ip_score, 0, 100),
            'domain_score':  self._clip(ri.domain_score, 0, 100),
            'threat_score':  self._clip(ri.threat_score, 0, 100),
        }
        return result

    @staticmethod
    def _clip(value, lo, hi):
        """Return None if value is None, otherwise clip to range"""
        if value is None:
            return None
        try:
            return max(lo, min(hi, float(value)))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _scale_ml(probability):
        """Convert ML probability (0-1) to 0-100 scale"""
        if probability is None:
            return None
        try:
            p = float(probability)
            # Clip to [0, 1]
            p = max(0.0, min(1.0, p))
            return p * 100.0
        except (TypeError, ValueError):
            return None

    # ============================================
    # WEIGHT HANDLING
    # ============================================

    @staticmethod
    def _validate_weights(weights: dict) -> dict:
        """Ensure weights are valid and sum to 1.0"""
        required_keys = {'rule_score', 'ml_score', 'ip_score', 'domain_score', 'threat_score'}

        # Check all keys present
        missing = required_keys - set(weights.keys())
        if missing:
            raise ValueError(f"Missing weights for: {missing}")

        total = sum(weights.values())
        if not (0.99 <= total <= 1.01):
            logger.warning(f"Weights sum to {total:.4f}, not 1.0 — normalizing")
            weights = {k: v / total for k, v in weights.items()}

        return weights

    def _renormalize_weights(self, present_keys, missing_keys) -> dict:
        """
        If some signals are missing, redistribute their weights
        proportionally to the remaining signals.
        """
        adjusted = {}
        total_remaining = sum(
            self.weights[k] for k in present_keys
        )

        if total_remaining == 0:
            # Fallback: equal weights
            equal = 1.0 / len(present_keys) if present_keys else 0
            return {k: equal for k in present_keys}

        for k in present_keys:
            adjusted[k] = self.weights[k] / total_remaining

        # Missing signals get 0
        for k in missing_keys:
            adjusted[k] = 0.0

        return adjusted

    # ============================================
    # VERDICT
    # ============================================

    def _determine_verdict(self, score: float) -> str:
        """Map risk score to verdict"""
        if score < self.thresholds['benign']:
            return 'BENIGN'
        elif score < self.thresholds['suspicious']:
            return 'SUSPICIOUS'
        elif score < self.thresholds['high_risk']:
            return 'HIGH_RISK'
        else:
            return 'MALICIOUS'

    def _compute_confidence(self, score, present_signals, missing_signals) -> float:
        """
        Confidence is based on:
        1. Signal availability (more signals = higher confidence)
        2. Distance from thresholds (further = more confident)
        """
        # Signal availability factor (0-1)
        total_signals = len(self.weights)
        availability = len(present_signals) / total_signals if total_signals else 0

        # Distance from nearest threshold
        thresholds = sorted(self.thresholds.values())
        min_distance = min(abs(score - t) for t in thresholds + [0, 100])
        # Normalize: 0 at threshold, 1 at max distance (20 points away)
        distance_factor = min(min_distance / 20.0, 1.0)

        # Combined confidence
        confidence = (availability * 0.5) + (distance_factor * 0.5)

        return round(confidence, 4)

    # ============================================
    # EXPLANATION
    # ============================================

    def _build_explanation(self, score, verdict, contributions, weights, missing):
        """Build human-readable explanation"""
        lines = []

        # Header
        lines.append(f"Risk score: {score:.1f}/100 → {verdict}")

        # Top contributing signals
        sorted_signals = sorted(
            [(k, v) for k, v in contributions.items() if v > 0],
            key=lambda x: x[1],
            reverse=True
        )

        if sorted_signals:
            lines.append("Top contributing signals:")
            for signal, contribution in sorted_signals[:5]:
                weight = weights.get(signal, 0)
                lines.append(
                    f"  • {signal}: {contribution:.1f} pts "
                    f"(weight {weight:.2f})"
                )

        # Missing signals
        if missing:
            lines.append(f"Missing signals: {', '.join(missing)}")

        return lines

    # ============================================
    # UTILITIES
    # ============================================

    def set_weights(self, weights: dict):
        """Update weights at runtime"""
        self.weights = self._validate_weights(weights)
        logger.info(f"Risk engine weights updated: {self.weights}")

    def set_thresholds(self, thresholds: dict):
        """Update thresholds at runtime"""
        self.thresholds = thresholds
        logger.info(f"Risk engine thresholds updated: {self.thresholds}")


# ============================================
# CONVENIENCE FUNCTION
# ============================================

def compute_risk(
    rule_score=None,
    ml_probability=None,
    ip_score=None,
    domain_score=None,
    threat_score=None,
    weights=None,
) -> dict:
    """
    Quick one-shot risk computation.

    Returns: dict (see RiskVerdict.to_dict)
    """
    engine = RiskEngine(weights=weights)
    ri = RiskInput(
        rule_score=rule_score,
        ml_probability=ml_probability,
        ip_score=ip_score,
        domain_score=domain_score,
        threat_score=threat_score,
    )
    return engine.compute(ri).to_dict()


# ============================================
# SELF-TEST
# ============================================

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("HYBRID RISK ENGINE — SELF TEST")
    print("=" * 70)

    engine = RiskEngine()

    test_cases = [
        {
            'name': 'Clearly benign (Google)',
            'input': RiskInput(
                rule_score=2,
                ml_probability=0.02,
                ip_score=0,
                domain_score=0,
                threat_score=0,
            )
        },
        {
            'name': 'Clearly malicious phishing',
            'input': RiskInput(
                rule_score=85,
                ml_probability=0.95,
                ip_score=75,
                domain_score=90,
                threat_score=100,
            )
        },
        {
            'name': 'Suspicious — mixed signals',
            'input': RiskInput(
                rule_score=45,
                ml_probability=0.55,
                ip_score=30,
                domain_score=50,
                threat_score=20,
            )
        },
        {
            'name': 'High risk — new domain + bad IP',
            'input': RiskInput(
                rule_score=70,
                ml_probability=0.80,
                ip_score=85,
                domain_score=75,
                threat_score=60,
            )
        },
        {
            'name': 'Missing IP signal',
            'input': RiskInput(
                rule_score=80,
                ml_probability=0.90,
                ip_score=None,     # missing
                domain_score=70,
                threat_score=50,
            )
        },
        {
            'name': 'Only ML available',
            'input': RiskInput(
                ml_probability=0.92,
            )
        },
    ]

    for tc in test_cases:
        print(f"\n{'─' * 70}")
        print(f"📋 {tc['name']}")
        print(f"{'─' * 70}")

        verdict = engine.compute(tc['input'])
        result = verdict.to_dict()

        print(f"  Risk Score:  {result['risk_score']}/100")
        print(f"  Verdict:     {result['verdict']}")
        print(f"  Confidence:  {result['confidence']:.2%}")

        if result['missing_signals']:
            print(f"  Missing:     {', '.join(result['missing_signals'])}")

        print(f"  Contributions:")
        for signal, contrib in sorted(
            result['contributions'].items(),
            key=lambda x: x[1],
            reverse=True
        ):
            if contrib > 0:
                print(f"    • {signal:<16} → {contrib:>6.2f} pts")

    print("\n" + "=" * 70)
    print("✅ Risk engine test complete")
    print("=" * 70 + "\n")