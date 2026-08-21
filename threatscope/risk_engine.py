"""
threatscope/risk_engine.py
===========================
Dynamic risk scoring engine for ThreatScope.

Produces a 0–100 risk score and a severity label
(Low / Medium / High / Critical) from multiple signal inputs.

Design principles
-----------------
  - All factor weights are configurable at the top of this file
  - The scoring formula is additive and fully transparent
  - No black-box risk logic; every component is traceable
  - Score breakdown is returned for dashboard display

Score components (max contributions)
--------------------------------------
  anomaly_component      max 20  — from IF anomaly score
  attack_type_component  max 35  — from XGBoost predicted class
  confidence_component   max 15  — from XGBoost class probability
  stage_component        max 15  — from current attack stage
  next_stage_component   max 15  — from predicted next stage severity

Total max = 100

Severity thresholds
-------------------
  0–24   Low
  25–49  Medium
  50–74  High
  75–100 Critical
"""

from typing import Optional


# ---------------------------------------------------------------------------
# Attack type base risk (0–35)
# ---------------------------------------------------------------------------

_ATTACK_TYPE_RISK = {
    "BENIGN":                      0,
    "PortScan":                    10,
    "FTP-Patator":                 20,
    "SSH-Patator":                 20,
    "Web Attack - Brute Force":    22,
    "Web Attack - XSS":            22,
    "Web Attack - SQL Injection":  28,
    "Heartbleed":                  30,
    "Bot":                         30,
    "Infiltration":                33,
    "DoS slowloris":               25,
    "DoS Slowhttptest":            25,
    "DoS GoldenEye":               28,
    "DoS Hulk":                    28,
    "DDoS":                        35,
}

# Fallback for unknown labels
_UNKNOWN_ATTACK_RISK = 20

# ---------------------------------------------------------------------------
# Attack stage risk (0–15)
# ---------------------------------------------------------------------------

_STAGE_RISK = {
    "NORMAL":               0,
    "RECONNAISSANCE":       5,
    "INITIAL_ACCESS":       8,
    "COMMAND_AND_CONTROL":  12,
    "LATERAL_MOVEMENT":     13,
    "IMPACT":               15,
}

# Next-stage risk contribution (0–15)
# Higher if the predicted next stage is severe
_NEXT_STAGE_RISK = {
    "NORMAL":               0,
    "RECONNAISSANCE":       3,
    "INITIAL_ACCESS":       6,
    "COMMAND_AND_CONTROL":  10,
    "LATERAL_MOVEMENT":     12,
    "IMPACT":               15,
}

# Severity thresholds
_THRESHOLDS = [
    (75, "Critical"),
    (50, "High"),
    (25, "Medium"),
    (0,  "Low"),
]


def _anomaly_component(anomaly_score: float) -> float:
    """
    Convert Isolation Forest decision_function score to 0–20 contribution.

    decision_function returns a real value:
      positive  = more normal
      negative  = more anomalous

    We negate and normalise to [0, 20].
    We clip to a reasonable observed range of [-0.5, 0.5].
    """
    # Negate (lower = more anomalous -> higher risk)
    inv = -anomaly_score
    # Clip to [-0.5, 0.5] range then scale to [0, 20]
    clamped = max(-0.5, min(0.5, inv))
    normalised = (clamped + 0.5) / 1.0  # -> [0, 1]
    return round(normalised * 20, 2)


def _confidence_component(confidence: float) -> float:
    """
    XGBoost classification confidence (0.0–1.0) -> 0–15 contribution.
    Higher confidence in an attack classification = higher risk.
    """
    return round(max(0.0, min(1.0, confidence)) * 15, 2)


def _severity_label(score: float) -> str:
    for threshold, label in _THRESHOLDS:
        if score >= threshold:
            return label
    return "Low"


def calculate(
    anomaly_score: float,
    attack_label: str,
    confidence: float,
    current_stage: str,
    next_stage: str,
) -> dict:
    """
    Calculate risk score and return a full breakdown.

    Parameters
    ----------
    anomaly_score : float
        Raw Isolation Forest decision_function output (negative = anomalous).
    attack_label : str
        XGBoost predicted class label (e.g. 'DDoS', 'BENIGN').
    confidence : float
        XGBoost max class probability [0.0–1.0].
    current_stage : str
        Attack stage from attack_chain.label_to_stage().
    next_stage : str
        Predicted next stage from attack_chain.predict().

    Returns
    -------
    dict
        {
            score        : int   (0–100, clamped),
            severity     : str   (Low / Medium / High / Critical),
            breakdown    : dict  (per-component scores),
            inputs       : dict  (the raw inputs for audit trail),
        }
    """
    # Compute components
    anom_c  = _anomaly_component(anomaly_score)
    atype_c = float(_ATTACK_TYPE_RISK.get(attack_label, _UNKNOWN_ATTACK_RISK))
    conf_c  = _confidence_component(confidence) if attack_label != "BENIGN" else 0.0
    stage_c = float(_STAGE_RISK.get(current_stage, 5))
    next_c  = float(_NEXT_STAGE_RISK.get(next_stage, 3))

    # Suppress risk components if BENIGN and low anomaly
    if attack_label == "BENIGN" and anomaly_score > 0:
        anom_c  = 0.0
        stage_c = 0.0
        next_c  = 0.0

    total = anom_c + atype_c + conf_c + stage_c + next_c
    total = max(0, min(100, round(total)))  # clamp to [0, 100]

    return {
        "score":    total,
        "severity": _severity_label(total),
        "breakdown": {
            "anomaly_score_component":  anom_c,
            "attack_type_component":    atype_c,
            "confidence_component":     conf_c,
            "stage_component":          stage_c,
            "next_stage_component":     next_c,
        },
        "inputs": {
            "anomaly_score":  anomaly_score,
            "attack_label":   attack_label,
            "confidence":     confidence,
            "current_stage":  current_stage,
            "next_stage":     next_stage,
        },
    }


if __name__ == "__main__":
    # Quick self-test
    scenarios = [
        dict(anomaly_score=0.2,  attack_label="BENIGN",          confidence=0.97, current_stage="NORMAL",             next_stage="NORMAL"),
        dict(anomaly_score=-0.1, attack_label="PortScan",         confidence=0.82, current_stage="RECONNAISSANCE",     next_stage="INITIAL_ACCESS"),
        dict(anomaly_score=-0.2, attack_label="SSH-Patator",      confidence=0.91, current_stage="INITIAL_ACCESS",     next_stage="COMMAND_AND_CONTROL"),
        dict(anomaly_score=-0.3, attack_label="Bot",              confidence=0.88, current_stage="COMMAND_AND_CONTROL",next_stage="LATERAL_MOVEMENT"),
        dict(anomaly_score=-0.4, attack_label="DDoS",             confidence=0.95, current_stage="IMPACT",             next_stage="IMPACT"),
    ]

    print("Risk Engine — Self Test")
    print("=" * 60)
    for s in scenarios:
        r = calculate(**s)
        print(f"\n  Label    : {s['attack_label']}")
        print(f"  Stage    : {s['current_stage']}")
        print(f"  Score    : {r['score']}  [{r['severity']}]")
        print(f"  Breakdown: {r['breakdown']}")
