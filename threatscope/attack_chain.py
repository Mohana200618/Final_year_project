"""
threatscope/attack_chain.py
============================
Attack chain prediction using a Markov Chain transition model.

Approach
--------
  A first-order Markov chain defines transition probabilities between
  attack stages.  The model is rule-based and transparent — the
  transition matrix is stored as a plain Python dict so it can be
  audited and tuned without any ML training.

Attack stages (ordered by kill-chain position)
-----------------------------------------------
  NORMAL          - No attack activity
  RECONNAISSANCE  - Scanning / information gathering
  INITIAL_ACCESS  - Brute force / exploit / web attack
  C2              - Command & Control / botnet
  LATERAL_MOVE    - Lateral movement / infiltration
  IMPACT          - DoS / DDoS disruption

Stage assignment
----------------
  The current stage is derived from the XGBoost attack label by the
  label_to_stage() function.  Transitions are then looked up in the
  Markov matrix.

Output contract
---------------
  predict() returns a dict:
    {
      "current_stage"   : str,
      "next_stage"      : str,      # most probable next stage
      "next_probability": float,    # 0.0–1.0
      "alt_stage"       : str|None, # second-most probable next stage
      "alt_probability" : float,    # 0.0–1.0 (0 if none)
      "note"            : str       # limitation disclosure
    }
"""

from typing import Optional

# ---------------------------------------------------------------------------
# Stage constants
# ---------------------------------------------------------------------------

STAGE_NORMAL    = "NORMAL"
STAGE_RECON     = "RECONNAISSANCE"
STAGE_ACCESS    = "INITIAL_ACCESS"
STAGE_C2        = "COMMAND_AND_CONTROL"
STAGE_LATERAL   = "LATERAL_MOVEMENT"
STAGE_IMPACT    = "IMPACT"

ALL_STAGES = [
    STAGE_NORMAL,
    STAGE_RECON,
    STAGE_ACCESS,
    STAGE_C2,
    STAGE_LATERAL,
    STAGE_IMPACT,
]

# ---------------------------------------------------------------------------
# CICIDS2017 label -> attack stage mapping
# ---------------------------------------------------------------------------

_LABEL_TO_STAGE = {
    "BENIGN":                      STAGE_NORMAL,
    "PortScan":                    STAGE_RECON,
    "FTP-Patator":                 STAGE_ACCESS,
    "SSH-Patator":                 STAGE_ACCESS,
    "Web Attack - Brute Force":    STAGE_ACCESS,
    "Web Attack - XSS":            STAGE_ACCESS,
    "Web Attack - SQL Injection":  STAGE_ACCESS,
    "Heartbleed":                  STAGE_ACCESS,
    "Bot":                         STAGE_C2,
    "Infiltration":                STAGE_LATERAL,
    "DoS Hulk":                    STAGE_IMPACT,
    "DoS GoldenEye":               STAGE_IMPACT,
    "DoS slowloris":               STAGE_IMPACT,
    "DoS Slowhttptest":            STAGE_IMPACT,
    "DDoS":                        STAGE_IMPACT,
}

# ---------------------------------------------------------------------------
# Markov transition matrix
# P[current_stage][next_stage] = probability
#
# Probabilities per row must sum to 1.0.
#
# Rationale:
#   NORMAL -> RECON most likely (attacker starts with scanning)
#   RECON  -> ACCESS (exploitation) most likely after recon
#   ACCESS -> C2 (establish foothold) or directly to IMPACT
#   C2     -> LATERAL or IMPACT
#   LATERAL -> IMPACT or more lateral movement
#   IMPACT -> self (DoS tends to continue) or back to NORMAL
#
# These probabilities are expert-informed, not ML-derived.
# They represent directional likelihoods, not calibrated frequencies.
# ---------------------------------------------------------------------------

_TRANSITION_MATRIX = {
    STAGE_NORMAL: {
        STAGE_NORMAL:  0.80,
        STAGE_RECON:   0.15,
        STAGE_ACCESS:  0.03,
        STAGE_C2:      0.01,
        STAGE_LATERAL: 0.00,
        STAGE_IMPACT:  0.01,
    },
    STAGE_RECON: {
        STAGE_NORMAL:  0.10,
        STAGE_RECON:   0.20,
        STAGE_ACCESS:  0.55,
        STAGE_C2:      0.05,
        STAGE_LATERAL: 0.00,
        STAGE_IMPACT:  0.10,
    },
    STAGE_ACCESS: {
        STAGE_NORMAL:  0.05,
        STAGE_RECON:   0.05,
        STAGE_ACCESS:  0.15,
        STAGE_C2:      0.50,
        STAGE_LATERAL: 0.15,
        STAGE_IMPACT:  0.10,
    },
    STAGE_C2: {
        STAGE_NORMAL:  0.05,
        STAGE_RECON:   0.05,
        STAGE_ACCESS:  0.05,
        STAGE_C2:      0.20,
        STAGE_LATERAL: 0.40,
        STAGE_IMPACT:  0.25,
    },
    STAGE_LATERAL: {
        STAGE_NORMAL:  0.05,
        STAGE_RECON:   0.05,
        STAGE_ACCESS:  0.10,
        STAGE_C2:      0.10,
        STAGE_LATERAL: 0.30,
        STAGE_IMPACT:  0.40,
    },
    STAGE_IMPACT: {
        STAGE_NORMAL:  0.10,
        STAGE_RECON:   0.05,
        STAGE_ACCESS:  0.05,
        STAGE_C2:      0.05,
        STAGE_LATERAL: 0.05,
        STAGE_IMPACT:  0.70,
    },
}


def label_to_stage(label: str) -> str:
    """
    Map a CICIDS2017 / XGBoost predicted label to an attack stage.
    Falls back to STAGE_RECON for unknown labels (conservative assumption).
    """
    return _LABEL_TO_STAGE.get(label.strip(), STAGE_RECON)


def predict(current_stage: str) -> dict:
    """
    Given the current attack stage, return the predicted next stage(s).

    Parameters
    ----------
    current_stage : str
        One of the ALL_STAGES constants.

    Returns
    -------
    dict with keys:
        current_stage, next_stage, next_probability,
        alt_stage, alt_probability, note
    """
    if current_stage not in _TRANSITION_MATRIX:
        current_stage = STAGE_RECON  # safe fallback

    transitions = _TRANSITION_MATRIX[current_stage]

    # Sort by probability descending
    ranked = sorted(transitions.items(), key=lambda kv: kv[1], reverse=True)

    next_stage, next_prob = ranked[0]
    alt_stage, alt_prob   = ranked[1] if len(ranked) > 1 else (None, 0.0)

    return {
        "current_stage":    current_stage,
        "next_stage":       next_stage,
        "next_probability": round(next_prob, 4),
        "alt_stage":        alt_stage,
        "alt_probability":  round(alt_prob, 4),
        "note": (
            "Predictions are based on a rule-based Markov chain trained on "
            "expert knowledge, not observed sequences. They indicate likely "
            "attack progression, not certainty."
        ),
    }


def predict_from_label(label: str) -> dict:
    """
    Convenience: map label -> stage -> predict().
    Includes the resolved stage in the returned dict.
    """
    stage = label_to_stage(label)
    result = predict(stage)
    result["resolved_from_label"] = label
    return result


if __name__ == "__main__":
    print("Attack Chain Prediction — Markov Chain Demo")
    print("=" * 55)
    labels = [
        "BENIGN", "PortScan", "FTP-Patator",
        "Bot", "Infiltration", "DDoS"
    ]
    for lbl in labels:
        r = predict_from_label(lbl)
        print(f"\n  Label   : {lbl}")
        print(f"  Stage   : {r['current_stage']}")
        print(f"  Next    : {r['next_stage']}  ({r['next_probability']*100:.0f}%)")
        print(f"  Alt     : {r['alt_stage']}   ({r['alt_probability']*100:.0f}%)")
