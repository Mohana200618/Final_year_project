"""
threatscope/pipeline.py
========================
End-to-end ThreatScope inference pipeline.

Given a single feature row (or DataFrame of rows), runs:
  1. StandardScaler  (pre-fitted)
  2. Isolation Forest  -> anomaly flag + anomaly score
  3. XGBoost classifier  -> attack label + class probabilities
  4. MITRE ATT&CK mapping
  5. Attack stage derivation
  6. Attack chain prediction (Markov)
  7. Risk scoring
  8. Recommendations

Returns a structured result dict per flow (or list of dicts).

Usage
-----
  from threatscope.pipeline import ThreatScopePipeline

  pipeline = ThreatScopePipeline()
  results  = pipeline.run_df(feature_dataframe)
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import joblib

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import feature_schema as fs
from threatscope.mitre_mapper  import MitreMapper
from threatscope.attack_chain  import label_to_stage, predict as chain_predict
from threatscope.risk_engine   import calculate as risk_calculate
from threatscope.recommender   import get_recommendations


# ---------------------------------------------------------------------------
# Default model paths (relative to project root)
# ---------------------------------------------------------------------------

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_DEFAULT_PATHS = {
    "scaler":     os.path.join(_PROJECT_ROOT, "models", "isolation_scaler.pkl"),
    "if_model":   os.path.join(_PROJECT_ROOT, "models", "isolation_forest.pkl"),
    "threshold":  os.path.join(_PROJECT_ROOT, "models", "isolation_threshold.txt"),
    "xgb_model":  os.path.join(_PROJECT_ROOT, "models", "xgb_classifier.pkl"),
    "xgb_le":     os.path.join(_PROJECT_ROOT, "models", "xgb_label_encoder.pkl"),
}


class ThreatScopePipeline:
    """
    End-to-end ThreatScope inference pipeline.

    Parameters
    ----------
    model_paths : dict, optional
        Override any of the default model paths.
    require_xgb : bool
        If False, XGBoost is optional (pipeline works with IF only).
    """

    def __init__(self, model_paths: dict = None, require_xgb: bool = True):
        paths = {**_DEFAULT_PATHS, **(model_paths or {})}

        # --- Load Scaler ---
        if not os.path.exists(paths["scaler"]):
            raise FileNotFoundError(f"Scaler not found: {paths['scaler']}")
        self.scaler = joblib.load(paths["scaler"])

        # --- Load Isolation Forest ---
        if not os.path.exists(paths["if_model"]):
            raise FileNotFoundError(f"IF model not found: {paths['if_model']}")
        self.if_model = joblib.load(paths["if_model"])

        # --- Load threshold ---
        if os.path.exists(paths["threshold"]):
            with open(paths["threshold"]) as fh:
                self.if_threshold = float(fh.read().strip())
        else:
            # Fall back to default contamination-derived threshold
            self.if_threshold = 0.0
            print("[Pipeline] WARNING: isolation_threshold.txt not found. "
                  "Using default threshold 0.0")

        # --- Load XGBoost (optional) ---
        self._xgb_available = False
        if os.path.exists(paths["xgb_model"]) and os.path.exists(paths["xgb_le"]):
            self.xgb_model = joblib.load(paths["xgb_model"])
            self.xgb_le    = joblib.load(paths["xgb_le"])
            self._xgb_available = True
        elif require_xgb:
            raise FileNotFoundError(
                "XGBoost model not found. Run train_xgboost.py first.\n"
                f"  Expected: {paths['xgb_model']}"
            )
        else:
            print("[Pipeline] XGBoost not available — using IF-only mode.")

        # --- Load MITRE mapper ---
        self.mitre = MitreMapper()

        print(f"[Pipeline] Loaded successfully.")
        print(f"  IF threshold    : {self.if_threshold:.6f}")
        print(f"  XGBoost ready   : {self._xgb_available}")
        print(f"  MITRE labels    : {len(self.mitre.list_labels())}")

    def run_row(self, feature_dict: dict) -> dict:
        """
        Run the pipeline on a single flow (dict of feature_name -> value).

        Returns
        -------
        Full analysis result dict.
        """
        row_df = pd.DataFrame([feature_dict])[fs.FEATURES]
        results = self.run_df(row_df)
        return results[0]

    def run_df(self, df: pd.DataFrame) -> list:
        """
        Run the pipeline on a DataFrame of flows.

        Parameters
        ----------
        df : pd.DataFrame
            Must contain the 6 ThreatScope features.

        Returns
        -------
        List of result dicts, one per row.
        """
        fs.validate_dataframe(df, context="Pipeline")

        X = df[fs.FEATURES].values

        # ------------------------------------------------------------------
        # Step 1: Scale
        # ------------------------------------------------------------------
        X_scaled = self.scaler.transform(X)

        # ------------------------------------------------------------------
        # Step 2: Isolation Forest
        # ------------------------------------------------------------------
        if_scores    = self.if_model.decision_function(X_scaled)
        if_anomalous = (if_scores < self.if_threshold).astype(bool)

        # ------------------------------------------------------------------
        # Step 3: XGBoost classification
        # ------------------------------------------------------------------
        if self._xgb_available:
            xgb_preds  = self.xgb_model.predict(X)
            xgb_labels = self.xgb_le.inverse_transform(xgb_preds)
            xgb_probs  = self.xgb_model.predict_proba(X)
            xgb_confs  = xgb_probs.max(axis=1)
        else:
            xgb_labels = np.where(if_anomalous, "Unknown Attack", "BENIGN")
            xgb_confs  = np.where(if_anomalous, 0.5, 0.9)

        # ------------------------------------------------------------------
        # Steps 4–8 per row
        # ------------------------------------------------------------------
        results = []

        for i in range(len(X)):
            label      = str(xgb_labels[i])
            anomalous  = bool(if_anomalous[i])
            anom_score = float(if_scores[i])
            confidence = float(xgb_confs[i])

            # MITRE mapping
            mitre_info = self.mitre.get(label)

            # Attack chain
            stage  = label_to_stage(label)
            chain  = chain_predict(stage)

            # Risk
            risk   = risk_calculate(
                anomaly_score  = anom_score,
                attack_label   = label,
                confidence     = confidence,
                current_stage  = stage,
                next_stage     = chain["next_stage"],
            )

            # Recommendations
            recs   = get_recommendations(
                attack_label  = label,
                current_stage = stage,
                severity      = risk["severity"],
            )

            results.append({
                "is_anomalous":       anomalous,
                "anomaly_score":      round(anom_score, 6),
                "attack_label":       label,
                "confidence":         round(confidence, 4),
                "mitre": {
                    "tactic":         mitre_info.get("tactic"),
                    "technique_id":   mitre_info.get("technique_id"),
                    "technique_name": mitre_info.get("technique_name"),
                    "sub_technique":  mitre_info.get("sub_technique_id"),
                    "reference":      mitre_info.get("reference"),
                },
                "attack_chain": {
                    "current_stage":    chain["current_stage"],
                    "next_stage":       chain["next_stage"],
                    "next_probability": chain["next_probability"],
                    "alt_stage":        chain["alt_stage"],
                    "alt_probability":  chain["alt_probability"],
                },
                "risk": {
                    "score":     risk["score"],
                    "severity":  risk["severity"],
                    "breakdown": risk["breakdown"],
                },
                "recommendations": recs["actions"],
                "disclaimer":      recs["disclaimer"],
                "features": {
                    k: float(df[fs.FEATURES].iloc[i][k])
                    for k in fs.FEATURES
                },
            })

        return results


if __name__ == "__main__":
    print("ThreatScope Pipeline — Quick Test")
    print("=" * 55)

    # Test with a synthetic flow (realistic-ish values)
    test_flows = pd.DataFrame([
        {
            "Destination Port":        22,
            "Flow Duration":           500000,
            "Total Fwd Packets":       200,
            "Total Backward Packets":  5,
            "Flow Bytes/s":            15000.0,
            "Flow Packets/s":          410.0,
        },
        {
            "Destination Port":        80,
            "Flow Duration":           1200000,
            "Total Fwd Packets":       10,
            "Total Backward Packets":  8,
            "Flow Bytes/s":            1200.0,
            "Flow Packets/s":          15.0,
        },
    ])

    try:
        pipeline = ThreatScopePipeline(require_xgb=False)
        results  = pipeline.run_df(test_flows)

        for i, r in enumerate(results):
            print(f"\n--- Flow {i+1} ---")
            print(f"  Anomalous  : {r['is_anomalous']}")
            print(f"  Label      : {r['attack_label']}  ({r['confidence']:.1%} conf)")
            print(f"  MITRE      : {r['mitre']['technique_id']} {r['mitre']['technique_name']}")
            print(f"  Stage      : {r['attack_chain']['current_stage']}")
            print(f"  Next Stage : {r['attack_chain']['next_stage']}  ({r['attack_chain']['next_probability']*100:.0f}%)")
            print(f"  Risk       : {r['risk']['score']} [{r['risk']['severity']}]")
            print(f"  Actions    : {len(r['recommendations'])} recommendations")

    except FileNotFoundError as e:
        print(f"[EXPECTED in early dev] {e}")
