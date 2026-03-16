"""
PhishGuard ML Detector — Ensemble of Random Forest + Gradient Boosting
Trained on real phishing/legitimate URL patterns using PhishUSIIL-inspired features.
"""
import os, sys, json
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
import joblib
from feature_extractor import extract_features, FEATURE_NAMES, feature_vector
from typing import Dict, Any

MODEL_DIR = "/home/claude/phishguard/models"


class MLDetector:
    def __init__(self):
        self.rf     = None
        self.gb     = None
        self.scaler = None
        self._load()

    def _load(self):
        try:
            self.rf     = joblib.load(f"{MODEL_DIR}/rf_model.joblib")
            self.gb     = joblib.load(f"{MODEL_DIR}/gb_model.joblib")
            self.scaler = joblib.load(f"{MODEL_DIR}/scaler.joblib")
        except Exception as e:
            print(f"[ML] Could not load models: {e}. Run train_model.py first.")

    def predict(self, url: str) -> Dict[str, Any]:
        if not self.rf or not self.gb or not self.scaler:
            return self._unavailable()

        try:
            fv      = feature_vector(url)
            X       = self.scaler.transform([fv])
            rf_p    = float(self.rf.predict_proba(X)[0][1])
            gb_p    = float(self.gb.predict_proba(X)[0][1])
            prob    = rf_p * 0.55 + gb_p * 0.45
            score   = round(prob * 100, 2)
            label   = self._label(prob)

            findings = []
            if prob > 0.65:
                findings.append({
                    "flagged": True,
                    "check":   f"ML Ensemble: {prob:.1%} phishing probability",
                    "detail":  f"Random Forest: {rf_p:.1%}, Gradient Boosting: {gb_p:.1%}",
                    "severity": min(int(prob * 45), 40),
                })

            top_features = self._explain(fv, prob)

            return {
                "module":               "ML Detection",
                "score":                score,
                "phishing_probability": round(prob, 4),
                "rf_probability":       round(rf_p, 4),
                "gb_probability":       round(gb_p, 4),
                "classification":       label,
                "confidence":           round(max(rf_p, gb_p) * 100, 1),
                "findings":             findings,
                "top_features":         top_features,
                "features":             {k: v for k, v in zip(FEATURE_NAMES, fv)},
            }
        except Exception as e:
            return self._unavailable(str(e))

    def _label(self, p: float) -> str:
        if p >= 0.90: return "DEFINITE_PHISHING"
        if p >= 0.70: return "LIKELY_PHISHING"
        if p >= 0.50: return "SUSPICIOUS"
        if p >= 0.30: return "LOW_RISK"
        return "LIKELY_LEGITIMATE"

    def _explain(self, fv: list, prob: float) -> list:
        """Return top contributing features for explainability."""
        if not hasattr(self.rf, 'feature_importances_'):
            return []
        importances = self.rf.feature_importances_
        explanations = []
        for name, importance, value in sorted(
            zip(FEATURE_NAMES, importances, fv),
            key=lambda x: x[1] * abs(x[2]),
            reverse=True
        )[:5]:
            if importance > 0.01:
                explanations.append({
                    "feature":    name,
                    "value":      round(value, 4),
                    "importance": round(importance, 4),
                })
        return explanations

    def _unavailable(self, err="") -> Dict[str, Any]:
        return {
            "module":               "ML Detection",
            "score":                0,
            "phishing_probability": 0,
            "rf_probability":       0,
            "gb_probability":       0,
            "classification":       "UNAVAILABLE",
            "confidence":           0,
            "findings":             [],
            "top_features":         [],
            "features":             {},
            "error":                err,
        }
