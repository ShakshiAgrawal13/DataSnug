import re
import os
import pickle
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

MODEL_PATH = os.path.join(os.path.dirname(__file__), "classifier.pkl")

_NUMERIC_KEYS = [
    "file_size", "num_emails", "num_ssn", "num_credit_cards",
    "num_phone", "entropy", "keyword_count", "is_encrypted"
]

class TextExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None): return self
    def transform(self, X):
        return [x.get("text", "") if isinstance(x, dict) else str(x) for x in X]

class NumericExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None): return self
    def transform(self, X):
        return np.array([[float(x.get(k, 0)) for k in _NUMERIC_KEYS] for x in X])

def _compute_entropy(text):
    if not text:
        return 0.0
    freq = np.array([text.count(c) for c in set(text)], dtype=float)
    freq /= len(text)
    return float(-np.sum(freq * np.log2(freq + 1e-12)))

def _count_pattern(text, pattern_name):
    patterns = {
        "ssn":         r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
        "email":       r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "phone":       r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b",
    }
    return len(re.findall(patterns.get(pattern_name, r"(?!)"), text))

SENSITIVE_KEYWORDS = [
    "ssn","social security","credit card","password","passwd","confidential",
    "secret","private key","api_key","token","bank account","routing number",
    "iban","swift","dob","date of birth","passport","driver license",
    "medical record","hipaa","pii","phi","salary","payroll","acquisition",
    "merger","insider","classified","top secret",
]

class DataLeakDetector:
    def __init__(self):
        # Load ML model if available
        self._ml_model = None
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, "rb") as f:
                    self._ml_model = pickle.load(f)
            except Exception:
                self._ml_model = None

        self.patterns = {
            "Credit Card Number": {
                "regex": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6011[0-9]{12})\b',
                "risk": "HIGH",
                "emoji": "💳"
            },
            "Social Security Number (SSN)": {
                "regex": r'\b\d{3}-\d{2}-\d{4}\b',
                "risk": "HIGH",
                "emoji": "🪪"
            },
            "Email Address": {
                "regex": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                "risk": "MEDIUM",
                "emoji": "📧"
            },
            "Phone Number": {
                "regex": r'\b(?:\+91[-\s]?)?[6-9]\d{9}\b|\b\+?1?\s?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
                "risk": "MEDIUM",
                "emoji": "📞"
            },
            "API Key / Token": {
                "regex": r'\b(?:sk|pk|api|token|key)[-_]?[A-Za-z0-9]{20,}\b',
                "risk": "HIGH",
                "emoji": "🔑"
            },
            "IP Address": {
                "regex": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                "risk": "LOW",
                "emoji": "🌐"
            },
            "Aadhaar Number": {
                "regex": r'\b[2-9]{1}[0-9]{11}\b',
                "risk": "HIGH",
                "emoji": "🪪"
            },
            "Password (plaintext)": {
                "regex": r'(?i)(?:password|passwd|pwd)\s*[:=]\s*\S+',
                "risk": "HIGH",
                "emoji": "🔒"
            },
            "Bank Account Number": {
                "regex": r'\b\d{9,18}\b',
                "risk": "MEDIUM",
                "emoji": "🏦"
            },
            "Date of Birth": {
                "regex": r'\b(?:dob|date of birth|birth date)\s*[:=]?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',
                "risk": "MEDIUM",
                "emoji": "🎂"
            }
        }

    def _ml_predict(self, text):
        """Run ML classifier and return label + confidence."""
        if self._ml_model is None:
            return None
        features = [{
            "text":               text,
            "file_size":          len(text.encode("utf-8")),
            "num_emails":         _count_pattern(text, "email"),
            "num_ssn":            _count_pattern(text, "ssn"),
            "num_credit_cards":   _count_pattern(text, "credit_card"),
            "num_phone":          _count_pattern(text, "phone"),
            "entropy":            round(_compute_entropy(text), 4),
            "keyword_count":      sum(1 for kw in SENSITIVE_KEYWORDS if kw in text.lower()),
            "is_encrypted":       int(_compute_entropy(text) > 6.5),
        }]
        try:
            label = int(self._ml_model.predict(features)[0])
            prob  = self._ml_model.predict_proba(features)[0]
            return {
                "label":      label,
                "label_name": "Sensitive" if label == 1 else "Normal",
                "confidence": round(float(max(prob)) * 100, 1),
            }
        except Exception:
            return None

    def scan_text(self, text):
        findings = []
        risk_score = 0
        risk_weights = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

        # ── Regex-based detection ────────────────────────────────────────────
        for label, config in self.patterns.items():
            matches = re.findall(config["regex"], text)
            if matches:
                masked = [self._mask(m) for m in matches[:3]]
                findings.append({
                    "type":    label,
                    "emoji":   config["emoji"],
                    "risk":    config["risk"],
                    "count":   len(matches),
                    "samples": masked
                })
                risk_score += risk_weights[config["risk"]] * len(matches)

        # ── ML-based detection ────────────────────────────────────────────────
        ml_verdict = self._ml_predict(text)
        if ml_verdict:
            # Boost risk score if ML also flags as sensitive
            if ml_verdict["label"] == 1 and ml_verdict["confidence"] >= 70:
                risk_score += 3
            # Reduce score if ML is confident content is normal
            elif ml_verdict["label"] == 0 and ml_verdict["confidence"] >= 85:
                risk_score = max(0, risk_score - 2)

        # ── Final risk level ─────────────────────────────────────────────────
        if risk_score == 0:
            risk_level = "SAFE"
        elif risk_score <= 3:
            risk_level = "LOW"
        elif risk_score <= 8:
            risk_level = "MEDIUM"
        else:
            risk_level = "HIGH"

        return {
            "findings":      findings,
            "risk_level":    risk_level,
            "risk_score":    risk_score,
            "total_matches": sum(f["count"] for f in findings),
            "ml_verdict":    ml_verdict,
            "summary":       self._generate_summary(findings, risk_level, ml_verdict)
        }

    def _mask(self, value):
        s = str(value)
        if len(s) <= 4:
            return "*" * len(s)
        return s[:2] + "*" * (len(s) - 4) + s[-2:]

    def _generate_summary(self, findings, risk_level, ml_verdict=None):
        ml_note = ""
        if ml_verdict:
            ml_note = f" · 🤖 ML: {ml_verdict['label_name']} ({ml_verdict['confidence']}% confidence)"
        if not findings:
            if ml_verdict and ml_verdict["label"] == 1:
                return f"⚠️ No pattern matches, but ML model flagged this as sensitive.{ml_note}"
            return f"✅ No sensitive data detected. Content appears safe.{ml_note}"
        types = [f["type"] for f in findings]
        return f"⚠️ Detected {len(findings)} sensitive data type(s): {', '.join(types)}. Risk Level: {risk_level}{ml_note}"
