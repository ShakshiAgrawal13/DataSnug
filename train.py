"""
╔══════════════════════════════════════════════════════════╗
║         DataSnug — AI-Powered Data Loss Prevention       ║
║                      train.py                            ║
║  Trains a Logistic Regression classifier on mixed        ║
║  (text + numeric) features and saves classifier.pkl      ║
╚══════════════════════════════════════════════════════════╝
"""

import os
import pickle
import logging
import argparse
import numpy as np
import pandas as pd

from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score, classification_report,
    confusion_matrix, roc_auc_score
)

# ─── Logging Setup ────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("DataSnug.Train")

# ─── Constants ────────────────────────────────────────────────────────────────

MODEL_DIR    = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH   = os.path.join(MODEL_DIR, "classifier.pkl")
DATA_PATH    = os.path.join(os.path.dirname(__file__), "data", "sample_data.txt")

NUMERIC_FEATURES = [
    "file_size",       # Size of the file/document in bytes
    "num_emails",      # Count of email addresses found
    "num_ssn",         # Count of SSN patterns detected
    "num_credit_cards",# Count of credit card numbers
    "num_phone",       # Count of phone numbers
    "entropy",         # Shannon entropy of the content
    "keyword_count",   # Count of sensitive keywords matched
    "is_encrypted",    # 1 if content appears encrypted, else 0
]

SENSITIVE_KEYWORDS = [
    "ssn", "social security", "credit card", "password", "passwd",
    "confidential", "secret", "private key", "api_key", "token",
    "bank account", "routing number", "iban", "swift", "dob",
    "date of birth", "passport", "driver license", "medical record",
    "hipaa", "pii", "phi", "salary", "payroll", "acquisition",
    "merger", "insider", "classified", "top secret",
]

# ─── Custom Transformers ──────────────────────────────────────────────────────

class TextExtractor(BaseEstimator, TransformerMixin):
    """Pulls the 'text' field from each sample dict."""
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return [x.get("text", "") if isinstance(x, dict) else str(x) for x in X]


class NumericExtractor(BaseEstimator, TransformerMixin):
    """Pulls numeric feature fields from each sample dict."""
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        rows = []
        for x in X:
            if isinstance(x, dict):
                rows.append([float(x.get(k, 0)) for k in NUMERIC_FEATURES])
            else:
                rows.append([0.0] * len(NUMERIC_FEATURES))
        return np.array(rows, dtype=float)


# ─── Feature Engineering Helpers ─────────────────────────────────────────────

def compute_entropy(text: str) -> float:
    """Shannon entropy of character distribution."""
    if not text:
        return 0.0
    freq = np.array([text.count(c) for c in set(text)], dtype=float)
    freq /= len(text)
    return float(-np.sum(freq * np.log2(freq + 1e-12)))


def count_keywords(text: str) -> int:
    t = text.lower()
    return sum(1 for kw in SENSITIVE_KEYWORDS if kw in t)


def count_pattern(text: str, pattern_name: str) -> int:
    import re
    patterns = {
        "ssn":          r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card":  r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
        "email":        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "phone":        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b",
    }
    rx = patterns.get(pattern_name, r"(?!)")
    return len(re.findall(rx, text))


def extract_features_from_text(text: str) -> dict:
    """Auto-compute numeric features from raw text (used when loading from file)."""
    return {
        "text":              text,
        "file_size":         len(text.encode("utf-8")),
        "num_emails":        count_pattern(text, "email"),
        "num_ssn":           count_pattern(text, "ssn"),
        "num_credit_cards":  count_pattern(text, "credit_card"),
        "num_phone":         count_pattern(text, "phone"),
        "entropy":           round(compute_entropy(text), 4),
        "keyword_count":     count_keywords(text),
        "is_encrypted":      int(compute_entropy(text) > 6.5),
    }


# ─── Data Loaders ─────────────────────────────────────────────────────────────

def load_from_file(filepath: str):
    """
    Load training data from sample_data.txt.

    Expected format (one sample per line):
        LABEL|text content here
        e.g.  1|SSN 123-45-6789 confidential record
              0|Meeting notes from Q3 review
    """
    log.info(f"Loading data from: {filepath}")
    X, y = [], []
    with open(filepath, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "|" not in line:
                log.warning(f"Line {line_no}: no '|' separator, skipping.")
                continue
            label_str, text = line.split("|", 1)
            try:
                label = int(label_str.strip())
            except ValueError:
                log.warning(f"Line {line_no}: invalid label '{label_str}', skipping.")
                continue
            features = extract_features_from_text(text.strip())
            X.append(features)
            y.append(label)
    log.info(f"Loaded {len(X)} samples ({sum(y)} sensitive, {len(y)-sum(y)} normal).")
    return X, y


def load_synthetic_data(n_samples: int = 800):
    """
    Generate a rich synthetic DLP dataset for demo/initial training.
    Replace or augment this with real labelled data for production.
    """
    log.info(f"Generating {n_samples} synthetic training samples...")
    np.random.seed(42)

    sensitive_pool = [
        "SSN 123-45-6789 and credit card number 4111111111111111 found in document",
        "Patient record DOB 05/14/1982 diagnosis ICD-10 Z87.891 insurance 334455",
        "Wire transfer details IBAN GB29NWBK60161331926819 amount $250,000 urgent",
        "Salary slip Employee ID 7823 base pay $95000 bank routing 021000021",
        "PII export: name John Doe email john@corp.com passport A12345678",
        "Database dump 10000 user records hashed passwords bcrypt confidential",
        "M&A document: acquisition target Q4 financial model strictly confidential",
        "API key sk-abcd1234efgh5678 AWS secret AKIAIOSFODNN7EXAMPLE do not share",
        "HIPAA PHI patient SSN 987-65-4321 health insurance member 88776655",
        "Credit card 5500005555555559 CVV 123 expiry 12/27 billing address 221B Baker",
        "Internal memo: employee termination list names salaries severance packages",
        "Source code with hardcoded password passwd=Sup3rS3cret! db_host=prod-db",
        "Legal NDA draft: confidential terms merger valuation $2.3B signing parties",
        "Medical test results HIV positive patient ID 44521 doctor notes attached",
        "Export of CRM data 50000 customers full name email phone credit score",
    ]

    normal_pool = [
        "Meeting agenda for Q3 review project milestones and team discussion points",
        "Please find attached the quarterly marketing report slide deck for review",
        "Schedule reminder lunch at 12pm team standup at 3pm on Friday afternoon",
        "The new product launch plan has been approved by all key stakeholders today",
        "Company newsletter: welcome to our new interns joining us this summer cohort",
        "Code review comments for PR 412 minor style fixes and naming suggestions",
        "Travel itinerary for annual conference in Chicago next week hotel booked",
        "Updated org chart reflecting recent team restructuring and reporting changes",
        "Holiday party invitation Friday December 20th rooftop venue 6pm dress smart",
        "System maintenance notice: downtime scheduled Sunday 2am to 4am for updates",
        "Monthly all-hands recording now available on the internal portal for viewing",
        "Office supply order approved: notebooks pens whiteboard markers and folders",
        "Project retrospective action items assigned owners and due dates confirmed",
        "IT helpdesk ticket resolved: VPN access restored for remote work today",
        "New parking policy effective next month please read the attached guidelines",
    ]

    X, y = [], []
    for i in range(n_samples):
        is_sensitive = i % 2 == 0
        base = sensitive_pool[i % len(sensitive_pool)] if is_sensitive else normal_pool[i % len(normal_pool)]
        # Add slight variation
        noise = f" ref#{np.random.randint(1000,9999)}"
        text = base + noise

        row = extract_features_from_text(text)
        # Inject realistic noise into numeric fields
        if is_sensitive:
            row["num_ssn"]          = max(row["num_ssn"],          np.random.randint(0, 4))
            row["num_credit_cards"] = max(row["num_credit_cards"],  np.random.randint(0, 3))
            row["keyword_count"]    = max(row["keyword_count"],     np.random.randint(2, 10))
        X.append(row)
        y.append(1 if is_sensitive else 0)

    log.info(f"Synthetic data ready: {sum(y)} sensitive, {len(y)-sum(y)} normal.")
    return X, y


# ─── Model Builder ────────────────────────────────────────────────────────────

def build_pipeline() -> Pipeline:
    text_pipeline = Pipeline([
        ("extract_text", TextExtractor()),
        ("tfidf", TfidfVectorizer(
            max_features=8000,
            ngram_range=(1, 2),
            sublinear_tf=True,
            min_df=2,
            analyzer="word",
            stop_words="english",
        )),
    ])

    numeric_pipeline = Pipeline([
        ("extract_num", NumericExtractor()),
        ("scaler", StandardScaler()),
    ])

    combined = FeatureUnion([
        ("text_features",    text_pipeline),
        ("numeric_features", numeric_pipeline),
    ])

    return Pipeline([
        ("features", combined),
        ("clf", LogisticRegression(
            C=1.0,
            max_iter=1000,
            solver="lbfgs",
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )),
    ])


# ─── Training & Evaluation ────────────────────────────────────────────────────

def train(X, y, test_size: float = 0.2):
    log.info("Splitting data into train/test sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )

    log.info("Building model pipeline (TF-IDF + Numeric → Logistic Regression)...")
    model = build_pipeline()

    log.info("Training model...")
    model.fit(X_train, y_train)

    # ── Evaluation ──────────────────────────────────────────────────────────
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc     = accuracy_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_prob)

    log.info("─" * 55)
    log.info(f"  Test Accuracy : {acc:.4f}")
    log.info(f"  ROC-AUC Score : {roc_auc:.4f}")
    log.info("─" * 55)
    log.info("\n" + classification_report(
        y_test, y_pred, target_names=["Normal (0)", "Sensitive (1)"]
    ))

    cm = confusion_matrix(y_test, y_pred)
    log.info(f"Confusion Matrix:\n  TN={cm[0,0]}  FP={cm[0,1]}\n  FN={cm[1,0]}  TP={cm[1,1]}")

    # ── Cross-Validation ────────────────────────────────────────────────────
    log.info("Running 5-fold cross-validation...")
    cv_scores = cross_val_score(model, X, y, cv=5, scoring="roc_auc", n_jobs=-1)
    log.info(f"  CV ROC-AUC: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    return model


def save_model(model, path: str = MODEL_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(model, f)
    size_kb = os.path.getsize(path) / 1024
    log.info(f"✅ Model saved → {path}  ({size_kb:.1f} KB)")


def load_model(path: str = MODEL_PATH):
    with open(path, "rb") as f:
        model = pickle.load(f)
    log.info(f"Model loaded from: {path}")
    return model


# ─── Quick Prediction Helper ──────────────────────────────────────────────────

def predict(model, raw_text: str) -> dict:
    """
    Predict whether a piece of raw text is sensitive/DLP risk.

    Returns:
        dict with 'label', 'label_name', 'confidence'
    """
    features = extract_features_from_text(raw_text)
    pred     = model.predict([features])[0]
    prob     = model.predict_proba([features])[0]
    return {
        "label":      int(pred),
        "label_name": "Sensitive / DLP Risk" if pred == 1 else "Normal",
        "confidence": round(float(max(prob)) * 100, 2),
        "prob_normal":    round(float(prob[0]) * 100, 2),
        "prob_sensitive": round(float(prob[1]) * 100, 2),
    }


# ─── CLI Entry Point ──────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="DataSnug DLP — Model Trainer")
    parser.add_argument(
        "--data", type=str, default=None,
        help="Path to labelled data file (default: uses synthetic data)"
    )
    parser.add_argument(
        "--output", type=str, default=MODEL_PATH,
        help=f"Where to save classifier.pkl (default: {MODEL_PATH})"
    )
    parser.add_argument(
        "--test-size", type=float, default=0.2,
        help="Fraction of data used for testing (default: 0.2)"
    )
    parser.add_argument(
        "--predict", type=str, default=None,
        help="Run a quick prediction on this text after training"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    log.info("=" * 55)
    log.info("   DataSnug — DLP Classifier Training")
    log.info("=" * 55)

    # Load data
    if args.data and os.path.exists(args.data):
        X, y = load_from_file(args.data)
    else:
        if args.data:
            log.warning(f"Data file not found: {args.data}. Using synthetic data.")
        X, y = load_synthetic_data(n_samples=800)

    # Train
    model = train(X, y, test_size=args.test_size)

    # Save
    save_model(model, path=args.output)

    # Optional quick prediction
    if args.predict:
        log.info("\n── Quick Prediction ─────────────────────────────")
        result = predict(model, args.predict)
        log.info(f"  Input     : {args.predict[:80]}...")
        log.info(f"  Result    : {result['label_name']}")
        log.info(f"  Confidence: {result['confidence']}%")
        log.info(f"  P(Normal) : {result['prob_normal']}%")
        log.info(f"  P(Sensitive): {result['prob_sensitive']}%")

    log.info("=" * 55)
    log.info("Training complete. classifier.pkl is ready.")
    log.info("=" * 55)


if __name__ == "__main__":
    main()
