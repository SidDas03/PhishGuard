"""
PhishGuard — Train ML model from the real PhishUSIIL Kaggle dataset.

Dataset: https://www.kaggle.com/datasets/kaggleprollc/phishing-url-websites-dataset-phiusiil
File:    phiusiil_phishing_url_website.csv
Place that CSV file in the same folder as this script, then run:

    python train_from_kaggle.py

This will:
  1. Load all 235,795 URLs from the dataset
  2. Extract 38 features from each URL using feature_extractor.py
  3. Train a Random Forest + Gradient Boosting ensemble
  4. Save the models to ../models/
  5. Print accuracy, F1, confusion matrix
  6. Validate against the known problem URLs

Expected results: ~97-99% accuracy on held-out test set
"""

import os, sys, json, time
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (classification_report, confusion_matrix,
                              accuracy_score, f1_score, roc_auc_score)
import joblib

from feature_extractor import extract_features, FEATURE_NAMES, feature_vector

# ── Config ──────────────────────────────────────────────────────────────────
CSV_FILE   = os.path.join(os.path.dirname(__file__), "phiusiil_phishing_url_website.csv")
MODEL_DIR  = os.path.join(os.path.dirname(__file__), "..", "models")
BATCH_SIZE = 5000   # process in batches to show progress
MAX_ROWS   = None   # set to e.g. 50000 to limit for faster training; None = all rows

# ── Validation URLs (our known problem cases) ───────────────────────────────
VALIDATION_CASES = [
    # SAFE — must score < 0.5
    ("https://www.google.com",                                              0),
    ("https://security.berkeley.edu/resources/phishing",                   0),
    ("https://docs.python.org/3/library/urllib.html",                      0),
    ("https://paypal.com/signin",                                          0),
    ("https://accounts.google.com/signin/v2/identifier",                  0),
    ("https://login.microsoftonline.com/common/oauth2",                    0),
    ("https://www.americanexpress.com/en-us/account/login",                0),
    ("https://mit.edu/research",                                           0),
    ("https://www.irs.gov/filing",                                         0),
    ("https://en.wikipedia.org/wiki/Phishing",                             0),
    ("https://www.chase.com/personal/banking",                             0),
    ("https://secure.bankofamerica.com/login/sign-in",                     0),
    # PHISHING — must score > 0.5
    ("https://mail.printakid.com/www.online.americanexpress.com/index.html",1),
    ("http://paypa1-login.verify.tk/account",                              1),
    ("https://microsoft-account-verify.online/confirm",                    1),
    ("https://secure-paypal-login.xyz/signin",                             1),
    ("http://192.168.1.1/admin/login.php",                                 1),
    ("https://amaz0n-prime.club/renew",                                    1),
    ("https://accounts-google-com.verify-login.tk/signin",                 1),
    ("https://netf1ix-renewal.xyz/account-suspended",                      1),
    ("http://evil.tk/www.paypal.com/login",                                1),
    ("http://user@paypal.com@evil.tk/login",                               1),
    ("https://apple-id.suspend.cf/unlock",                                 1),
    ("https://verify-your-identity-now.online/step1/personal",             1),
]


def load_dataset(csv_path: str, max_rows=None):
    """Load and parse the PhishUSIIL CSV file."""
    print(f"\nLoading dataset from: {csv_path}")

    if not os.path.exists(csv_path):
        print(f"\n  ERROR: File not found: {csv_path}")
        print(f"\n  Steps to fix:")
        print(f"  1. Go to https://www.kaggle.com/datasets/kaggleprollc/phishing-url-websites-dataset-phiusiil")
        print(f"  2. Download the CSV file")
        print(f"  3. Rename it to: phiusiil_phishing_url_website.csv")
        print(f"  4. Place it in: {os.path.dirname(csv_path)}")
        print(f"  5. Run this script again")
        sys.exit(1)

    df = pd.read_csv(csv_path, nrows=max_rows)
    print(f"  Loaded {len(df):,} rows, columns: {list(df.columns)}")

    # Auto-detect URL and label columns
    url_col   = None
    label_col = None

    for col in df.columns:
        col_low = col.lower()
        if col_low in ('url', 'urls', 'link', 'website', 'address'):
            url_col = col
        if col_low in ('label', 'class', 'phishing', 'target', 'result',
                       'status', 'type', 'is_phishing'):
            label_col = col

    # Fallback: guess from column values
    if not url_col:
        for col in df.columns:
            sample = str(df[col].iloc[0])
            if sample.startswith('http') or '.' in sample:
                url_col = col
                break
    if not label_col:
        for col in df.columns:
            if df[col].dtype in ('int64','float64','bool'):
                unique = df[col].dropna().unique()
                if len(unique) <= 3:
                    label_col = col
                    break

    if not url_col or not label_col:
        print(f"\n  ERROR: Could not auto-detect URL or label columns.")
        print(f"  Columns found: {list(df.columns)}")
        print(f"  Please check your CSV file structure.")
        sys.exit(1)

    print(f"  URL column:   '{url_col}'")
    print(f"  Label column: '{label_col}'")

    # Normalise labels to 0/1
    raw_labels = df[label_col].dropna().unique()
    print(f"  Label values: {raw_labels[:10]}")

    def normalize_label(v):
        v = str(v).lower().strip()
        if v in ('1', 'phishing', 'phish', 'malicious', 'bad', 'yes', 'true', 'p'):
            return 1
        if v in ('0', 'legitimate', 'legit', 'benign', 'safe', 'good', 'no', 'false', 'l'):
            return 0
        try:
            return int(float(v))
        except Exception:
            return None

    df['_label'] = df[label_col].apply(normalize_label)
    df['_url']   = df[url_col].astype(str)
    df = df.dropna(subset=['_label'])
    df['_label'] = df['_label'].astype(int)

    n_phish = (df['_label'] == 1).sum()
    n_legit = (df['_label'] == 0).sum()
    print(f"  Legitimate: {n_legit:,}  |  Phishing: {n_phish:,}")

    return df['_url'].tolist(), df['_label'].tolist()


def extract_features_batch(urls, labels, batch_size=5000):
    """Extract features in batches with progress reporting."""
    X, y, failed = [], [], 0
    total = len(urls)

    print(f"\nExtracting features from {total:,} URLs...")
    t0 = time.time()

    for i in range(0, total, batch_size):
        batch_urls   = urls[i:i+batch_size]
        batch_labels = labels[i:i+batch_size]

        for url, label in zip(batch_urls, batch_labels):
            try:
                fv = feature_vector(str(url).strip())
                X.append(fv)
                y.append(int(label))
            except Exception:
                failed += 1

        pct      = min((i + batch_size) / total * 100, 100)
        elapsed  = time.time() - t0
        eta      = (elapsed / max(i+batch_size, 1)) * (total - i - batch_size)
        print(f"  {pct:5.1f}%  [{i+len(batch_urls):,}/{total:,}]  "
              f"elapsed: {elapsed:.0f}s  eta: {max(eta,0):.0f}s  failed: {failed}",
              end='\r')

    print(f"\n  Done. {len(X):,} features extracted, {failed:,} skipped.")
    return np.array(X, dtype=float), np.array(y, dtype=int)


def train(X_train, y_train, X_test, y_test):
    """Train RF + GB ensemble."""
    os.makedirs(MODEL_DIR, exist_ok=True)

    print("\nScaling features...")
    scaler   = StandardScaler()
    X_tr_s   = scaler.fit_transform(X_train)
    X_te_s   = scaler.transform(X_test)

    print(f"Training Random Forest on {len(y_train):,} samples...")
    t0 = time.time()
    rf = RandomForestClassifier(
        n_estimators   = 500,
        max_depth      = 15,
        min_samples_leaf= 3,
        max_features   = "sqrt",
        class_weight   = "balanced",
        random_state   = 42,
        n_jobs         = -1,
        verbose        = 1,
    )
    rf.fit(X_tr_s, y_train)
    print(f"  Done in {time.time()-t0:.0f}s")

    print(f"\nTraining Gradient Boosting on {len(y_train):,} samples...")
    t0 = time.time()
    gb = GradientBoostingClassifier(
        n_estimators   = 300,
        max_depth      = 7,
        learning_rate  = 0.05,
        subsample      = 0.8,
        min_samples_leaf= 5,
        random_state   = 42,
        verbose        = 1,
    )
    gb.fit(X_tr_s, y_train)
    print(f"  Done in {time.time()-t0:.0f}s")

    return rf, gb, scaler, X_te_s


def evaluate(rf, gb, scaler, X_test_s, y_test):
    """Print full evaluation metrics."""
    print("\n" + "="*60)
    print("EVALUATION RESULTS")
    print("="*60)

    rf_probs  = rf.predict_proba(X_test_s)[:,1]
    gb_probs  = gb.predict_proba(X_test_s)[:,1]
    ens_probs = rf_probs * 0.55 + gb_probs * 0.45
    ens_preds = (ens_probs > 0.5).astype(int)

    acc   = accuracy_score(y_test, ens_preds)
    f1    = f1_score(y_test, ens_preds)
    auc   = roc_auc_score(y_test, ens_probs)

    print(f"\nEnsemble (RF 55% + GB 45%):")
    print(f"  Accuracy:  {acc*100:.2f}%")
    print(f"  F1 Score:  {f1:.4f}")
    print(f"  ROC-AUC:   {auc:.4f}")

    print(f"\nClassification Report:")
    print(classification_report(y_test, ens_preds,
                                target_names=['Legitimate','Phishing']))

    cm = confusion_matrix(y_test, ens_preds)
    tn, fp, fn, tp = cm.ravel()
    print(f"Confusion Matrix:")
    print(f"  True Negatives  (correct legit):   {tn:,}")
    print(f"  False Positives (legit → phishing): {fp:,}  ← false alarms")
    print(f"  False Negatives (phishing → legit): {fn:,}  ← missed threats")
    print(f"  True Positives  (correct phishing): {tp:,}")

    print(f"\nTop 15 Most Important Features (Random Forest):")
    imp = sorted(zip(FEATURE_NAMES, rf.feature_importances_),
                 key=lambda x: x[1], reverse=True)
    for name, val in imp[:15]:
        bar = "█" * int(val * 400)
        print(f"  {name:<35} {val:.4f}  {bar}")

    return acc, f1, auc


def validate_problem_cases(rf, gb, scaler):
    """Check our known problem cases still work."""
    print("\n" + "="*60)
    print("VALIDATION — Known Problem Cases")
    print("="*60)

    ok = fail = 0
    for url, expected in VALIDATION_CASES:
        try:
            fv        = feature_vector(url)
            X_s       = scaler.transform([fv])
            rf_p      = rf.predict_proba(X_s)[0][1]
            gb_p      = gb.predict_proba(X_s)[0][1]
            ens_p     = rf_p * 0.55 + gb_p * 0.45
            predicted = 1 if ens_p > 0.5 else 0
            correct   = predicted == expected
            if correct: ok += 1
            else:       fail += 1
            label     = "SAFE" if expected == 0 else "PHISHING"
            mark      = "✓" if correct else "✗ FAIL"
            print(f"  {mark} [{label:8}] p={ens_p:.3f} | {url[:65]}")
        except Exception as e:
            fail += 1
            print(f"  ✗ ERROR | {url[:60]} — {e}")

    print(f"\n  Validation: {ok}/{ok+fail} = {ok/(ok+fail)*100:.0f}%")


def save_models(rf, gb, scaler):
    """Save trained models and metadata."""
    joblib.dump(rf,     os.path.join(MODEL_DIR, "rf_model.joblib"))
    joblib.dump(gb,     os.path.join(MODEL_DIR, "gb_model.joblib"))
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.joblib"))
    with open(os.path.join(MODEL_DIR, "feature_names.json"), "w") as f:
        json.dump(FEATURE_NAMES, f)
    with open(os.path.join(MODEL_DIR, "model_info.json"), "w") as f:
        json.dump({
            "trained_on": "PhishUSIIL Kaggle Dataset",
            "source": "https://www.kaggle.com/datasets/kaggleprollc/phishing-url-websites-dataset-phiusiil",
            "features": len(FEATURE_NAMES),
            "feature_names": FEATURE_NAMES,
        }, f, indent=2)
    print(f"\n  Models saved to: {MODEL_DIR}")


def main():
    print("=" * 60)
    print("PhishGuard v4 — Real Dataset Training")
    print("Dataset: PhishUSIIL (Kaggle)")
    print("=" * 60)

    # Load dataset
    urls, labels = load_dataset(CSV_FILE, max_rows=MAX_ROWS)

    # Extract features
    X, y = extract_features_batch(urls, labels)

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"\nTrain: {len(y_train):,}  |  Test: {len(y_test):,}")

    # Train
    rf, gb, scaler, X_test_s = train(X_train, y_train, X_test, y_test)

    # Evaluate
    acc, f1, auc = evaluate(rf, gb, scaler, X_test_s, y_test)

    # Validate
    validate_problem_cases(rf, gb, scaler)

    # Save
    save_models(rf, gb, scaler)

    print("\n" + "=" * 60)
    print(f"TRAINING COMPLETE")
    print(f"  Accuracy: {acc*100:.2f}%  F1: {f1:.4f}  AUC: {auc:.4f}")
    print(f"  Replace your models/ folder with the new files.")
    print("=" * 60)


if __name__ == "__main__":
    main()
