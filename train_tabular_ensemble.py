"""
train_tabular_ensemble.py

Train a strong tabular-only ensemble (NO RandomForest) for phishing detection.
- Advanced URL feature extraction
- Out-of-fold (OOF) training for LightGBM, XGBoost and CatBoost
- OOF stacking using LogisticRegression meta-model
- Optuna hyperparameter tuning (for LightGBM by default)
- Probability calibration and threshold tuning (F1-optimized)
- Saves models and OOF predictions to `models/`

Usage:
    python train_tabular_ensemble.py
"""

import os
import re
import math
import joblib
import random
import optuna
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from sklearn.model_selection import StratifiedKFold
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_recall_fscore_support, classification_report
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV
import category_encoders as ce

# Try imports (optional)
try:
    import lightgbm as lgb
except Exception as e:
    raise RuntimeError("Install lightgbm: pip install lightgbm") from e
try:
    import xgboost as xgb
except:
    xgb = None
try:
    from catboost import CatBoostClassifier
except:
    CatBoostClassifier = None

from imblearn.over_sampling import SMOTE

# -----------------------
# Paths (adjusted for your project)
# -----------------------
BASE = r"C:\Users\ibnsi\Downloads\Real-Time-Detection-of-Phishing-Scam-Fraudulent-and-Legitimate-Websites-Using-Machine-Learning-main\PhishingDetector"
DATA_PATH = os.path.join(BASE, "data", "balanced_dataset.csv")
FEATURES_OUT = os.path.join(BASE, "data", "features.csv")
MODELS_DIR = os.path.join(BASE, "models")
os.makedirs(MODELS_DIR, exist_ok=True)

# -----------------------
# Feature extraction
# -----------------------
SUSPICIOUS_TOKENS = ["login", "secure", "signin", "verify", "account", "update", "bank", "payment", "confirm", "auth", "password", "verifyaccount", "security"]

def entropy_str(s: str):
    if not s:
        return 0.0
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs if p > 0)

def extract_url_features(url: str):
    # ensure scheme
    try:
        if not url.startswith("http"):
            url = "http://" + url
        parsed = urlparse(url)
    except Exception:
        parsed = urlparse("")

    host = (parsed.netloc or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = (parsed.scheme or "").lower()

    host_no_port = host.split(':')[0]
    tld = host_no_port.split('.')[-1] if '.' in host_no_port else host_no_port

    # numeric counts
    digits = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    url_len = len(url)
    host_len = len(host_no_port)
    path_len = len(path)
    query_len = len(query)
    hyphens = host_no_port.count('-')
    dots = host_no_port.count('.')

    # booleans
    has_https = 1 if scheme == 'https' else 0
    has_ip = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', host_no_port) else 0
    is_shortened = int(any(s in host_no_port for s in ['bit.ly','tinyurl','goo.gl','t.co','ow.ly','is.gd','buff.ly']))
    suspicious_token_count = sum(token in url.lower() for token in SUSPICIOUS_TOKENS)

    # ratios and entropy
    digit_ratio = digits / url_len if url_len else 0.0
    letter_ratio = letters / url_len if url_len else 0.0
    host_entropy = entropy_str(host_no_port)
    url_entropy = entropy_str(url)

    # features map
    feats = {
        "url": url,
        "host": host_no_port,
        "tld": tld,
        "url_length": url_len,
        "host_length": host_len,
        "path_length": path_len,
        "query_length": query_len,
        "num_digits": digits,
        "num_letters": letters,
        "digit_ratio": digit_ratio,
        "letter_ratio": letter_ratio,
        "num_hyphens": hyphens,
        "num_dots": dots,
        "has_https": has_https,
        "has_ip": has_ip,
        "is_shortened": is_shortened,
        "suspicious_token_count": suspicious_token_count,
        "host_entropy": host_entropy,
        "url_entropy": url_entropy
    }
    return feats

# -----------------------
# Load & build features (will save features.csv)
# -----------------------
def build_features(input_csv=DATA_PATH, out_csv=FEATURES_OUT, force=False):
    if os.path.exists(out_csv) and not force:
        print(f"[+] Features file already exists: {out_csv}")
        return pd.read_csv(out_csv)
    df = pd.read_csv(input_csv)
    print(f"[+] Loaded dataset: {df.shape}")

    # Extract features
    feats = df['url'].apply(extract_url_features).apply(pd.Series)
    merged = pd.concat([df.reset_index(drop=True), feats.drop(columns=['url'])], axis=1)
    # Add some engineered features
    merged['host_token_count'] = merged['host'].apply(lambda x: len(x.split('.')))
    merged['contains_at'] = merged['url'].str.contains('@').astype(int)
    merged['contains_percent'] = merged['url'].str.contains('%').astype(int)
    merged['contains_www'] = merged['host'].str.contains('www').astype(int)
    # frequency encoding for TLD
    merged['tld_freq'] = merged['tld'].map(merged['tld'].value_counts()).fillna(0)
    # Drop long text columns not needed
    merged = merged.drop(columns=['host'])
    merged.to_csv(out_csv, index=False)
    print(f"[+] Features saved to {out_csv} with shape {merged.shape}")
    return merged

# -----------------------
# Training utilities
# -----------------------
def get_feature_matrix(df):
    # numerical features and a categorical 'tld'
    drop_cols = ['url', 'label']
    cat_cols = ['tld']
    feature_cols = [c for c in df.columns if c not in drop_cols and c not in cat_cols]
    X_num = df[feature_cols].fillna(0)
    # frequency-encode tld (already have tld_freq) but we'll also cat-encode for robustness
    tld_encoder = ce.TargetEncoder(cols=cat_cols)
    X_cat = tld_encoder.fit_transform(df[cat_cols], df['label'])
    X = pd.concat([X_num.reset_index(drop=True), X_cat.reset_index(drop=True)], axis=1)
    return X, df['label'], feature_cols + list(X_cat.columns), tld_encoder

def f1_threshold_search(y_true, y_proba):
    best_t, best_f1 = 0.5, 0.0
    for t in np.linspace(0.01, 0.99, 99):
        preds = (y_proba >= t).astype(int)
        f1 = f1_score(y_true, preds)
        if f1 > best_f1:
            best_f1 = f1
            best_t = t
    return best_t, best_f1

# -----------------------
# Optuna tuning for LightGBM
# -----------------------
def tune_lgb(X, y, n_trials=30, random_state=42):
    def objective(trial):
        params = {
            'objective': 'binary',
            'metric': 'binary_logloss',
            'verbosity': -1,
            'boosting_type': 'gbdt',
            'seed': random_state,
            'lambda_l1': trial.suggest_loguniform('lambda_l1', 1e-8, 10.0),
            'lambda_l2': trial.suggest_loguniform('lambda_l2', 1e-8, 10.0),
            'num_leaves': trial.suggest_int('num_leaves', 16, 128),
            'feature_fraction': trial.suggest_uniform('feature_fraction', 0.4, 1.0),
            'bagging_fraction': trial.suggest_uniform('bagging_fraction', 0.4, 1.0),
            'bagging_freq': trial.suggest_int('bagging_freq', 1, 7),
            'min_child_samples': trial.suggest_int('min_child_samples', 5, 100),
            'learning_rate': trial.suggest_loguniform('learning_rate', 1e-3, 0.2)
        }
        skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=random_state)
        f1s = []
        for tr_idx, va_idx in skf.split(X, y):
            dtrain = lgb.Dataset(X.iloc[tr_idx], label=y.iloc[tr_idx])
            booster = lgb.train(
                params,
                dtrain,
                num_boost_round=1000,
                valid_sets=[dtrain],
                callbacks=[
                    lgb.early_stopping(stopping_rounds=50),
                    lgb.log_evaluation(period=0)
                ]
            )
            y_hat = booster.predict(X.iloc[va_idx], num_iteration=booster.best_iteration)
            _, f1 = f1_threshold_search(y.iloc[va_idx], y_hat)
            f1s.append(f1)
        return np.mean(f1s)

    study = optuna.create_study(direction='maximize')
    study.optimize(objective, n_trials=n_trials)
    print("[+] Best LightGBM params:", study.best_params)
    return study.best_params

# -----------------------
# OOF training for base models
# -----------------------
def train_oof_models(X, y, n_splits=5, random_state=42, tune=False):
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    oof_preds = {
        'lgb': np.zeros(len(X)),
        'xgb': np.zeros(len(X)) if xgb else None,
        'cat': np.zeros(len(X)) if CatBoostClassifier else None
    }
    models = {'lgb': [], 'xgb': [], 'cat': []}

    # Optionally tune lgb
    lgb_params = {
        'objective': 'binary', 'metric':'binary_logloss', 'verbosity': -1,
        'num_leaves': 64, 'learning_rate': 0.05, 'n_estimators': 1000,
        'subsample': 0.8, 'colsample_bytree': 0.8, 'random_state': random_state
    }
    if tune:
        best = tune_lgb(X, y, n_trials=25, random_state=random_state)
        lgb_params.update(best)
        lgb_params['n_estimators'] = 2000

    for fold, (tr_idx, va_idx) in enumerate(skf.split(X, y)):
        X_tr, X_va = X.iloc[tr_idx], X.iloc[va_idx]
        y_tr, y_va = y.iloc[tr_idx], y.iloc[va_idx]

        # Optionally balance (SMOTE) on training folds only
        sm = SMOTE(random_state=random_state)
        X_tr_bal, y_tr_bal = sm.fit_resample(X_tr, y_tr)

        # LightGBM
        clf_lgb = lgb.LGBMClassifier(**lgb_params)
        clf_lgb.fit(X_tr_bal, y_tr_bal, eval_set=[(X_va, y_va)], early_stopping_rounds=100, verbose=100)
        oof_preds['lgb'][va_idx] = clf_lgb.predict_proba(X_va)[:,1]
        models['lgb'].append(clf_lgb)

        # XGBoost
        if xgb:
            clf_xgb = xgb.XGBClassifier(
                objective='binary:logistic',
                eval_metric='logloss',
                use_label_encoder=False,
                n_estimators=1000,
                learning_rate=0.05,
                max_depth=6,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=random_state
            )
            clf_xgb.fit(X_tr_bal, y_tr_bal, eval_set=[(X_va, y_va)], early_stopping_rounds=100, verbose=100)
            oof_preds['xgb'][va_idx] = clf_xgb.predict_proba(X_va)[:,1]
            models['xgb'].append(clf_xgb)

        # CatBoost
        if CatBoostClassifier:
            clf_cat = CatBoostClassifier(
                iterations=2000,
                learning_rate=0.03,
                depth=6,
                eval_metric='Logloss',
                early_stopping_rounds=100,
                verbose=100,
                random_seed=random_state
            )
            clf_cat.fit(X_tr_bal, y_tr_bal, eval_set=(X_va, y_va), use_best_model=True)
            oof_preds['cat'][va_idx] = clf_cat.predict_proba(X_va)[:,1]
            models['cat'].append(clf_cat)

        print(f"[fold {fold}] done")

    return oof_preds, models

# -----------------------
# Stack meta-model training
# -----------------------
def train_meta_and_evaluate(oof_preds, y, models, X_full, tld_encoder):
    # Build stack feature matrix
    stack_cols = []
    stack_arrays = []
    for k, arr in oof_preds.items():
        if arr is None:
            continue
        name = f"oof_{k}"
        stack_cols.append(name)
        stack_arrays.append(arr.reshape(-1,1))
    stack_X = np.hstack(stack_arrays)

    # Optionally add a few strong tabular features to stack
    extras = X_full[['url_length','host_length','suspicious_token_count','tld_freq']].values
    stack_X = np.hstack([stack_X, extras])

    # Meta model
    meta = LogisticRegression(class_weight='balanced', max_iter=2000)
    meta.fit(stack_X, y)
    meta_probas = meta.predict_proba(stack_X)[:,1]
    best_t, best_f1 = f1_threshold_search(y, meta_probas)

    print("\n===== STACK METRICS (OOF) =====")
    preds = (meta_probas >= best_t).astype(int)
    print("Threshold:", best_t)
    print(classification_report(y, preds, digits=4))
    print("F1:", best_f1)

    # Save meta + base models
    joblib.dump(meta, os.path.join(MODELS_DIR, "meta_logreg.joblib"))
    joblib.dump(models, os.path.join(MODELS_DIR, "base_models.joblib"))
    print("[+] Saved meta and base models")
    return meta, best_t

# -----------------------
# Main
# -----------------------
def main():
    df = build_features()
    # Keep a small holdout test if you want. For now use full OOF CV
    X, y, feat_cols, tld_encoder = None, None, None, None
    X, y, feat_cols, tld_encoder = get_feature_matrix(df)
    print("[+] Feature matrix shape:", X.shape)

    # Standardize numeric columns
    scaler = StandardScaler()
    X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.joblib"))

    # Train OOF base models
    oof_preds, models = train_oof_models(X_scaled, y, n_splits=5, random_state=42, tune=True)

    # Train meta model and evaluate OOF
    meta, threshold = train_meta_and_evaluate(oof_preds, y, models, X_scaled, tld_encoder)

    # Save tld encoder and final artifacts
    joblib.dump(tld_encoder, os.path.join(MODELS_DIR, "tld_target_encoder.joblib"))
    print("[+] All artifacts saved in:", MODELS_DIR)

if __name__ == "__main__":
    main()