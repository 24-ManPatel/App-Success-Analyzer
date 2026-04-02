import os
import json
import numpy as np
import joblib

_dir = os.path.dirname(os.path.abspath(__file__))

# ── Primary model (XGBoost) ──────────────────────────────────
model = joblib.load(os.path.join(_dir, "model", "model.joblib"))

# ── Additional models ─────────────────────────────────────────
rf_model   = joblib.load(os.path.join(_dir, "model", "rf_model.joblib"))
lgbm_model = joblib.load(os.path.join(_dir, "model", "lgbm_model.joblib"))

# ── Encodings & feature order ─────────────────────────────────
with open(os.path.join(_dir, "model", "feature_cols.json")) as f:
    feature_cols = json.load(f)

with open(os.path.join(_dir, "model", "category_map.json")) as f:
    category_map = json.load(f)

with open(os.path.join(_dir, "model", "content_rating_map.json")) as f:
    content_rating_map = json.load(f)

with open(os.path.join(_dir, "model", "primary_genre_map.json")) as f:
    primary_genre_map = json.load(f)

with open(os.path.join(_dir, "model", "rf_feature_importance.json")) as f:
    _rf_fi_raw = json.load(f)

with open(os.path.join(_dir, "model", "lgbm_feature_importance.json")) as f:
    _lgbm_fi_raw = json.load(f)

_LABEL_MAP = {0: "Poor", 1: "Average", 2: "Good"}

_HUMAN_LABELS = {
    "Category_Enc":      "Category",
    "Log_Reviews":       "Number of Reviews",
    "Size_MB":           "App Size (MB)",
    "Log_Installs":      "Install Count",
    "Is_Free":           "Free vs Paid",
    "Price_Clean":       "Price (USD)",
    "Content_Rating_Enc":"Content Rating",
    "Primary_Genre_Enc": "Primary Genre",
    "Days_Since_Update": "Days Since Last Update",
    "Min_Android_Ver":   "Min Android Version",
}

MODEL_META = {
    "xgb":  {"name": "XGBoost",       "accuracy": 80.18},
    "rf":   {"name": "Random Forest",  "accuracy": 78.50},
    "lgbm": {"name": "LightGBM",       "accuracy": 79.80},
}


# ── Internal helpers ──────────────────────────────────────────
def _encode(form_data: dict):
    """Encode categorical fields and build feature vector. Returns (X, error_str)."""
    try:
        cat_enc = category_map[form_data["category"]]
    except KeyError:
        return None, f"Unknown category: {form_data['category']}"
    try:
        cr_enc = content_rating_map[form_data["content_rating"]]
    except KeyError:
        return None, f"Unknown content rating: {form_data['content_rating']}"
    try:
        pg_enc = primary_genre_map[form_data["primary_genre"]]
    except KeyError:
        return None, f"Unknown primary genre: {form_data['primary_genre']}"

    price_raw = form_data.get("price", "") or "0"
    fv = {
        "Category_Enc":      cat_enc,
        "Log_Reviews":       np.log1p(float(form_data["reviews"])),
        "Size_MB":           float(form_data["size_mb"]),
        "Log_Installs":      np.log1p(float(form_data["installs"])),
        "Is_Free":           int(form_data["is_free"]),
        "Price_Clean":       float(price_raw),
        "Content_Rating_Enc":cr_enc,
        "Primary_Genre_Enc": pg_enc,
        "Days_Since_Update": int(form_data["days_since_update"]),
        "Min_Android_Ver":   float(form_data["min_android_ver"]),
    }
    X = np.array([[fv[col] for col in feature_cols]])
    return X, None


def _predict_with(mdl, X) -> dict:
    pred_class = int(mdl.predict(X)[0])
    proba      = mdl.predict_proba(X)[0]
    prob_dict  = {}
    for i, cls in enumerate(mdl.classes_):
        prob_dict[_LABEL_MAP[int(cls)]] = float(proba[i])
    return {
        "label": _LABEL_MAP[pred_class],
        "class": pred_class,
        "probabilities": {
            "Poor":    prob_dict.get("Poor",    0.0),
            "Average": prob_dict.get("Average", 0.0),
            "Good":    prob_dict.get("Good",    0.0),
        },
        "confidence": float(max(proba) * 100),
    }


# ── Public API ────────────────────────────────────────────────
def predict(form_data: dict) -> dict:
    """Predict using the primary XGBoost model."""
    X, err = _encode(form_data)
    if err:
        return {"error": err}
    return _predict_with(model, X)


def predict_all(form_data: dict) -> dict:
    """Run all 3 models and return results keyed by model id."""
    X, err = _encode(form_data)
    if err:
        return {"error": err}
    return {
        "xgb":  _predict_with(model,      X),
        "rf":   _predict_with(rf_model,   X),
        "lgbm": _predict_with(lgbm_model, X),
    }


def get_feature_importances() -> list:
    """XGBoost feature importances."""
    return _fi_list(model.feature_importances_)


def get_all_feature_importances() -> dict:
    """Feature importances for all 3 models, normalised to %."""
    xgb_raw = model.feature_importances_

    lgbm_vals = np.array([_lgbm_fi_raw.get(c, 0.0) for c in feature_cols], dtype=float)
    rf_vals   = np.array([_rf_fi_raw.get(c,   0.0) for c in feature_cols], dtype=float)

    return {
        "xgb":  _fi_list(xgb_raw),
        "rf":   _fi_list(rf_vals),
        "lgbm": _fi_list(lgbm_vals),
    }


def _fi_list(raw_importances) -> list:
    total = float(sum(raw_importances)) or 1.0
    result = []
    for col, imp in zip(feature_cols, raw_importances):
        result.append({
            "feature":        col,
            "label":          _HUMAN_LABELS.get(col, col),
            "importance":     float(imp),
            "importance_pct": float(imp) / total * 100,
        })
    result.sort(key=lambda x: x["importance"], reverse=True)
    return result
