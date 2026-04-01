import os
import json
import numpy as np
import joblib

_dir = os.path.dirname(os.path.abspath(__file__))

model = joblib.load(os.path.join(_dir, "model", "model.joblib"))

with open(os.path.join(_dir, "model", "feature_cols.json")) as f:
    feature_cols = json.load(f)

with open(os.path.join(_dir, "model", "category_map.json")) as f:
    category_map = json.load(f)

with open(os.path.join(_dir, "model", "content_rating_map.json")) as f:
    content_rating_map = json.load(f)

with open(os.path.join(_dir, "model", "primary_genre_map.json")) as f:
    primary_genre_map = json.load(f)

_LABEL_MAP = {0: "Poor", 1: "Average", 2: "Good"}

_HUMAN_LABELS = {
    "Category_Enc": "Category",
    "Log_Reviews": "Number of Reviews",
    "Size_MB": "App Size (MB)",
    "Log_Installs": "Install Count",
    "Is_Free": "Free vs Paid",
    "Price_Clean": "Price (USD)",
    "Content_Rating_Enc": "Content Rating",
    "Primary_Genre_Enc": "Primary Genre",
    "Days_Since_Update": "Days Since Last Update",
    "Min_Android_Ver": "Min Android Version",
}


def predict(form_data: dict) -> dict:
    try:
        category_enc = category_map[form_data["category"]]
    except KeyError:
        return {"error": f"Unknown category: {form_data['category']}"}

    try:
        content_rating_enc = content_rating_map[form_data["content_rating"]]
    except KeyError:
        return {"error": f"Unknown content rating: {form_data['content_rating']}"}

    try:
        primary_genre_enc = primary_genre_map[form_data["primary_genre"]]
    except KeyError:
        return {"error": f"Unknown primary genre: {form_data['primary_genre']}"}

    log_reviews = np.log1p(float(form_data["reviews"]))
    log_installs = np.log1p(float(form_data["installs"]))

    feature_values = {
        "Category_Enc": category_enc,
        "Log_Reviews": log_reviews,
        "Size_MB": float(form_data["size_mb"]),
        "Log_Installs": log_installs,
        "Is_Free": int(form_data["is_free"]),
        "Price_Clean": float(form_data["price"]),
        "Content_Rating_Enc": content_rating_enc,
        "Primary_Genre_Enc": primary_genre_enc,
        "Days_Since_Update": int(form_data["days_since_update"]),
        "Min_Android_Ver": float(form_data["min_android_ver"]),
    }

    X = np.array([[feature_values[col] for col in feature_cols]])
    pred_class = int(model.predict(X)[0])
    proba = model.predict_proba(X)[0]

    classes = model.classes_
    prob_dict = {}
    for i, cls in enumerate(classes):
        prob_dict[_LABEL_MAP[int(cls)]] = float(proba[i])

    return {
        "label": _LABEL_MAP[pred_class],
        "class": pred_class,
        "probabilities": {
            "Poor": prob_dict.get("Poor", 0.0),
            "Average": prob_dict.get("Average", 0.0),
            "Good": prob_dict.get("Good", 0.0),
        },
        "confidence": float(max(proba) * 100),
    }


def get_feature_importances() -> list:
    importances = model.feature_importances_
    total = sum(importances)
    result = []
    for col, imp in zip(feature_cols, importances):
        result.append({
            "feature": col,
            "label": _HUMAN_LABELS.get(col, col),
            "importance": float(imp),
            "importance_pct": float(imp / total * 100) if total > 0 else 0.0,
        })
    result.sort(key=lambda x: x["importance"], reverse=True)
    return result
