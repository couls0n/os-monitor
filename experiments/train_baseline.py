#!/usr/bin/env python3
"""Train a RandomForest baseline on sliding-window tabular features."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Tuple

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--features", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--out", default="models/rf_baseline.joblib")
    parser.add_argument("--metrics-out", default="models/rf_baseline_metrics.json")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


def merge_features_and_labels(features: pd.DataFrame, labels: pd.DataFrame) -> pd.DataFrame:
    """Merge on session_index when possible, otherwise fall back to start."""
    if "session_index" in features.columns and "session_index" in labels.columns:
        merged = pd.merge(features, labels, on="session_index", how="inner")
    else:
        merged = pd.merge(features, labels, on="start", how="inner")

    if merged.empty:
        raise SystemExit("merged dataset is empty; check labels and feature identifiers")
    return merged


def build_feature_matrix(merged: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """Separate numeric features from the label column without leakage."""
    label = merged["label"]
    feature_frame = merged.drop(
        columns=[
            column
            for column in ("label", "start", "end", "dominant_comm")
            if column in merged.columns
        ]
    )
    numeric = feature_frame.select_dtypes(include=["number", "bool"]).fillna(0)
    if numeric.empty:
        raise SystemExit("no numeric features available after preprocessing")
    return numeric, label


def main() -> None:
    args = parse_args()

    features = pd.read_parquet(args.features)
    labels = pd.read_csv(args.labels)
    merged = merge_features_and_labels(features, labels)
    X, y = build_feature_matrix(merged)

    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)

    stratify = y_encoded if len(set(y_encoded)) > 1 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=stratify,
    )

    clf = RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced",
        random_state=args.random_state,
        n_jobs=-1,
    )
    print(f"[*] training RandomForest on {len(X_train)} samples")
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    metrics = {
        "classes": encoder.classes_.tolist(),
        "classification_report": classification_report(
            y_test,
            y_pred,
            target_names=encoder.classes_.tolist(),
            output_dict=True,
            zero_division=0,
        ),
    }

    if hasattr(clf, "predict_proba"):
        probabilities = clf.predict_proba(X_test)
        try:
            if len(encoder.classes_) == 2:
                metrics["roc_auc"] = float(roc_auc_score(y_test, probabilities[:, 1]))
            else:
                metrics["roc_auc_ovr"] = float(
                    roc_auc_score(y_test, probabilities, multi_class="ovr")
                )
        except ValueError:
            pass

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": clf,
            "label_encoder": encoder,
            "feature_columns": X.columns.tolist(),
        },
        out_path,
    )
    print("wrote model to", str(out_path))

    metrics_path = Path(args.metrics_out)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    with metrics_path.open("w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2, ensure_ascii=False)
    print("wrote metrics to", str(metrics_path))


if __name__ == "__main__":
    main()
