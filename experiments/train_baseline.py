#!/usr/bin/env python3
"""Train a RandomForest baseline on sliding-window tabular features."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from experiments.split_utils import prepare_split_frame, time_split_boundary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--features", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--out", default="models/rf_baseline.joblib")
    parser.add_argument("--metrics-out", default="models/rf_baseline_metrics.json")
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--split-strategy", choices=["auto", "time", "random"], default="auto")
    parser.add_argument("--allow-overlap-windows", action="store_true")
    parser.add_argument("--sampling-phase", type=int, default=0)
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
            for column in (
                "label",
                "start",
                "end",
                "start_ts",
                "end_ts",
                "session_index",
                "timeline_index",
                "dominant_comm",
                "_order_ts",
                "_order_session",
                "_order_fallback",
                "_ordered_row_id",
            )
            if column in merged.columns
        ]
    )
    numeric = feature_frame.select_dtypes(include=["number", "bool"]).fillna(0)
    if numeric.empty:
        raise SystemExit("no numeric features available after preprocessing")
    return numeric, label


def choose_split_indices(
    labels: np.ndarray,
    sample_count: int,
    args: argparse.Namespace,
) -> tuple[list[int], list[int], str]:
    """Pick a train/test split while preferring chronological holdout."""
    all_classes = set(labels.tolist())

    if args.split_strategy in {"auto", "time"}:
        split_at = time_split_boundary(sample_count, args.test_size)
        train_idx = list(range(split_at))
        test_idx = list(range(split_at, sample_count))
        train_classes = set(labels[train_idx].tolist())
        test_classes = set(labels[test_idx].tolist())
        if args.split_strategy == "time" or (train_classes == all_classes and test_classes):
            return train_idx, test_idx, "time"
        print("[*] time split would drop class coverage; falling back to random split")

    stratify = labels if len(all_classes) > 1 else None
    try:
        train_idx, test_idx = train_test_split(
            list(range(sample_count)),
            test_size=args.test_size,
            random_state=args.random_state,
            stratify=stratify,
        )
    except ValueError:
        train_idx, test_idx = train_test_split(
            list(range(sample_count)),
            test_size=args.test_size,
            random_state=args.random_state,
            stratify=None,
        )
    return sorted(train_idx), sorted(test_idx), "random"


def main() -> None:
    args = parse_args()

    features = pd.read_parquet(args.features)
    labels = pd.read_csv(args.labels)
    merged = merge_features_and_labels(features, labels)
    prepared, disjoint_step = prepare_split_frame(
        merged,
        allow_overlap_windows=args.allow_overlap_windows,
        sampling_phase=args.sampling_phase,
    )
    if prepared.empty:
        raise SystemExit("no samples remain after overlap filtering")
    if len(prepared) != len(merged):
        print(f"[*] overlap-aware downsampling kept {len(prepared)}/{len(merged)} windows (step={disjoint_step})")

    X, y = build_feature_matrix(prepared)

    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)
    train_idx, test_idx, effective_split = choose_split_indices(y_encoded, len(X), args)
    X_train = X.iloc[train_idx]
    X_test = X.iloc[test_idx]
    y_train = y_encoded[train_idx]
    y_test = y_encoded[test_idx]

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
        "split_strategy": effective_split,
        "allow_overlap_windows": args.allow_overlap_windows,
        "disjoint_step": disjoint_step,
        "samples_before_filter": int(len(merged)),
        "samples_after_filter": int(len(prepared)),
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
