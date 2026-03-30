#!/usr/bin/env python3
"""Helpers for safer training/evaluation splits on sliding-window data."""

from __future__ import annotations

import math
from typing import Tuple

import pandas as pd


def _parsed_start_seconds(frame: pd.DataFrame) -> pd.Series:
    if "start_ts" in frame.columns:
        values = pd.to_numeric(frame["start_ts"], errors="coerce")
        if values.notna().any():
            return values

    if "start" in frame.columns:
        parsed = pd.to_datetime(frame["start"], utc=True, errors="coerce")
        if parsed.notna().any():
            return pd.Series(
                [
                    value.timestamp() if not pd.isna(value) else float("nan")
                    for value in parsed
                ],
                index=frame.index,
                dtype="float64",
            )

    if "session_index" in frame.columns:
        values = pd.to_numeric(frame["session_index"], errors="coerce")
        if values.notna().any():
            return values.astype("float64")

    return pd.Series(range(len(frame)), index=frame.index, dtype="float64")


def infer_disjoint_step(frame: pd.DataFrame) -> int:
    """Infer how many overlapping windows share the same events."""
    if "window_ms" not in frame.columns or "stride_ms" not in frame.columns:
        return 1

    window_values = pd.to_numeric(frame["window_ms"], errors="coerce").dropna()
    stride_values = pd.to_numeric(frame["stride_ms"], errors="coerce").dropna()
    if window_values.empty or stride_values.empty:
        return 1

    window_ms = int(window_values.mode().iloc[0])
    stride_ms = int(stride_values.mode().iloc[0])
    if window_ms <= 0 or stride_ms <= 0:
        return 1

    return max(1, math.ceil(window_ms / stride_ms))


def prepare_split_frame(
    frame: pd.DataFrame,
    *,
    allow_overlap_windows: bool,
    sampling_phase: int = 0,
) -> Tuple[pd.DataFrame, int]:
    """Sort rows chronologically and optionally drop overlapping windows."""
    ordered = frame.copy().reset_index(drop=True)
    ordered["_order_ts"] = _parsed_start_seconds(ordered)
    ordered["_order_session"] = pd.to_numeric(
        ordered.get("session_index"),
        errors="coerce",
    )
    ordered["_order_fallback"] = range(len(ordered))
    ordered = ordered.sort_values(
        by=["_order_ts", "_order_session", "_order_fallback"],
        na_position="last",
    ).reset_index(drop=True)

    step = 1
    if not allow_overlap_windows:
        step = infer_disjoint_step(ordered)
        if step > 1:
            phase = sampling_phase % step
            ordered = ordered.iloc[phase::step].reset_index(drop=True)

    ordered["_ordered_row_id"] = range(len(ordered))
    return ordered, step


def time_split_boundary(sample_count: int, test_size: float) -> int:
    """Return the boundary index for a chronological holdout split."""
    if sample_count < 2:
        raise ValueError("need at least two samples for a train/test split")

    test_count = max(1, int(round(sample_count * test_size)))
    if test_count >= sample_count:
        test_count = sample_count - 1

    return sample_count - test_count
