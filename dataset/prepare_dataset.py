#!/usr/bin/env python3
"""
prepare_dataset.py

Builds fixed-size sliding windows from raw JSONL events. This keeps short-lived
behavior bursts intact, which is critical for ransomware and fileless detection.
"""

from __future__ import annotations

import argparse
import os
import pickle
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from monitoring.constants import DEFAULT_STRIDE_MS, DEFAULT_WINDOW_MS, LOG_DIR
from monitoring.event_schema import load_normalized_events, parse_timestamp
from monitoring.window_engine import event_time_seconds


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=LOG_DIR, help="directory or aggregated JSONL file")
    parser.add_argument("--out", default="dataset/raw_sessions.pkl")
    parser.add_argument(
        "--window-ms",
        type=int,
        default=DEFAULT_WINDOW_MS,
        help="window size in milliseconds",
    )
    parser.add_argument(
        "--stride-ms",
        type=int,
        default=DEFAULT_STRIDE_MS,
        help="window stride in milliseconds",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=None,
        help="deprecated seconds-based alias for --window-ms",
    )
    parser.add_argument(
        "--min-events",
        type=int,
        default=1,
        help="skip windows with fewer than this many events",
    )
    return parser.parse_args()


def iso_from_seconds(seconds_value: float) -> str:
    """Convert a Unix timestamp to UTC ISO format."""
    return datetime.fromtimestamp(seconds_value, tz=timezone.utc).isoformat()


def build_wall_time_converter(events: List[Dict[str, Any]], event_times: List[float]):
    """Map monotonic window offsets back to wall-clock timestamps."""
    if not events or not event_times:
        return None

    first_event_time = parse_timestamp(events[0].get("timestamp"))
    if first_event_time is None:
        return None

    base_wall = first_event_time.timestamp()
    base_timeline = event_times[0]

    def convert(timeline_seconds: float) -> tuple[str, float]:
        wall_seconds = base_wall + (timeline_seconds - base_timeline)
        return iso_from_seconds(wall_seconds), wall_seconds

    return convert


def fallback_window_bounds(window_events: List[Dict[str, Any]]) -> tuple[str | None, float | None, str | None, float | None]:
    """Fall back to event timestamps when a wall-clock converter is unavailable."""
    if not window_events:
        return None, None, None, None

    start_dt = parse_timestamp(window_events[0].get("timestamp"))
    end_dt = parse_timestamp(window_events[-1].get("timestamp"))
    start_iso = start_dt.isoformat() if start_dt else None
    end_iso = end_dt.isoformat() if end_dt else None
    start_ts = start_dt.timestamp() if start_dt else None
    end_ts = end_dt.timestamp() if end_dt else None
    return start_iso, start_ts, end_iso, end_ts


def build_windows(
    events: List[Dict[str, Any]],
    window_ms: int,
    stride_ms: int,
    min_events: int,
) -> List[Dict[str, Any]]:
    """Create sliding windows over normalized events."""
    if not events:
        return []

    events = list(events)
    event_times = [event_time_seconds(event) for event in events]
    window_s = window_ms / 1000.0
    stride_s = stride_ms / 1000.0

    left = 0
    right = 0
    cursor = event_times[0]
    end_time = event_times[-1]
    sessions: List[Dict[str, Any]] = []
    session_index = 0
    wall_time_converter = build_wall_time_converter(events, event_times)

    while cursor <= end_time:
        while left < len(events) and event_times[left] < cursor:
            left += 1
        while right < len(events) and event_times[right] < cursor + window_s:
            right += 1

        window_events = events[left:right]
        if len(window_events) >= min_events:
            dominant_pid = None
            pid_counter = {}
            for event in window_events:
                pid = event.get("pid")
                if pid is None:
                    continue
                pid_counter[pid] = pid_counter.get(pid, 0) + 1
            if pid_counter:
                dominant_pid = max(pid_counter.items(), key=lambda item: item[1])[0]

            if wall_time_converter is not None:
                start_iso, start_ts = wall_time_converter(cursor)
                end_iso, end_ts = wall_time_converter(cursor + window_s)
            else:
                start_iso, start_ts, end_iso, end_ts = fallback_window_bounds(window_events)

            sessions.append(
                {
                    "session_index": session_index,
                    "timeline_index": session_index,
                    "start": start_iso,
                    "end": end_iso,
                    "start_ts": start_ts,
                    "end_ts": end_ts,
                    "window_ms": window_ms,
                    "stride_ms": stride_ms,
                    "event_count": len(window_events),
                    "primary_pid": dominant_pid,
                    "events": window_events,
                }
            )
            session_index += 1

        cursor += stride_s

    return sessions


def main() -> None:
    args = parse_args()

    if args.window is not None:
        args.window_ms = int(args.window * 1000)
        if args.stride_ms == DEFAULT_STRIDE_MS:
            args.stride_ms = max(1, args.window_ms // 2)

    if args.window_ms <= 0 or args.stride_ms <= 0:
        raise SystemExit("window-ms and stride-ms must be positive integers")

    events = load_normalized_events(args.input)
    if not events:
        raise SystemExit(f"no events found in {args.input}")

    sessions = build_windows(
        events=events,
        window_ms=args.window_ms,
        stride_ms=args.stride_ms,
        min_events=args.min_events,
    )
    if not sessions:
        raise SystemExit("no sessions produced; try lowering --min-events or increasing window size")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("wb") as handle:
        pickle.dump(sessions, handle)

    print(
        "wrote",
        str(out_path),
        "sessions:",
        len(sessions),
        "window_ms:",
        args.window_ms,
        "stride_ms:",
        args.stride_ms,
    )


if __name__ == "__main__":
    main()
