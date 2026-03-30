#!/usr/bin/env python3
"""Shared helpers for consistent wall-clock timestamps."""

from __future__ import annotations

import time
from datetime import datetime, timezone


_MONOTONIC_TO_EPOCH_OFFSET_NS = time.time_ns() - time.monotonic_ns()


def monotonic_ns_to_epoch_ns(monotonic_ns: int) -> int:
    """Convert a monotonic kernel timestamp into an epoch timestamp."""
    return _MONOTONIC_TO_EPOCH_OFFSET_NS + int(monotonic_ns)


def monotonic_ns_to_utc_iso(monotonic_ns: int) -> str:
    """Convert a monotonic kernel timestamp into an ISO-8601 UTC string."""
    epoch_ns = monotonic_ns_to_epoch_ns(monotonic_ns)
    return datetime.fromtimestamp(epoch_ns / 1e9, tz=timezone.utc).isoformat()


def utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()
