#!/usr/bin/env python3
"""Sequence helpers used by offline feature extraction and online detection."""

from __future__ import annotations

from collections import Counter
from typing import Dict, Iterable, List, Sequence, Tuple


def ngrams(items: Sequence[str], size: int) -> List[Tuple[str, ...]]:
    """Return all contiguous n-grams of the requested size."""
    if size <= 0 or len(items) < size:
        return []
    return [tuple(items[index : index + size]) for index in range(len(items) - size + 1)]


def count_patterns(
    items: Sequence[str],
    patterns: Dict[str, Tuple[str, ...]],
) -> Dict[str, int]:
    """Count how many times each named pattern appears contiguously."""
    counts: Dict[str, int] = {}
    cache: Dict[int, Counter[Tuple[str, ...]]] = {}

    for name, pattern in patterns.items():
        size = len(pattern)
        if size not in cache:
            cache[size] = Counter(ngrams(items, size))
        counts[name] = cache[size][pattern]

    return counts
