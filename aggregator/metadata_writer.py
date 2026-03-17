#!/usr/bin/env python3
"""Write host/environment metadata alongside the collected raw logs."""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from monitoring.constants import LOG_DIR


OUT_DIR = Path(LOG_DIR)
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = OUT_DIR / "metadata.json"


def gather() -> dict[str, object]:
    """Collect reproducibility metadata for the current host."""
    meta = {"uname": platform.uname()._asdict()}

    try:
        dpkg = subprocess.check_output(["dpkg", "-l"], stderr=subprocess.DEVNULL)
        meta["packages_head"] = "\n".join(
            dpkg.decode("utf-8", errors="ignore").splitlines()[:50]
        )
    except Exception:
        meta["packages_head"] = ""

    try:
        with open("/proc/version", "r", encoding="utf-8") as handle:
            meta["proc_version"] = handle.read().strip()
    except Exception:
        meta["proc_version"] = ""

    return meta


def write() -> None:
    """Write metadata to disk."""
    with OUT_FILE.open("w", encoding="utf-8") as handle:
        json.dump(gather(), handle, indent=2, ensure_ascii=False)
    print("wrote metadata to", str(OUT_FILE))


if __name__ == "__main__":
    write()
