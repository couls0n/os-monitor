#!/usr/bin/env python3
"""
collector.py

Normalize and merge raw agent JSONL files into either a canonical JSONL stream or
an SQLite database. This keeps source/time fields aligned for downstream stages.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from monitoring.constants import LOG_DIR, OUTPUT_DIR
from monitoring.event_schema import load_normalized_events


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=LOG_DIR)
    parser.add_argument("--out", choices=["sqlite", "file"], default="file")
    parser.add_argument("--db", default=os.path.join(OUTPUT_DIR, "events.db"))
    return parser.parse_args()


def dedupe_key(event: Dict[str, object]) -> Tuple[object, ...]:
    """Build a deduplication key for canonical events."""
    return (
        event.get("source"),
        event.get("pid"),
        event.get("ppid"),
        event.get("ts_ns"),
        event.get("timestamp"),
        event.get("event_key"),
        event.get("file_path"),
        event.get("file_new_path"),
        event.get("remote_ip"),
        event.get("remote_port"),
        event.get("dns_host"),
        event.get("syscall_name"),
        event.get("module_name"),
    )


def dedupe_events(events: Iterable[Dict[str, object]]) -> List[Dict[str, object]]:
    """Return canonical events without duplicates."""
    seen = set()
    result = []
    for event in events:
        key = dedupe_key(event)
        if key in seen:
            continue
        seen.add(key)
        result.append(event)
    return result


def write_sqlite(events: Iterable[Dict[str, object]], db_path: str) -> None:
    """Persist canonical events to SQLite."""
    db = Path(db_path)
    db.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(str(db)) as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                source TEXT,
                action TEXT,
                event_key TEXT,
                pid INTEGER,
                ppid INTEGER,
                comm TEXT,
                timestamp TEXT,
                ts_ns INTEGER,
                file_path TEXT,
                file_new_path TEXT,
                write_bytes INTEGER,
                remote_ip TEXT,
                remote_port INTEGER,
                dns_host TEXT,
                target_pid INTEGER,
                syscall_name TEXT,
                module_name TEXT,
                raw TEXT
            )
            """
        )
        for event in events:
            cursor.execute(
                """
                INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    event.get("source"),
                    event.get("action"),
                    event.get("event_key"),
                    event.get("pid"),
                    event.get("ppid"),
                    event.get("comm"),
                    event.get("timestamp"),
                    event.get("ts_ns"),
                    event.get("file_path"),
                    event.get("file_new_path"),
                    event.get("write_bytes"),
                    event.get("remote_ip"),
                    event.get("remote_port"),
                    event.get("dns_host"),
                    event.get("target_pid"),
                    event.get("syscall_name"),
                    event.get("module_name"),
                    json.dumps(event, ensure_ascii=False),
                ),
            )
        connection.commit()

    print("wrote to sqlite db:", str(db))


def write_jsonl(events: Iterable[Dict[str, object]]) -> None:
    """Persist canonical events to an aggregated JSONL file."""
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_file = Path(OUTPUT_DIR) / f"aggregated_{timestamp}.jsonl"
    with out_file.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    print("wrote", str(out_file))


def main() -> None:
    args = parse_args()
    events = load_normalized_events(args.input)
    events = dedupe_events(events)
    print(f"collected {len(events)} events from {args.input}")

    if args.out == "sqlite":
        write_sqlite(events, args.db)
    else:
        write_jsonl(events)


if __name__ == "__main__":
    main()
