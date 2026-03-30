#!/usr/bin/env python3
"""Normalize heterogeneous agent JSONL events into a canonical schema."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from monitoring.constants import ALERTS_FILE


FILE_TO_SOURCE = {
    "process.jsonl": "process",
    "fileio.jsonl": "file",
    "net.jsonl": "net",
    "dns.jsonl": "dns",
    "kmod.jsonl": "kmod",
    "memory.jsonl": "memory",
    "syscall.jsonl": "syscall",
}


def safe_int(value: Any) -> Optional[int]:
    """Best-effort integer parsing."""
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def safe_float(value: Any) -> Optional[float]:
    """Best-effort float parsing."""
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse an ISO timestamp and normalize to UTC."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def infer_source_from_filename(path: str) -> Optional[str]:
    """Infer the source agent from the JSONL filename."""
    return FILE_TO_SOURCE.get(Path(path).name)


def infer_source(record: Dict[str, Any], source_hint: Optional[str] = None) -> str:
    """Infer source from the record if the file hint is unavailable."""
    if record.get("source"):
        return str(record["source"])
    if source_hint:
        return source_hint

    event = str(record.get("event") or "")
    if event in {"exec", "fork", "exit"}:
        return "process"
    if event in {"open", "write", "delete", "rename"}:
        return "file"
    if event == "dns_query" or record.get("host"):
        return "dns"
    if event == "kmod_load" or record.get("module_name"):
        return "kmod"
    if event in {"mprotect", "vm_writev", "mmap", "brk"}:
        return "memory"
    if event == "suspicious_syscall" or record.get("syscall_name"):
        return "syscall"
    if record.get("dport") is not None or record.get("daddr_str"):
        return "net"
    return "unknown"


def normalize_action(source: str, record: Dict[str, Any]) -> str:
    """Map raw event names into canonical actions."""
    event = str(record.get("event") or "")

    if source == "process":
        return event or "unknown"
    if source == "file":
        return event or "unknown"
    if source == "net":
        return event or "connect"
    if source == "dns":
        return "query" if event == "dns_query" else (event or "query")
    if source == "kmod":
        return "load" if event == "kmod_load" else (event or "load")
    if source == "memory":
        return event or "unknown"
    if source == "syscall":
        if event == "suspicious_syscall" and record.get("syscall_name"):
            return str(record["syscall_name"])
        return event or str(record.get("syscall_name") or "unknown")
    return event or "unknown"


def normalize_event(record: Dict[str, Any], source_hint: Optional[str] = None) -> Dict[str, Any]:
    """Normalize a raw agent record into a canonical event."""
    source = infer_source(record, source_hint)
    action = normalize_action(source, record)
    wall_time = parse_timestamp(
        record.get("timestamp")
        or record.get("ts")
        or record.get("_ts")
        or record.get("start")
    )
    ts_ns = safe_int(record.get("ts_ns"))
    timeline_ts = (
        (ts_ns / 1e9)
        if ts_ns is not None
        else safe_float(record.get("timeline_ts"))
    )
    if timeline_ts is None and wall_time is not None:
        timeline_ts = wall_time.timestamp()

    canonical = {
        "source": source,
        "action": action,
        "event": str(record.get("event") or action),
        "event_key": f"{source}.{action}",
        "pid": safe_int(record.get("pid")),
        "ppid": safe_int(record.get("ppid")),
        "comm": str(record.get("comm") or ""),
        "timestamp": wall_time.isoformat() if wall_time else None,
        "sort_ts": wall_time.timestamp() if wall_time else None,
        "timeline_ts": timeline_ts,
        "ts_ns": ts_ns,
        "raw": record,
    }

    file_path = (
        record.get("file_path")
        or record.get("fname")
        or record.get("path")
        or ""
    )
    file_new_path = record.get("new_fname") or record.get("file_new_path") or ""

    canonical.update(
        {
            "file_path": str(file_path),
            "file_new_path": str(file_new_path),
            "fd": safe_int(record.get("fd")),
            "write_bytes": safe_int(record.get("count") or record.get("write_bytes")) or 0,
            "family": safe_int(record.get("family")),
            "remote_ip": str(record.get("daddr_str") or ""),
            "remote_port": safe_int(record.get("dport")),
            "dns_host": str(record.get("host") or ""),
            "module_name": str(record.get("module_name") or ""),
            "syscall_name": str(record.get("syscall_name") or ""),
            "target_pid": safe_int(record.get("target_pid")),
            "memory_protection": str(record.get("protection") or ""),
            "memory_length": safe_int(record.get("length")) or 0,
            "memory_flags": safe_int(record.get("flags")) or 0,
            "memory_address": safe_int(record.get("address")),
        }
    )

    if canonical["source"] == "net" and canonical["event"] == "unknown":
        canonical["event"] = "connect"
        canonical["action"] = "connect"
        canonical["event_key"] = "net.connect"

    if canonical["source"] == "dns" and not canonical["dns_host"]:
        canonical["dns_host"] = str(record.get("query") or "")

    return canonical


def event_order_key(event: Dict[str, Any]) -> Tuple[int, float, int, str]:
    """Sort by monotonic event time first, then by wall-clock time."""
    timeline_missing = 1 if event.get("timeline_ts") is None else 0
    timeline_ts = float(event.get("timeline_ts") or 0.0)
    wall_missing = 1 if event.get("sort_ts") is None else 0
    wall_ts = float(event.get("sort_ts") or 0.0)
    mono_ns = int(event.get("ts_ns") or 0)
    return timeline_missing, timeline_ts, wall_missing, wall_ts, mono_ns, event.get("event_key", "")


def sort_events(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return events sorted by their canonical order."""
    return sorted(events, key=event_order_key)


def iter_event_files(input_path: str) -> Iterator[Path]:
    """Yield all event JSONL files from a directory or a single file."""
    path = Path(input_path)
    if path.is_file():
        if path.suffix == ".jsonl" and path.name != ALERTS_FILE:
            yield path
        return

    if not path.exists():
        return

    for item in sorted(path.glob("*.jsonl")):
        if item.name == ALERTS_FILE:
            continue
        yield item


def load_normalized_events(input_path: str) -> List[Dict[str, Any]]:
    """Load and normalize every JSONL event under input_path."""
    events: List[Dict[str, Any]] = []

    for path in iter_event_files(input_path):
        source_hint = infer_source_from_filename(str(path))
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                events.append(normalize_event(raw, source_hint=source_hint))

    return sort_events(events)
