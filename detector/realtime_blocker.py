#!/usr/bin/env python3
"""Real-time sliding-window detector and optional process blocker."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from monitoring.constants import ALERTS_FILE, DEFAULT_WINDOW_MS, LOG_DIR, RAW_EVENT_FILES
from monitoring.event_schema import normalize_event
from monitoring.window_engine import ThresholdProfile, extract_window_metrics, score_pid_metrics


class JsonlFollower:
    """Tail-like JSONL follower that survives truncation and delayed file creation."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.offset = 0
        self.inode: Optional[int] = None

    def read_new_lines(self) -> List[str]:
        if not self.path.exists():
            return []

        stat = self.path.stat()
        inode = getattr(stat, "st_ino", None)
        if self.inode is None:
            self.inode = inode
            self.offset = stat.st_size
            return []
        if inode != self.inode or stat.st_size < self.offset:
            self.offset = 0
            self.inode = inode

        with self.path.open("r", encoding="utf-8") as handle:
            handle.seek(self.offset)
            lines = handle.readlines()
            self.offset = handle.tell()

        return lines


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log-dir", default=LOG_DIR)
    parser.add_argument("--window-ms", type=int, default=DEFAULT_WINDOW_MS)
    parser.add_argument("--poll-ms", type=int, default=100)
    parser.add_argument("--mode", choices=["detect", "block"], default="detect")
    parser.add_argument("--signal", default="SIGKILL")
    parser.add_argument("--alert-score", type=int, default=4)
    parser.add_argument("--block-score", type=int, default=ThresholdProfile().block_score)
    parser.add_argument("--cooldown-s", type=float, default=5.0)
    parser.add_argument(
        "--protect-comm",
        default="systemd,sshd,sudo",
        help="comma-separated process names that will never be blocked",
    )
    return parser.parse_args()


def resolve_signal(name: str) -> int:
    """Resolve a signal name like SIGKILL to its numeric value."""
    if not name.startswith("SIG"):
        name = "SIG" + name.upper()
    return int(getattr(signal, name))


def now_utc_iso() -> str:
    """Current UTC time as ISO string."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def is_safe_to_block(pid: int, comm: str, protected: set[str]) -> bool:
    """Prevent obviously dangerous self-inflicted kills."""
    if pid <= 1:
        return False
    if pid in {os.getpid(), os.getppid()}:
        return False
    if comm and comm in protected:
        return False
    return True


def main() -> None:
    args = parse_args()
    signal_value = resolve_signal(args.signal)
    protected_comms = {value.strip() for value in args.protect_comm.split(",") if value.strip()}

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    alerts_path = log_dir / ALERTS_FILE

    followers = {
        file_name: JsonlFollower(log_dir / file_name)
        for file_name in RAW_EVENT_FILES
    }
    state: Dict[int, Deque[Dict[str, Any]]] = {}
    last_alert_at: Dict[int, float] = {}
    thresholds = ThresholdProfile(block_score=args.block_score)

    print(
        f"[*] realtime_blocker starting | mode={args.mode} | window_ms={args.window_ms} "
        f"| block_score={args.block_score}"
    )

    while True:
        had_events = False
        for file_name, follower in followers.items():
            for line in follower.read_new_lines():
                had_events = True
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue

                event = normalize_event(raw, source_hint=file_name.replace(".jsonl", "").replace("fileio", "file"))
                pid = event.get("pid")
                if pid is None:
                    continue

                pid = int(pid)
                pid_events = state.setdefault(pid, deque())
                pid_events.append(event)

                current_ts = event.get("sort_ts")
                if current_ts is None:
                    current_ts = (event.get("ts_ns") or 0) / 1e9
                expire_before = current_ts - (args.window_ms / 1000.0)

                while pid_events:
                    head = pid_events[0]
                    head_ts = head.get("sort_ts")
                    if head_ts is None:
                        head_ts = (head.get("ts_ns") or 0) / 1e9
                    if head_ts >= expire_before:
                        break
                    pid_events.popleft()

                metrics = extract_window_metrics(list(pid_events))
                score, reasons = score_pid_metrics(metrics, thresholds)
                if score < args.alert_score:
                    continue

                current_time = time.time()
                if current_time - last_alert_at.get(pid, 0.0) < args.cooldown_s:
                    continue
                last_alert_at[pid] = current_time

                comm = metrics.get("dominant_comm") or event.get("comm") or ""
                action = "alert"
                block_error = ""

                if score >= args.block_score and args.mode == "block":
                    if is_safe_to_block(pid, comm, protected_comms):
                        try:
                            os.kill(pid, signal_value)
                            action = f"blocked:{args.signal}"
                        except ProcessLookupError:
                            action = "already-exited"
                        except PermissionError as exc:
                            action = "block-failed"
                            block_error = str(exc)
                    else:
                        action = "protected-process"

                alert = {
                    "timestamp": now_utc_iso(),
                    "pid": pid,
                    "comm": comm,
                    "score": score,
                    "mode": args.mode,
                    "action": action,
                    "reasons": reasons,
                    "metrics": metrics,
                    "signal": args.signal,
                    "error": block_error,
                }

                with alerts_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(alert, ensure_ascii=False) + "\n")

                print(
                    f"[ALERT] pid={pid} comm={comm or '-'} score={score} "
                    f"action={action} reasons={'; '.join(reasons)}"
                )

        if not had_events:
            time.sleep(max(args.poll_ms / 1000.0, 0.05))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] realtime_blocker stopped")
