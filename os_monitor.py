#!/usr/bin/env python3
"""Unified CLI for simple OS-Monitor workflows on Ubuntu/Linux."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


ROOT_DIR = Path(__file__).resolve().parent
LOG_DIR = Path("/var/log/os_monitor_log")
RUNS_DIR = ROOT_DIR / "runs"


def now_tag() -> str:
    """Return a filesystem-safe UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def require_root() -> None:
    """Abort if the current command requires root privileges."""
    if os.geteuid() != 0:
        raise SystemExit("请使用 sudo 运行此命令。")


def run_command(
    command: List[str],
    *,
    env: Optional[dict[str, str]] = None,
    cwd: Optional[Path] = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Run a child command and stream stdout/stderr directly."""
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(command, cwd=str(cwd or ROOT_DIR), env=merged_env, check=check)


def popen_command(
    command: List[str],
    *,
    env: Optional[dict[str, str]] = None,
    cwd: Optional[Path] = None,
) -> subprocess.Popen:
    """Spawn a background process."""
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.Popen(command, cwd=str(cwd or ROOT_DIR), env=merged_env)


def start_stack(args: argparse.Namespace) -> None:
    """Start agents and the optional detector."""
    require_root()
    env = {
        "ENABLE_DETECTOR": "0" if args.no_detector else "1",
        "DETECTOR_MODE": args.mode,
        "DETECTOR_WINDOW_MS": str(args.window_ms),
        "DETECTOR_BLOCK_SCORE": str(args.block_score),
    }
    run_command(["bash", str(ROOT_DIR / "start_monitoring.sh")], env=env)


def stop_stack(_: argparse.Namespace) -> None:
    """Stop agents, detector and dashboard."""
    require_root()
    run_command(["bash", str(ROOT_DIR / "stop_monitoring.sh")])


def show_status(_: argparse.Namespace) -> None:
    """Print current agent/detector status."""
    run_command(["bash", str(ROOT_DIR / "check_status.sh")], check=False)


def watch_dashboard(args: argparse.Namespace) -> None:
    """Start the stack and open the multitail dashboard in one command."""
    require_root()
    env = {
        "ENABLE_DETECTOR": "0" if args.no_detector else "1",
        "DETECTOR_MODE": args.mode,
        "DETECTOR_WINDOW_MS": str(args.window_ms),
        "DETECTOR_BLOCK_SCORE": str(args.block_score),
    }
    run_command(["bash", str(ROOT_DIR / "run_dashboard.sh")], env=env)


def archive_runtime_logs(label: str) -> Optional[Path]:
    """Move old runtime logs into an archive folder so each quick run starts clean."""
    archive_candidates = list(LOG_DIR.glob("*.jsonl")) + list(LOG_DIR.glob("*.log"))
    metadata_file = LOG_DIR / "metadata.json"
    if metadata_file.exists():
        archive_candidates.append(metadata_file)

    archive_candidates = [path for path in archive_candidates if path.exists()]
    if not archive_candidates:
        return None

    archive_dir = LOG_DIR / "archive" / f"{label}_{now_tag()}"
    archive_dir.mkdir(parents=True, exist_ok=True)
    for path in archive_candidates:
        shutil.move(str(path), str(archive_dir / path.name))
    return archive_dir


def build_workload_command(args: argparse.Namespace) -> Optional[List[str]]:
    """Map a quick-run scenario to a concrete command."""
    python = sys.executable or "python3"

    if args.command:
        return ["bash", "-lc", args.command]
    if args.scenario == "none":
        return None
    if args.scenario == "advanced":
        return [python, str(ROOT_DIR / "dataset" / "advanced_attack_simulator.py")]
    if args.scenario == "benign":
        return [python, str(ROOT_DIR / "dataset" / "simulate_benign_activity.py")]
    if args.scenario == "attack":
        if not args.attack:
            raise SystemExit("--scenario attack 时必须提供 --attack")
        return [python, str(ROOT_DIR / "dataset" / "simulate_attacks.py"), "--attack", args.attack]
    if args.scenario == "loader":
        command = [
            python,
            str(ROOT_DIR / "dataset" / "loader.py"),
            "--malware-dir",
            args.malware_dir,
            "--target-dir",
            args.target_dir,
            "--timeout",
            str(args.sample_timeout),
        ]
        if args.sample:
            command += ["--sample", args.sample]
        return command

    raise SystemExit(f"未知场景: {args.scenario}")


def terminate_process(process: subprocess.Popen) -> None:
    """Terminate a workload process gracefully, then force-kill if needed."""
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run_workload(args: argparse.Namespace) -> Optional[int]:
    """Run the chosen workload, optionally for a fixed duration."""
    command = build_workload_command(args)
    effective_duration = args.duration
    if effective_duration <= 0 and args.scenario == "benign":
        effective_duration = 60.0
        print("[*] benign 场景默认运行 60s；如需修改可传 --duration")

    if command is None:
        if effective_duration > 0:
            print(f"[*] 未指定工作负载，保持监控栈运行 {effective_duration}s ...")
            time.sleep(effective_duration)
        return None

    print("[*] 运行场景命令:", " ".join(command))
    process = popen_command(command)

    if effective_duration > 0:
        try:
            process.wait(timeout=effective_duration)
        except subprocess.TimeoutExpired:
            print(f"[*] 已达到 {effective_duration}s，正在结束场景进程 ...")
            terminate_process(process)
    else:
        process.wait()

    return process.returncode


def build_outputs(args: argparse.Namespace, run_id: str, input_dir: Path) -> Path:
    """Build canonical events, sessions and features into one run directory."""
    python = sys.executable or "python3"
    out_dir = Path(args.out_dir) if args.out_dir else RUNS_DIR / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    run_command(
        [
            python,
            str(ROOT_DIR / "aggregator" / "collector.py"),
            "--input",
            str(input_dir),
            "--out",
            "sqlite",
            "--db",
            str(out_dir / "events.db"),
        ]
    )
    run_command(
        [
            python,
            str(ROOT_DIR / "dataset" / "prepare_dataset.py"),
            "--input",
            str(input_dir),
            "--out",
            str(out_dir / "raw_sessions.pkl"),
            "--window-ms",
            str(args.window_ms),
            "--stride-ms",
            str(args.stride_ms),
        ]
    )
    run_command(
        [
            python,
            str(ROOT_DIR / "features" / "feature_builder.py"),
            "--infile",
            str(out_dir / "raw_sessions.pkl"),
            "--outfile",
            str(out_dir / "features.parquet"),
            "--graphs-out",
            str(out_dir / "graphs.pkl"),
        ]
    )

    manifest = {
        "run_id": run_id,
        "log_dir": str(input_dir),
        "window_ms": args.window_ms,
        "stride_ms": args.stride_ms,
        "mode": getattr(args, "mode", None),
        "scenario": getattr(args, "scenario", None),
        "attack": getattr(args, "attack", None),
        "built_at": now_tag(),
    }
    with (out_dir / "manifest.json").open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=False)

    return out_dir


def runtime_event_count(input_dir: Path) -> int:
    """Count collected raw events, excluding alert files."""
    total = 0
    for path in input_dir.glob("*.jsonl"):
        if path.name == "alerts.jsonl":
            continue
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        total += 1
        except OSError:
            continue
    return total


def build_only(args: argparse.Namespace) -> None:
    """Offline build command for a log directory."""
    out_dir = build_outputs(args, run_id=args.run_id or now_tag(), input_dir=Path(args.input))
    print(f"[+] 构建完成: {out_dir}")


def quick_run(args: argparse.Namespace) -> None:
    """One-command scenario workflow: start -> run -> stop -> optional build."""
    require_root()
    run_id = args.run_id or now_tag()
    archived = None

    if args.archive_logs:
        archived = archive_runtime_logs(run_id)
        if archived:
            print(f"[*] 旧日志已归档到: {archived}")

    start_args = argparse.Namespace(
        no_detector=args.no_detector,
        mode=args.mode,
        window_ms=args.window_ms,
        block_score=args.block_score,
    )

    start_stack(start_args)
    workload_rc = None
    try:
        workload_rc = run_workload(args)
        if args.post_wait > 0:
            print(f"[*] 等待 {args.post_wait}s 让尾部事件落盘 ...")
            time.sleep(args.post_wait)
    finally:
        if not args.keep_running:
            stop_stack(args)

    if args.build:
        event_count = runtime_event_count(LOG_DIR)
        if event_count > 0:
            out_dir = build_outputs(args, run_id=run_id, input_dir=LOG_DIR)
            print(f"[+] 本次运行产物已输出到: {out_dir}")
        else:
            print("[!] 未检测到任何原始事件，已跳过 build。")
            print("[!] 请优先检查样本路径、执行命令、Agent 挂载和运行权限。")

    if workload_rc not in (None, 0):
        raise SystemExit(workload_rc)


def add_shared_stack_args(parser: argparse.ArgumentParser) -> None:
    """Add detector-related CLI flags."""
    parser.add_argument("--mode", choices=["detect", "block"], default="detect")
    parser.add_argument("--window-ms", type=int, default=500)
    parser.add_argument("--block-score", type=int, default=7)
    parser.add_argument("--no-detector", action="store_true")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="OS-Monitor unified workflow CLI",
        epilog=(
            "示例:\n"
            "  sudo python3 os_monitor.py up --mode detect\n"
            "  sudo python3 os_monitor.py watch --mode block\n"
            "  sudo python3 os_monitor.py quick --scenario advanced --mode block --build\n"
            "  sudo python3 os_monitor.py quick --scenario attack --attack ransom --build\n"
            "  python3 os_monitor.py build --input /var/log/os_monitor_log --out-dir runs/manual"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    up_parser = subparsers.add_parser("up", help="start agents and detector")
    add_shared_stack_args(up_parser)
    up_parser.set_defaults(func=start_stack)

    down_parser = subparsers.add_parser("down", help="stop agents and detector")
    down_parser.set_defaults(func=stop_stack)

    status_parser = subparsers.add_parser("status", help="show current status")
    status_parser.set_defaults(func=show_status)

    watch_parser = subparsers.add_parser("watch", help="start stack and open dashboard")
    add_shared_stack_args(watch_parser)
    watch_parser.set_defaults(func=watch_dashboard)

    build_parser = subparsers.add_parser("build", help="build sessions/features from an existing log directory")
    build_parser.add_argument("--input", default=str(LOG_DIR))
    build_parser.add_argument("--out-dir", default=None)
    build_parser.add_argument("--run-id", default=None)
    build_parser.add_argument("--window-ms", type=int, default=500)
    build_parser.add_argument("--stride-ms", type=int, default=250)
    build_parser.set_defaults(func=build_only)

    quick_parser = subparsers.add_parser("quick", help="one-command scenario workflow")
    add_shared_stack_args(quick_parser)
    quick_parser.add_argument(
        "--scenario",
        choices=["advanced", "attack", "benign", "loader", "none"],
        default="advanced",
    )
    quick_parser.add_argument("--attack", choices=["forkbomb", "ransom", "slow-breach", "scan"], default=None)
    quick_parser.add_argument("--sample", default=None, help="sample filename for --scenario loader")
    quick_parser.add_argument("--malware-dir", default="dataset/malware_samples")
    quick_parser.add_argument("--target-dir", default="/tmp/documents_to_encrypt")
    quick_parser.add_argument("--sample-timeout", type=int, default=60)
    quick_parser.add_argument("--command", default=None, help="custom shell command to run instead of a built-in scenario")
    quick_parser.add_argument("--duration", type=float, default=0.0, help="force-stop the workload after N seconds")
    quick_parser.add_argument("--post-wait", type=float, default=2.0)
    quick_parser.add_argument("--keep-running", action="store_true")
    quick_parser.add_argument("--build", action="store_true", help="auto-build events/sessions/features after the run")
    quick_parser.add_argument("--out-dir", default=None)
    quick_parser.add_argument("--run-id", default=None)
    quick_parser.add_argument("--stride-ms", type=int, default=250)
    quick_parser.add_argument("--archive-logs", action="store_true", default=True)
    quick_parser.add_argument("--no-archive-logs", action="store_false", dest="archive_logs")
    quick_parser.set_defaults(func=quick_run)

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
