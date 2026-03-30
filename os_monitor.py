#!/usr/bin/env python3
"""Unified CLI for OS-Monitor workflows and stack orchestration."""

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
from typing import Any, Optional

from monitoring.constants import ALERTS_FILE, DEFAULT_STRIDE_MS, DEFAULT_WINDOW_MS, RAW_EVENT_FILES


ROOT_DIR = Path(__file__).resolve().parent
LOG_DIR = Path("/var/log/os_monitor_log")
RUNS_DIR = ROOT_DIR / "runs"
RUNTIME_STATE_FILE = LOG_DIR / "runtime_state.json"
PYTHON = sys.executable or "python3"

AGENT_SPECS = (
    {"name": "process", "label": "进程采集器", "script": "agent/process_agent.py", "log": "process_agent.log"},
    {"name": "file", "label": "文件采集器", "script": "agent/file_agent.py", "log": "file_agent.log"},
    {"name": "net", "label": "网络采集器", "script": "agent/net_agent.py", "log": "net_agent.log"},
    {"name": "dns", "label": "DNS 采集器", "script": "agent/dns_agent.py", "log": "dns_agent.log"},
    {"name": "kmod", "label": "内核模块采集器", "script": "agent/kmod_agent.py", "log": "kmod_agent.log"},
    {"name": "memory", "label": "内存采集器", "script": "agent/memory_agent.py", "log": "memory_agent.log"},
    {"name": "syscall", "label": "可疑系统调用采集器", "script": "agent/syscall_agent.py", "log": "syscall_agent.log"},
)

DETECTOR_SPEC = {
    "name": "detector",
    "label": "实时检测器",
    "script": "detector/realtime_blocker.py",
    "log": "realtime_blocker.log",
}

LEGACY_PROCESS_PATTERNS = {
    "process": "agent/process_agent.py",
    "file": "agent/file_agent.py",
    "net": "agent/net_agent.py",
    "dns": "agent/dns_agent.py",
    "kmod": "agent/kmod_agent.py",
    "memory": "agent/memory_agent.py",
    "syscall": "agent/syscall_agent.py",
    "detector": "detector/realtime_blocker.py",
    "dashboard": "multitail.*os_monitor_log",
}


def now_tag() -> str:
    """Return a filesystem-safe UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def require_root() -> None:
    """Abort if the current command requires root privileges."""
    if os.geteuid() != 0:
        raise SystemExit("请使用 sudo 运行此命令。")


def build_pythonpath() -> str:
    """Compose a PYTHONPATH that always includes the repository root."""
    existing = os.environ.get("PYTHONPATH", "")
    return f"{ROOT_DIR}:{existing}" if existing else str(ROOT_DIR)


def base_env() -> dict[str, str]:
    """Environment shared by spawned child processes."""
    env = os.environ.copy()
    env["PYTHONPATH"] = build_pythonpath()
    return env


def run_command(
    command: list[str],
    *,
    env: Optional[dict[str, str]] = None,
    cwd: Optional[Path] = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Run a child command and stream stdout/stderr directly."""
    merged_env = base_env()
    if env:
        merged_env.update(env)
    return subprocess.run(command, cwd=str(cwd or ROOT_DIR), env=merged_env, check=check)


def popen_command(
    command: list[str],
    *,
    env: Optional[dict[str, str]] = None,
    cwd: Optional[Path] = None,
    stdout: Any = None,
    stderr: Any = None,
    start_new_session: bool = False,
) -> subprocess.Popen:
    """Spawn a background process."""
    merged_env = base_env()
    if env:
        merged_env.update(env)
    return subprocess.Popen(
        command,
        cwd=str(cwd or ROOT_DIR),
        env=merged_env,
        stdout=stdout,
        stderr=stderr,
        start_new_session=start_new_session,
    )


def ensure_log_layout() -> None:
    """Create the runtime log directory and known JSONL files."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    for file_name in (*RAW_EVENT_FILES, ALERTS_FILE):
        (LOG_DIR / file_name).touch(exist_ok=True)


def load_runtime_state() -> Optional[dict[str, Any]]:
    """Load the persisted runtime manifest if present."""
    if not RUNTIME_STATE_FILE.exists():
        return None
    try:
        with RUNTIME_STATE_FILE.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (json.JSONDecodeError, OSError):
        return None


def write_runtime_state(state: dict[str, Any]) -> None:
    """Persist the runtime manifest for stop/status commands."""
    ensure_log_layout()
    with RUNTIME_STATE_FILE.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, ensure_ascii=False)
    try:
        os.chmod(RUNTIME_STATE_FILE, 0o644)
    except OSError:
        pass


def remove_runtime_state() -> None:
    """Delete the runtime manifest if it exists."""
    try:
        RUNTIME_STATE_FILE.unlink()
    except FileNotFoundError:
        pass


def process_alive(pid: int) -> bool:
    """Check whether a PID still exists."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return Path(f"/proc/{pid}").exists()


def tail_recent_log(log_path: Path, line_count: int = 20) -> str:
    """Return the last few lines of a log file for debugging."""
    try:
        with log_path.open("r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()
    except OSError:
        return ""
    return "".join(lines[-line_count:])


def start_component(
    *,
    label: str,
    command: list[str],
    log_name: str,
) -> dict[str, Any]:
    """Spawn one long-running component and verify it started cleanly."""
    ensure_log_layout()
    log_path = LOG_DIR / log_name
    handle = log_path.open("ab")
    try:
        process = popen_command(
            command,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finally:
        handle.close()

    deadline = time.time() + 3.0
    while time.time() < deadline:
        if process.poll() is not None:
            print(f"❌ {label} 启动失败，最近日志如下：")
            recent = tail_recent_log(log_path)
            if recent:
                print(recent.rstrip())
            raise SystemExit(process.returncode or 1)
        time.sleep(0.2)

    print(f"✅ {label} 已启动 (PID {process.pid})")
    return {
        "pid": process.pid,
        "log_file": str(log_path),
        "command": command,
    }


def write_host_metadata() -> None:
    """Capture host metadata without going through an extra shell launcher."""
    ensure_log_layout()
    log_path = LOG_DIR / "metadata_writer.log"
    with log_path.open("ab") as handle:
        popen_env = base_env()
        subprocess.run(
            [PYTHON, str(ROOT_DIR / "aggregator" / "metadata_writer.py")],
            cwd=str(ROOT_DIR),
            env=popen_env,
            stdout=handle,
            stderr=subprocess.STDOUT,
            check=False,
        )


def detector_command(args: argparse.Namespace) -> list[str]:
    """Build the realtime detector command from CLI flags."""
    return [
        PYTHON,
        str(ROOT_DIR / DETECTOR_SPEC["script"]),
        "--mode",
        args.mode,
        "--window-ms",
        str(args.window_ms),
        "--block-score",
        str(args.block_score),
    ]


def runtime_component_rows(state: dict[str, Any]) -> list[dict[str, Any]]:
    """Return runtime rows with current liveness for display and cleanup."""
    rows = []
    for name, component in state.get("components", {}).items():
        pid = int(component.get("pid") or 0)
        rows.append(
            {
                "name": name,
                "label": component.get("label", name),
                "pid": pid,
                "alive": process_alive(pid),
                "log_file": component.get("log_file", ""),
                "role": component.get("role", "agent"),
            }
        )
    return rows


def runtime_health(state: Optional[dict[str, Any]]) -> str:
    """Classify the current runtime manifest."""
    if not state or not state.get("components"):
        return "stopped"
    rows = runtime_component_rows(state)
    alive_count = sum(1 for row in rows if row["alive"])
    if alive_count == 0:
        return "stopped"
    if alive_count == len(rows):
        return "running"
    return "partial"


def print_runtime_status(state: dict[str, Any]) -> None:
    """Render the tracked runtime state."""
    print("=== OS-Monitor 运行状态 ===")
    print(f"启动时间: {state.get('created_at', '-')}")
    print(f"模式: {state.get('mode', '-')}")
    print(f"检测器: {'关闭' if state.get('detector_disabled') else '开启'}")
    print(f"窗口: {state.get('window_ms', '-') } ms")
    print(f"阻断分数: {state.get('block_score', '-')}")
    for row in runtime_component_rows(state):
        mark = "✅" if row["alive"] else "❌"
        print(f"{mark} {row['label']:<14} PID={row['pid']:<8} log={row['log_file']}")


def pgrep_pattern(pattern: str) -> list[int]:
    """Return all PIDs matched by a pgrep pattern."""
    result = subprocess.run(
        ["pgrep", "-f", pattern],
        capture_output=True,
        text=True,
        check=False,
    )
    pids = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            pids.append(int(line))
        except ValueError:
            continue
    return sorted(set(pids))


def collect_legacy_processes(*, include_dashboard: bool = True) -> dict[str, list[int]]:
    """Find processes started by the old shell-script flow."""
    result: dict[str, list[int]] = {}
    for name, pattern in LEGACY_PROCESS_PATTERNS.items():
        if not include_dashboard and name == "dashboard":
            continue
        pids = pgrep_pattern(pattern)
        if pids:
            result[name] = pids
    return result


def describe_pid_map(pid_map: dict[str, list[int]]) -> None:
    """Print the PIDs about to be terminated."""
    all_pids = sorted({pid for pids in pid_map.values() for pid in pids})
    if not all_pids:
        return
    print("🛑 正在停止以下进程：")
    subprocess.run(["ps", "-fp", *[str(pid) for pid in all_pids]], check=False)


def terminate_pid_map(pid_map: dict[str, list[int]]) -> bool:
    """Gracefully stop a PID map, escalating to SIGKILL if required."""
    all_pids = sorted({pid for pids in pid_map.values() for pid in pids if pid > 0})
    if not all_pids:
        return False

    describe_pid_map(pid_map)

    for pid in all_pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
        except PermissionError:
            continue

    deadline = time.time() + 5.0
    while time.time() < deadline:
        remaining = [pid for pid in all_pids if process_alive(pid)]
        if not remaining:
            return True
        time.sleep(0.2)

    remaining = [pid for pid in all_pids if process_alive(pid)]
    if remaining:
        print(f"⚠️ 以下进程未响应 SIGTERM，升级为 SIGKILL： {' '.join(str(pid) for pid in remaining)}")
    for pid in remaining:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            continue
        except PermissionError:
            continue
    return True


def stop_tracked_runtime(state: dict[str, Any]) -> bool:
    """Stop processes recorded in the runtime manifest."""
    pid_map = {
        row["name"]: [row["pid"]]
        for row in runtime_component_rows(state)
        if row["alive"]
    }
    return terminate_pid_map(pid_map)


def start_stack(args: argparse.Namespace) -> dict[str, Any]:
    """Start agents and the optional detector using the unified CLI only."""
    require_root()
    ensure_log_layout()

    state = load_runtime_state()
    health = runtime_health(state)
    if health == "running" and not getattr(args, "restart", False):
        print("[*] 监控栈已在运行，直接复用现有实例。")
        if state:
            print_runtime_status(state)
            return state
    if health in {"running", "partial"} and state:
        print("[*] 检测到现有监控栈，先停止再重新拉起 ...")
        stop_tracked_runtime(state)
        remove_runtime_state()

    legacy = collect_legacy_processes(include_dashboard=False)
    if legacy:
        print("[*] 检测到旧版启动方式遗留进程，先清理后再启动 ...")
        terminate_pid_map(legacy)

    print("[*] 记录主机元数据 ...")
    write_host_metadata()

    components: dict[str, Any] = {}
    if not args.no_detector:
        components["detector"] = {
            "label": DETECTOR_SPEC["label"],
            "role": "detector",
            **start_component(
                label=DETECTOR_SPEC["label"],
                command=detector_command(args),
                log_name=DETECTOR_SPEC["log"],
            ),
        }
    else:
        print("ℹ️ 已跳过实时检测器")

    for spec in AGENT_SPECS:
        components[spec["name"]] = {
            "label": spec["label"],
            "role": "agent",
            **start_component(
                label=spec["label"],
                command=[PYTHON, str(ROOT_DIR / spec["script"])],
                log_name=spec["log"],
            ),
        }

    state = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "mode": args.mode,
        "window_ms": args.window_ms,
        "block_score": args.block_score,
        "detector_disabled": bool(args.no_detector),
        "components": components,
    }
    write_runtime_state(state)
    print("--------------------------------------")
    print(f"📡 采集目录：{LOG_DIR}")
    print("🔑 统一入口：sudo python3 os_monitor.py start | stop | status | watch")
    print("--------------------------------------")
    return state


def stop_stack(_: argparse.Namespace) -> None:
    """Stop agents, detector and any legacy dashboard process."""
    require_root()
    state = load_runtime_state()
    stopped_any = False

    if state:
        stopped_any = stop_tracked_runtime(state) or stopped_any
        remove_runtime_state()

    legacy = collect_legacy_processes(include_dashboard=True)
    if legacy:
        stopped_any = terminate_pid_map(legacy) or stopped_any

    if not stopped_any:
        print("⚠️ 未发现正在运行的采集器、检测器或仪表盘。")
        return

    print("✅ 已停止所有相关进程。")


def show_status(_: argparse.Namespace) -> None:
    """Print current stack status from the runtime manifest or legacy fallback."""
    state = load_runtime_state()
    if state and runtime_health(state) != "stopped":
        print_runtime_status(state)
        return

    legacy = collect_legacy_processes(include_dashboard=False)
    if legacy:
        print("=== OS-Monitor 运行状态（检测到旧版启动方式）===")
        for name, pids in legacy.items():
            print(f"✅ {name:<14} PID={','.join(str(pid) for pid in pids)}")
        return

    print("=== OS-Monitor 运行状态 ===")
    print("❌ 当前没有运行中的监控栈。")


def dashboard_command() -> list[str]:
    """Return the best available dashboard command."""
    files = [str(LOG_DIR / file_name) for file_name in (*RAW_EVENT_FILES, ALERTS_FILE)]
    if shutil.which("multitail"):
        return ["multitail", "-s", "4", *files]
    return ["tail", "-F", *files]


def watch_dashboard(args: argparse.Namespace) -> None:
    """Open the dashboard, auto-starting the stack when needed."""
    state = load_runtime_state()
    health = runtime_health(state)
    if getattr(args, "restart", False) or health != "running":
        state = start_stack(args)
    elif state:
        print("[*] 复用当前运行中的监控栈并打开仪表盘 ...")

    ensure_log_layout()
    command = dashboard_command()
    if command[0] == "multitail":
        print("[*] 启动实时仪表盘 (multitail)，按 q 退出。")
    else:
        print("[*] 未找到 multitail，改用 tail -F 打开实时日志。按 Ctrl+C 退出。")
    run_command(command, check=False)


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


def build_workload_command(args: argparse.Namespace) -> Optional[list[str]]:
    """Map a quick-run scenario to a concrete command."""
    if args.command:
        return ["bash", "-lc", args.command]
    if args.scenario == "none":
        return None
    if args.scenario == "advanced":
        return [PYTHON, str(ROOT_DIR / "dataset" / "advanced_attack_simulator.py")]
    if args.scenario == "benign":
        return [PYTHON, str(ROOT_DIR / "dataset" / "simulate_benign_activity.py")]
    if args.scenario == "attack":
        if not args.attack:
            raise SystemExit("--scenario attack 时必须提供 --attack")
        return [PYTHON, str(ROOT_DIR / "dataset" / "simulate_attacks.py"), "--attack", args.attack]
    if args.scenario == "loader":
        command = [
            PYTHON,
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
    out_dir = Path(args.out_dir) if args.out_dir else RUNS_DIR / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    run_command(
        [
            PYTHON,
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
            PYTHON,
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
            PYTHON,
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
        if path.name == ALERTS_FILE:
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

    if args.archive_logs:
        archived = archive_runtime_logs(run_id)
        if archived:
            print(f"[*] 旧日志已归档到: {archived}")

    start_args = argparse.Namespace(
        no_detector=args.no_detector,
        mode=args.mode,
        window_ms=args.window_ms,
        block_score=args.block_score,
        restart=True,
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
    parser.add_argument("--window-ms", type=int, default=DEFAULT_WINDOW_MS)
    parser.add_argument("--block-score", type=int, default=7)
    parser.add_argument("--no-detector", action="store_true")
    parser.add_argument("--restart", action="store_true", help="restart the stack if it is already running")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="OS-Monitor unified workflow CLI",
        epilog=(
            "推荐流程:\n"
            "  sudo python3 os_monitor.py start --mode detect\n"
            "  python3 os_monitor.py status\n"
            "  python3 os_monitor.py watch\n"
            "  sudo python3 os_monitor.py stop\n"
            "\n"
            "实验流程:\n"
            "  sudo python3 os_monitor.py quick --scenario advanced --mode block --build\n"
            "  python3 os_monitor.py build --input /var/log/os_monitor_log --out-dir runs/manual"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    start_parser = subparsers.add_parser("start", aliases=["up"], help="start agents and detector in background")
    add_shared_stack_args(start_parser)
    start_parser.set_defaults(func=start_stack)

    stop_parser = subparsers.add_parser("stop", aliases=["down"], help="stop agents and detector")
    stop_parser.set_defaults(func=stop_stack)

    status_parser = subparsers.add_parser("status", help="show current status")
    status_parser.set_defaults(func=show_status)

    watch_parser = subparsers.add_parser("watch", aliases=["dashboard"], help="open a live dashboard, auto-starting the stack if needed")
    add_shared_stack_args(watch_parser)
    watch_parser.set_defaults(func=watch_dashboard)

    build_parser = subparsers.add_parser("build", help="build sessions/features from an existing log directory")
    build_parser.add_argument("--input", default=str(LOG_DIR))
    build_parser.add_argument("--out-dir", default=None)
    build_parser.add_argument("--run-id", default=None)
    build_parser.add_argument("--window-ms", type=int, default=DEFAULT_WINDOW_MS)
    build_parser.add_argument("--stride-ms", type=int, default=DEFAULT_STRIDE_MS)
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
    quick_parser.add_argument("--stride-ms", type=int, default=DEFAULT_STRIDE_MS)
    quick_parser.add_argument("--archive-logs", action="store_true", default=True)
    quick_parser.add_argument("--no-archive-logs", action="store_false", dest="archive_logs")
    quick_parser.set_defaults(func=quick_run)

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
