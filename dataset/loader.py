#!/usr/bin/env python3
"""Detonate one malware sample inside an isolated VM against a decoy directory."""

from __future__ import annotations

import argparse
import datetime
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--malware-dir", default="dataset/malware_samples")
    parser.add_argument("--target-dir", default="/tmp/documents_to_encrypt")
    parser.add_argument("--sample", default=None, help="sample filename; defaults to the first file")
    parser.add_argument("--timeout", type=int, default=60)
    return parser.parse_args()


def reset_target_directory(target_dir: Path) -> None:
    """Create a clean decoy directory for each detonation."""
    print(f"[*] Resetting target directory: {target_dir}")

    if target_dir.exists():
        def on_rm_error(func, path, exc_info):
            os.chmod(path, stat.S_IWRITE)
            func(path)

        shutil.rmtree(target_dir, onerror=on_rm_error)

    target_dir.mkdir(parents=True, exist_ok=True)
    for index in range(100):
        with (target_dir / f"doc_{index}.docx").open("w", encoding="utf-8") as handle:
            handle.write("Confidential Data " * 100)


def run_sample(sample_path: Path, target_dir: Path, timeout: int) -> None:
    """Execute one sample against the prepared decoy directory."""
    print(f"[*] [REAL] Detonating {sample_path.name} at {datetime.datetime.now().isoformat()}")
    os.chmod(sample_path, 0o777)

    command = [str(sample_path), str(target_dir)]
    print(f"    -> Executing: {' '.join(command)}")
    try:
        subprocess.run(command, timeout=timeout, cwd=str(target_dir))
    except subprocess.TimeoutExpired:
        print("[!] Sample execution timed out (likely still encrypting)")
    except Exception as exc:
        print(f"[!] Error running sample: {exc}")


def main() -> None:
    args = parse_args()
    malware_dir = Path(args.malware_dir)
    target_dir = Path(args.target_dir)

    if not malware_dir.exists():
        raise SystemExit(f"[!] Malware directory not found: {malware_dir}")

    samples = sorted(path for path in malware_dir.iterdir() if path.is_file())
    if not samples:
        raise SystemExit("[!] No samples found.")

    if args.sample:
        selected = malware_dir / args.sample
        if selected not in samples:
            raise SystemExit(f"[!] Requested sample not found: {selected}")
        sample_path = selected
    else:
        sample_path = samples[0]

    reset_target_directory(target_dir)
    run_sample(sample_path, target_dir, args.timeout)

    print("[*] Waiting 30s for post-encryption activity...")
    time.sleep(30)

    print("-" * 40)
    print("[*] Detonation finished.")
    print("[*] 1. Stop monitoring (sudo python3 os_monitor.py stop)")
    print("[*] 2. Collect logs (python3 aggregator/fast_collector.py)")
    print("[*] 3. Revert the VM snapshot immediately")


if __name__ == "__main__":
    main()
