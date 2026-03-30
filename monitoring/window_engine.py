#!/usr/bin/env python3
"""Feature extraction helpers shared by offline and real-time detectors."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from math import log2
from statistics import mean
from typing import Any, Dict, Iterable, List, Sequence

from monitoring.event_schema import sort_events


SUSPICIOUS_PATTERNS = {
    "seq_encrypt": ("file.open", "file.write", "file.rename"),
    "seq_encrypt_cleanup": ("file.write", "file.rename", "file.delete"),
    "seq_memory_exec": ("memory.mmap", "memory.mprotect"),
    "seq_memory_inject": ("memory.vm_writev", "memory.mprotect"),
    "seq_dns_burst": ("dns.query", "dns.query", "dns.query"),
}


@dataclass(frozen=True)
class ThresholdProfile:
    """Heuristic thresholds for the real-time blocker."""

    rename_burst: int = 4
    delete_burst: int = 4
    write_bytes_burst: int = 1_500_000
    write_rate_bps: float = 2_500_000.0
    file_ops_rate: float = 10.0
    suspicious_syscalls: int = 2
    dns_burst: int = 8
    long_dns_queries: int = 3
    high_entropy_dns: int = 2
    block_score: int = 7


def sequence_ngrams(items: Sequence[str], size: int) -> List[tuple[str, ...]]:
    """Return contiguous n-grams for a sequence."""
    if size <= 0 or len(items) < size:
        return []
    return [tuple(items[index : index + size]) for index in range(len(items) - size + 1)]


def count_named_patterns(sequence: Sequence[str]) -> Dict[str, int]:
    """Count suspicious contiguous patterns inside the event sequence."""
    result: Dict[str, int] = {}
    ngram_cache: Dict[int, Counter[tuple[str, ...]]] = {}

    for name, pattern in SUSPICIOUS_PATTERNS.items():
        size = len(pattern)
        if size not in ngram_cache:
            ngram_cache[size] = Counter(sequence_ngrams(sequence, size))
        result[name] = ngram_cache[size][pattern]

    return result


def shannon_entropy(value: str) -> float:
    """Compute Shannon entropy for a string."""
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    entropy = 0.0
    for freq in counts.values():
        probability = freq / total
        entropy -= probability * log2(probability)
    return entropy


def event_time_seconds(event: Dict[str, Any]) -> float:
    """Return a comparable timestamp for the event."""
    if event.get("timeline_ts") is not None:
        return float(event["timeline_ts"])
    if event.get("ts_ns") is not None:
        return float(event["ts_ns"]) / 1e9
    if event.get("sort_ts") is not None:
        return float(event["sort_ts"])
    return 0.0


def window_duration_seconds(events: Sequence[Dict[str, Any]]) -> float:
    """Compute window duration while avoiding divide-by-zero."""
    if not events:
        return 0.001
    start = event_time_seconds(events[0])
    end = event_time_seconds(events[-1])
    return max(end - start, 0.001)


def longest_domain_label(host: str) -> str:
    """Return the longest label in a DNS hostname."""
    if not host:
        return ""
    labels = [label for label in host.split(".") if label]
    return max(labels, key=len, default="")


def group_events_by_pid(events: Iterable[Dict[str, Any]]) -> Dict[int, List[Dict[str, Any]]]:
    """Group canonical events by PID."""
    grouped: Dict[int, List[Dict[str, Any]]] = {}
    for event in sort_events(events):
        pid = event.get("pid")
        if pid is None:
            continue
        grouped.setdefault(int(pid), []).append(event)
    return grouped


def extract_window_metrics(events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract sequence, rate and resource metrics for a single PID window."""
    events = sort_events(events)
    duration = window_duration_seconds(events)
    event_keys = [event.get("event_key", "unknown.unknown") for event in events]
    counter = Counter(event_keys)
    pattern_counts = count_named_patterns(event_keys)

    file_paths = {
        event["file_path"]
        for event in events
        if event.get("file_path")
    }
    dns_hosts = [event["dns_host"] for event in events if event.get("dns_host")]
    remote_ips = {
        event["remote_ip"]
        for event in events
        if event.get("remote_ip")
    }
    comm_values = [event.get("comm") for event in events if event.get("comm")]

    longest_labels = [longest_domain_label(host) for host in dns_hosts]
    high_entropy_dns = [
        label
        for label in longest_labels
        if len(label) >= 12 and shannon_entropy(label) >= 3.3
    ]
    long_dns_queries = [
        host
        for host in dns_hosts
        if len(host) >= 45 or any(len(label) >= 20 for label in host.split("."))
    ]

    write_bytes = sum(event.get("write_bytes", 0) or 0 for event in events)
    mmap_bytes = sum(
        event.get("memory_length", 0) or 0
        for event in events
        if event.get("event_key") == "memory.mmap"
    )

    rename_count = counter["file.rename"]
    delete_count = counter["file.delete"]
    file_write_count = counter["file.write"]
    file_open_count = counter["file.open"]

    metrics = {
        "event_count": len(events),
        "duration_s": duration,
        "event_rate": len(events) / duration,
        "write_bytes": write_bytes,
        "write_bytes_per_sec": write_bytes / duration,
        "mmap_bytes": mmap_bytes,
        "file_open_count": file_open_count,
        "file_write_count": file_write_count,
        "rename_count": rename_count,
        "delete_count": delete_count,
        "file_churn_rate": (rename_count + delete_count + file_write_count) / duration,
        "process_exec_count": counter["process.exec"],
        "process_fork_count": counter["process.fork"],
        "process_exit_count": counter["process.exit"],
        "dns_query_count": counter["dns.query"],
        "net_connect_count": counter["net.connect"],
        "memory_mprotect_count": counter["memory.mprotect"],
        "memory_vm_writev_count": counter["memory.vm_writev"],
        "memory_mmap_count": counter["memory.mmap"],
        "memory_brk_count": counter["memory.brk"],
        "kmod_load_count": counter["kmod.load"],
        "suspicious_syscall_count": sum(
            count
            for key, count in counter.items()
            if key.startswith("syscall.")
        ),
        "unique_files": len(file_paths),
        "unique_dns_hosts": len(set(dns_hosts)),
        "unique_remote_ips": len(remote_ips),
        "unique_comms": len(set(comm_values)),
        "long_dns_query_count": len(long_dns_queries),
        "high_entropy_dns_count": len(high_entropy_dns),
        "memory_exec_combo": int(
            counter["memory.mmap"] > 0 and counter["memory.mprotect"] > 0
        ),
        "memory_inject_combo": int(
            counter["memory.vm_writev"] > 0 and counter["memory.mprotect"] > 0
        ),
        "dominant_comm": Counter(comm_values).most_common(1)[0][0] if comm_values else "",
    }
    metrics.update(pattern_counts)
    return metrics


def aggregate_pid_metrics(metrics_by_pid: Dict[int, Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate per-PID metrics into max/mean session features."""
    if not metrics_by_pid:
        return {}

    numeric_keys = [
        key
        for key, value in next(iter(metrics_by_pid.values())).items()
        if isinstance(value, (int, float))
    ]

    aggregated: Dict[str, Any] = {}
    for key in numeric_keys:
        values = [float(metrics[key]) for metrics in metrics_by_pid.values()]
        aggregated[f"max_{key}"] = max(values)
        aggregated[f"mean_{key}"] = mean(values)

    dominant_pid = max(
        metrics_by_pid.items(),
        key=lambda item: item[1].get("event_count", 0),
    )[0]
    aggregated["dominant_pid"] = dominant_pid
    aggregated["dominant_comm"] = metrics_by_pid[dominant_pid].get("dominant_comm", "")
    return aggregated


def score_pid_metrics(
    metrics: Dict[str, Any],
    thresholds: ThresholdProfile,
) -> tuple[int, List[str]]:
    """Score one PID window and return reasons for the score."""
    score = 0
    reasons: List[str] = []

    if (
        metrics.get("rename_count", 0) >= thresholds.rename_burst
        and metrics.get("write_bytes", 0) >= thresholds.write_bytes_burst
    ):
        score += 4
        reasons.append("rename burst with heavy writes")

    if metrics.get("delete_count", 0) >= thresholds.delete_burst:
        score += 2
        reasons.append("delete burst")

    if metrics.get("write_bytes_per_sec", 0.0) >= thresholds.write_rate_bps:
        score += 2
        reasons.append("write throughput spike")

    if metrics.get("file_churn_rate", 0.0) >= thresholds.file_ops_rate:
        score += 2
        reasons.append("file operation spike")

    if metrics.get("seq_encrypt", 0) > 0 or metrics.get("seq_encrypt_cleanup", 0) > 0:
        score += 3
        reasons.append("ransomware-like file sequence")

    if metrics.get("memory_exec_combo", 0):
        score += 4
        reasons.append("mmap + mprotect executable memory pattern")

    if metrics.get("memory_inject_combo", 0):
        score += 4
        reasons.append("cross-process write + executable memory pattern")

    if metrics.get("suspicious_syscall_count", 0) >= thresholds.suspicious_syscalls:
        score += 2
        reasons.append("burst of suspicious syscalls")

    if (
        metrics.get("dns_query_count", 0) >= thresholds.dns_burst
        and metrics.get("long_dns_query_count", 0) >= thresholds.long_dns_queries
    ):
        score += 3
        reasons.append("dns burst with long subdomains")

    if metrics.get("high_entropy_dns_count", 0) >= thresholds.high_entropy_dns:
        score += 2
        reasons.append("high-entropy dns labels")

    if metrics.get("kmod_load_count", 0) > 0:
        score += 4
        reasons.append("kernel module load attempt")

    return score, reasons
