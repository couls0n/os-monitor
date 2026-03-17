"""Shared constants used across collectors, feature builders and detectors."""

LOG_DIR = "/var/log/os_monitor_log"
OUTPUT_DIR = "logs"
ALERTS_FILE = "alerts.jsonl"

RAW_EVENT_FILES = (
    "process.jsonl",
    "fileio.jsonl",
    "net.jsonl",
    "dns.jsonl",
    "kmod.jsonl",
    "memory.jsonl",
    "syscall.jsonl",
)

DEFAULT_WINDOW_MS = 500
DEFAULT_STRIDE_MS = 250

