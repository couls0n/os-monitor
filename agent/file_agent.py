#!/usr/bin/env python3
"""
file_agent.py

File telemetry optimized for ransomware-style behavior detection.
Tracks open/write/unlink/rename with per-PID path correlation so the downstream
detector can reconstruct short file-operation bursts in real time.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from bcc import BPF


WRITE_SAMPLE_RATE = max(1, int(os.getenv("WRITE_SAMPLE_RATE", "1")))
OUT_DIR = "/var/log/os_monitor_log"
os.makedirs(OUT_DIR, exist_ok=True)
OUT_FILE = os.path.join(OUT_DIR, "fileio.jsonl")


BPF_PROGRAM = f"""
#include <uapi/linux/ptrace.h>
#include <linux/limits.h>
#include <linux/sched.h>

#define SAMPLE_RATE {WRITE_SAMPLE_RATE}

struct path_t {{
    char fname[256];
}};

struct fd_key_t {{
    u32 pid;
    int fd;
}};

struct data_t {{
    u32 pid;
    u64 ts_ns;
    int event_type; // 1=open, 2=write, 3=unlink, 4=rename
    int fd;
    char comm[TASK_COMM_LEN];
    char fname[256];
    char new_fname[256];
    u64 write_bytes;
}};

BPF_HASH(inflight_open, u64, struct path_t);
BPF_HASH(fd_paths, struct fd_key_t, struct path_t);
BPF_PERCPU_ARRAY(temp_buffer, struct data_t, 1);
BPF_PERF_OUTPUT(events);

static __always_inline struct data_t* get_data_buffer() {{
    u32 zero = 0;
    struct data_t *data = temp_buffer.lookup(&zero);
    if (!data) {{
        return NULL;
    }}
    data->pid = 0;
    data->ts_ns = 0;
    data->event_type = 0;
    data->fd = -1;
    data->write_bytes = 0;
    data->comm[0] = 0;
    data->fname[0] = 0;
    data->new_fname[0] = 0;
    return data;
}}

int trace_openat(struct tracepoint__syscalls__sys_enter_openat *args) {{
    struct data_t *data = get_data_buffer();
    if (!data) {{
        return 0;
    }}

    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;
    data->ts_ns = bpf_ktime_get_ns();
    data->event_type = 1;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->filename);

    if (data->fname[0] == 0) {{
        return 0;
    }}

    struct path_t pending = {{}};
    __builtin_memcpy(&pending.fname, &data->fname, sizeof(pending.fname));
    inflight_open.update(&pid_tgid, &pending);

    events.perf_submit((void *)args, data, sizeof(*data));
    return 0;
}}

int trace_openat_ret(struct tracepoint__syscalls__sys_exit_openat *args) {{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct path_t *pending = inflight_open.lookup(&pid_tgid);
    if (!pending) {{
        return 0;
    }}

    if (args->ret >= 0) {{
        struct fd_key_t fd_key = {{
            .pid = pid_tgid >> 32,
            .fd = args->ret,
        }};
        struct path_t path_value = {{}};
        __builtin_memcpy(&path_value.fname, &pending->fname, sizeof(path_value.fname));
        fd_paths.update(&fd_key, &path_value);
    }}

    inflight_open.delete(&pid_tgid);
    return 0;
}}

int trace_close(struct tracepoint__syscalls__sys_enter_close *args) {{
    struct fd_key_t fd_key = {{
        .pid = bpf_get_current_pid_tgid() >> 32,
        .fd = args->fd,
    }};
    fd_paths.delete(&fd_key);
    return 0;
}}

int trace_write(struct tracepoint__syscalls__sys_enter_write *args) {{
    if (SAMPLE_RATE > 1 && (bpf_get_prandom_u32() % SAMPLE_RATE) != 0) {{
        return 0;
    }}

    struct data_t *data = get_data_buffer();
    if (!data) {{
        return 0;
    }}

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fd_key_t fd_key = {{
        .pid = pid_tgid >> 32,
        .fd = args->fd,
    }};

    data->pid = fd_key.pid;
    data->ts_ns = bpf_ktime_get_ns();
    data->event_type = 2;
    data->fd = args->fd;
    data->write_bytes = args->count;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    struct path_t *path_value = fd_paths.lookup(&fd_key);
    if (path_value) {{
        __builtin_memcpy(&data->fname, &path_value->fname, sizeof(data->fname));
    }}

    events.perf_submit((void *)args, data, sizeof(*data));
    return 0;
}}

int trace_unlinkat(struct tracepoint__syscalls__sys_enter_unlinkat *args) {{
    struct data_t *data = get_data_buffer();
    if (!data) {{
        return 0;
    }}

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->ts_ns = bpf_ktime_get_ns();
    data->event_type = 3;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->pathname);
    events.perf_submit((void *)args, data, sizeof(*data));
    return 0;
}}

int trace_renameat(struct tracepoint__syscalls__sys_enter_renameat *args) {{
    struct data_t *data = get_data_buffer();
    if (!data) {{
        return 0;
    }}

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->ts_ns = bpf_ktime_get_ns();
    data->event_type = 4;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->oldname);
    bpf_probe_read_user_str(&data->new_fname, sizeof(data->new_fname), (void *)args->newname);
    events.perf_submit((void *)args, data, sizeof(*data));
    return 0;
}}

int trace_renameat2(struct tracepoint__syscalls__sys_enter_renameat2 *args) {{
    struct data_t *data = get_data_buffer();
    if (!data) {{
        return 0;
    }}

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->ts_ns = bpf_ktime_get_ns();
    data->event_type = 4;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->oldname);
    bpf_probe_read_user_str(&data->new_fname, sizeof(data->new_fname), (void *)args->newname);
    events.perf_submit((void *)args, data, sizeof(*data));
    return 0;
}}
"""


def write_record(record: dict) -> None:
    with open(OUT_FILE, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def is_noise(path: str) -> bool:
    if not path:
        return False
    if path.startswith(("/proc", "/sys", "/dev", "/run")):
        return True
    if "/var/log/os_monitor_log" in path:
        return True
    return False


def main() -> None:
    print(f"[*] loading file agent BPF (write sample 1/{WRITE_SAMPLE_RATE}) ...")
    bpf = BPF(text=BPF_PROGRAM)

    for tracepoint, function in (
        ("syscalls:sys_enter_openat", "trace_openat"),
        ("syscalls:sys_exit_openat", "trace_openat_ret"),
        ("syscalls:sys_enter_close", "trace_close"),
        ("syscalls:sys_enter_write", "trace_write"),
        ("syscalls:sys_enter_unlinkat", "trace_unlinkat"),
        ("syscalls:sys_enter_renameat", "trace_renameat"),
    ):
        try:
            bpf.attach_tracepoint(tracepoint, function)
            print(f"[+] attached {tracepoint}")
        except Exception as exc:
            print(f"[!] failed to attach {tracepoint}: {exc}")

    try:
        bpf.attach_tracepoint("syscalls:sys_enter_renameat2", "trace_renameat2")
        print("[+] attached syscalls:sys_enter_renameat2")
    except Exception:
        pass

    print(f"[+] file_agent started, logs -> {OUT_FILE}")

    def handle_event(cpu, data, size):
        event = bpf["events"].event(data)
        comm = event.comm.decode("utf-8", "replace").strip("\x00")
        record = {
            "source": "file",
            "pid": int(event.pid),
            "comm": comm,
            "fd": int(event.fd),
            "ts_ns": int(event.ts_ns),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if event.event_type == 1:
            record["event"] = "open"
            record["fname"] = event.fname.decode("utf-8", "replace").strip("\x00")
            if is_noise(record["fname"]):
                return
        elif event.event_type == 2:
            record["event"] = "write"
            record["fname"] = event.fname.decode("utf-8", "replace").strip("\x00")
            record["count"] = int(event.write_bytes)
            if record["fname"] and is_noise(record["fname"]):
                return
        elif event.event_type == 3:
            record["event"] = "delete"
            record["fname"] = event.fname.decode("utf-8", "replace").strip("\x00")
            if is_noise(record["fname"]):
                return
        elif event.event_type == 4:
            record["event"] = "rename"
            record["fname"] = event.fname.decode("utf-8", "replace").strip("\x00")
            record["new_fname"] = event.new_fname.decode("utf-8", "replace").strip("\x00")
            if is_noise(record["fname"]):
                return
        else:
            return

        if record["event"] == "write":
            print(
                f"[FILE] WRITE pid={record['pid']} comm={comm} bytes={record['count']} path={record.get('fname', '')}"
            )
        else:
            print(f"[FILE] {record['event'].upper()} pid={record['pid']} comm={comm} path={record.get('fname', '')}")

        write_record(record)

    bpf["events"].open_perf_buffer(handle_event)
    try:
        while True:
            bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n[!] file_agent stopped")


if __name__ == "__main__":
    main()
