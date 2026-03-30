#!/usr/bin/env python3
"""
memory_agent.py

Monitors memory allocation and code-execution pivots that commonly appear in
fileless attacks: mmap, brk, mprotect(PROT_EXEC) and process_vm_writev.
"""

from __future__ import annotations

import json
import os
import signal
import sys
from pathlib import Path

from bcc import BPF


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from monitoring.time_utils import monotonic_ns_to_utc_iso


OUT_DIR = "/var/log/os_monitor_log"
os.makedirs(OUT_DIR, exist_ok=True)
OUT_FILE = os.path.join(OUT_DIR, "memory.jsonl")

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>
#include <linux/sched.h>

#ifndef PROT_EXEC
#define PROT_EXEC 0x4
#endif

struct data_t {
    u32 pid;
    u64 ts_ns;
    char comm[TASK_COMM_LEN];
    int event_type; // 1=mprotect, 2=vm_writev, 3=mmap, 4=brk
    unsigned long prot;
    unsigned long length;
    unsigned long flags;
    unsigned long address;
    int target_pid;
};

BPF_PERF_OUTPUT(events);

int trace_mprotect(struct tracepoint__syscalls__sys_enter_mprotect *args) {
    if (!(args->prot & PROT_EXEC)) {
        return 0;
    }

    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.event_type = 1;
    data.prot = args->prot;
    data.address = args->start;
    data.length = args->len;
    events.perf_submit((void *)args, &data, sizeof(data));
    return 0;
}

int trace_vm_writev(struct tracepoint__syscalls__sys_enter_process_vm_writev *args) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.event_type = 2;
    data.target_pid = args->pid;
    events.perf_submit((void *)args, &data, sizeof(data));
    return 0;
}

int trace_mmap(struct tracepoint__syscalls__sys_enter_mmap *args) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.event_type = 3;
    data.prot = args->prot;
    data.length = args->len;
    data.flags = args->flags;
    data.address = args->addr;
    events.perf_submit((void *)args, &data, sizeof(data));
    return 0;
}

int trace_brk(struct tracepoint__syscalls__sys_enter_brk *args) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.event_type = 4;
    data.address = args->brk;
    events.perf_submit((void *)args, &data, sizeof(data));
    return 0;
}
"""


def prot_to_str(prot: int) -> str:
    perms = []
    if prot & 0x1:
        perms.append("PROT_READ")
    if prot & 0x2:
        perms.append("PROT_WRITE")
    if prot & 0x4:
        perms.append("PROT_EXEC")
    if not perms:
        perms.append("PROT_NONE")
    return "|".join(perms)


def write_record(record: dict) -> None:
    with open(OUT_FILE, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def main() -> None:
    print("[*] loading memory monitor BPF ...")
    bpf = BPF(text=BPF_PROGRAM)

    attachments = (
        ("syscalls:sys_enter_mprotect", "trace_mprotect"),
        ("syscalls:sys_enter_process_vm_writev", "trace_vm_writev"),
        ("syscalls:sys_enter_mmap", "trace_mmap"),
        ("syscalls:sys_enter_brk", "trace_brk"),
    )

    attached = 0
    for tracepoint, function in attachments:
        try:
            bpf.attach_tracepoint(tracepoint, function)
            attached += 1
            print(f"[+] attached {tracepoint}")
        except Exception as exc:
            print(f"[!] failed to attach {tracepoint}: {exc}")

    if attached == 0:
        print("[!] no memory tracepoints attached; exiting")
        sys.exit(1)

    def handle_event(cpu, data, size):
        event = bpf["events"].event(data)
        record = {
            "source": "memory",
            "pid": int(event.pid),
            "comm": event.comm.decode("utf-8", "replace").strip("\x00"),
            "ts_ns": int(event.ts_ns),
            "timestamp": monotonic_ns_to_utc_iso(int(event.ts_ns)),
            "address": int(event.address),
            "length": int(event.length),
            "flags": int(event.flags),
        }

        if event.event_type == 1:
            record["event"] = "mprotect"
            record["protection"] = prot_to_str(int(event.prot))
            print(
                f"[MEM] pid={record['pid']} comm={record['comm']} mprotect={record['protection']} "
                f"length={record['length']}"
            )
        elif event.event_type == 2:
            record["event"] = "vm_writev"
            record["target_pid"] = int(event.target_pid)
            print(
                f"[MEM] pid={record['pid']} comm={record['comm']} vm_writev target={record['target_pid']}"
            )
        elif event.event_type == 3:
            record["event"] = "mmap"
            record["protection"] = prot_to_str(int(event.prot))
            print(
                f"[MEM] pid={record['pid']} comm={record['comm']} mmap length={record['length']} "
                f"prot={record['protection']}"
            )
        elif event.event_type == 4:
            record["event"] = "brk"
            print(f"[MEM] pid={record['pid']} comm={record['comm']} brk addr={record['address']}")
        else:
            return

        write_record(record)

    bpf["events"].open_perf_buffer(handle_event)
    print(f"[+] memory_agent started, logs -> {OUT_FILE}")

    def handle_sig(signum, frame):
        print("\n[!] memory_agent stopped")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    while True:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()
