#!/usr/bin/env python3
"""
process_agent.py
增强版：监控进程生命周期事件（exec、fork、exit），记录 PID、PPID、进程名及时间戳。
输出 JSONL 文件，方便后续处理。
需要 root 权限运行。
"""

from pathlib import Path
from bcc import BPF
import json
import os
import signal
import sys


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from monitoring.time_utils import monotonic_ns_to_utc_iso


OUT_DIR = "/var/log/os_monitor_log"
os.makedirs(OUT_DIR, exist_ok=True)
OUT_FILE = os.path.join(OUT_DIR, "process.jsonl")

BPF_PROGRAM = r"""
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 ppid;
    u64 ts_ns;
    int event; // 1 exec, 2 fork, 3 exit
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

static __always_inline u32 current_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = 0;
    if (!task) {
        return 0;
    }
    bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);
    return ppid;
}

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct data_t data = {};
    data.pid = args->pid;
    data.ppid = current_ppid();
    data.ts_ns = bpf_ktime_get_ns();
    data.event = 1;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_fork) {
    struct data_t data = {};
    data.pid = args->child_pid;
    data.ppid = args->parent_pid;
    data.ts_ns = bpf_ktime_get_ns();
    data.event = 2;
    bpf_probe_read_kernel_str(&data.comm, sizeof(data.comm), args->child_comm);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct data_t data = {};
    data.pid = args->pid;
    data.ppid = current_ppid();
    data.ts_ns = bpf_ktime_get_ns();
    data.event = 3;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

def write_record(record: dict):
    """写入 JSONL 文件"""
    try:
        with open(OUT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[!] 写入日志失败: {e}")

def main():
    print("[*] 正在加载 BPF 程序...")
    b = BPF(text=BPF_PROGRAM)
    print("[+] 已启用 sched:sched_process_exec/fork/exit tracepoints")

    def handle_event(cpu, data, size):
        event = b["events"].event(data)
        ts_ns = int(event.ts_ns)
        record = {
            "source": "process",
            "pid": int(event.pid),
            "ppid": int(event.ppid),
            "comm": event.comm.decode('utf-8', 'replace').strip("\x00"),
            "ts_ns": ts_ns,
            "event": {1: "exec", 2: "fork", 3: "exit"}.get(int(event.event), "unknown"),
            "timestamp": monotonic_ns_to_utc_iso(ts_ns),
        }

        # 控制台打印日志
        print(f"[PROC] PID={record['pid']} PPID={record['ppid']} event={record['event']} comm={record['comm']}")

        write_record(record)

    b["events"].open_perf_buffer(handle_event)
    print(f"[+] process_agent 已启动，日志保存至: {OUT_FILE}")
    print("[*] 按 Ctrl+C 或发送 SIGTERM 停止采集")

    # 安全退出信号处理
    def handle_sig(signum, frame):
        print("\n[!] process_agent 停止运行")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()
