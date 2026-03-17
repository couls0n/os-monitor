#!/usr/bin/env python3
"""
process_agent.py
增强版：监控进程生命周期事件（exec、fork、exit），记录 PID、PPID、进程名及时间戳。
输出 JSONL 文件，方便后续处理。
需要 root 权限运行。
"""

from bcc import BPF
from datetime import datetime, timezone
import json
import os
import signal
import sys


OUT_DIR = "/var/log/os_monitor_log"
os.makedirs(OUT_DIR, exist_ok=True)
OUT_FILE = os.path.join(OUT_DIR, "process.jsonl")

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 ppid;
    u64 ts_ns;
    int event; // 1 exec, 2 fork, 3 exit
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int trace_exec(struct pt_regs *ctx, struct task_struct *p) {
    struct data_t data = {};
    data.pid = p->pid;
    data.ppid = p->real_parent->pid;
    data.ts_ns = bpf_ktime_get_ns();
    data.event = 1;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_fork(struct pt_regs *ctx, struct task_struct *p) {
    struct data_t data = {};
    data.pid = p->pid;
    data.ppid = p->real_parent->pid;
    data.ts_ns = bpf_ktime_get_ns();
    data.event = 2;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_exit(struct pt_regs *ctx, struct task_struct *p) {
    struct data_t data = {};
    data.pid = p->pid;
    data.ppid = p->real_parent->pid;
    data.ts_ns = bpf_ktime_get_ns();
    data.event = 3;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

def safe_attach(bpf, kprobe_name, fn_name):
    """安全挂载 kprobe，避免异常退出"""
    try:
        bpf.attach_kprobe(event=kprobe_name, fn_name=fn_name)
        return True
    except Exception:
        return False

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

    # 尝试挂载 exec
    attached_exec = safe_attach(b, "do_execveat_common", "trace_exec")
    if not attached_exec:
        try:
            b.attach_tracepoint("syscalls:sys_enter_execve", "trace_exec")
            attached_exec = True
        except Exception:
            attached_exec = False
    if attached_exec:
        print("[+] exec kprobe/tracepoint 挂载成功")
    else:
        print("[!] exec 挂载失败")

    # 挂载 fork
    if safe_attach(b, "do_fork", "trace_fork"):
        print("[+] fork kprobe 挂载成功")
    else:
        print("[!] fork 挂载失败")

    # 挂载 exit
    if safe_attach(b, "do_exit", "trace_exit"):
        print("[+] exit kprobe 挂载成功")
    else:
        try:
            b.attach_tracepoint("sched:sched_process_exit", "trace_exit")
            print("[+] exit tracepoint 挂载成功")
        except Exception:
            print("[!] exit 挂载失败")

    def handle_event(cpu, data, size):
        event = b["events"].event(data)
        record = {
            "source": "process",
            "pid": int(event.pid),
            "ppid": int(event.ppid),
            "comm": event.comm.decode('utf-8', 'replace').strip("\x00"),
            "ts_ns": int(event.ts_ns),
            "event": {1: "exec", 2: "fork", 3: "exit"}.get(int(event.event), "unknown"),
            "timestamp": datetime.now(timezone.utc).isoformat()
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
