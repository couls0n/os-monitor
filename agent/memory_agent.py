#!/usr/bin/env python3
"""
memory_agent.py
增强版：监控关键内存操作事件。
1. mprotect: 监控内存权限变更，特别是 PROT_EXEC (可执行) 权限的设置。
2. process_vm_writev: 监控跨进程内存写入，常用于进程注入。
需要 root 权限运行。
"""

from bcc import BPF
from datetime import datetime, timezone
import json
import os
import signal
import sys

# 与其他 agent 保持一致的输出目录
OUT_DIR = "/var/log/os_monitor_log"
os.makedirs(OUT_DIR, exist_ok=True)
OUT_FILE = os.path.join(OUT_DIR, "memory.jsonl")

# BPF 程序
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm.h>

// --- 修复: 手动定义 PROT_EXEC ---
#ifndef PROT_EXEC
#define PROT_EXEC 0x4
#endif
// ---------------------------------

struct data_t {
    u32 pid;
    u64 ts_ns;
    char comm[TASK_COMM_LEN];
    int event_type; // 1 = mprotect, 2 = vm_writev
    
    // mprotect fields
    unsigned long prot;
    
    // vm_writev fields
    int target_pid;
};

BPF_PERF_OUTPUT(events);

// 1. 监控 mprotect 系统调用
int trace_mprotect(struct tracepoint__syscalls__sys_enter_mprotect *args) {
    // 我们只关心权限中包含 PROT_EXEC (0x4) 的变更
    if (!(args->prot & PROT_EXEC)) {
        return 0;
    }

    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    data.event_type = 1;
    data.prot = args->prot;

    events.perf_submit((void *)args, &data, sizeof(data));
    return 0;
}

// 2. 监控 process_vm_writev 系统调用
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
"""

def prot_to_str(prot):
    """将 mprotect 权限标志转换为字符串"""
    perms = []
    if prot & 0x1: perms.append("PROT_READ")
    if prot & 0x2: perms.append("PROT_WRITE")
    if prot & 0x4: perms.append("PROT_EXEC")
    if not perms: perms.append("PROT_NONE")
    return "|".join(perms)

def write_record(record: dict):
    """写入 JSONL 文件"""
    try:
        with open(OUT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[!] 写入日志失败: {e}")

def main():
    print("[*] 正在加载 BPF 程序 (Memory Monitor)...")
    b = BPF(text=BPF_PROGRAM)

    # 挂载 tracepoint
    try:
        b.attach_tracepoint("syscalls:sys_enter_mprotect", "trace_mprotect")
        print("[+] tracepoint sys_enter_mprotect 挂载成功")
        b.attach_tracepoint("syscalls:sys_enter_process_vm_writev", "trace_vm_writev")
        print("[+] tracepoint sys_enter_process_vm_writev 挂载成功")
    except Exception as e:
        print(f"[!] tracepoint 挂载失败: {e}")
        sys.exit(1)

    def handle_event(cpu, data, size):
        event = b["events"].event(data)
        record = {
            "pid": int(event.pid),
            "comm": event.comm.decode('utf-8', 'replace').strip("\x00"),
            "ts_ns": int(event.ts_ns),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        if event.event_type == 1: # mprotect
            record["event"] = "mprotect"
            record["protection"] = prot_to_str(event.prot)
            print(f"[MEM] PID={record['pid']} comm={record['comm']} event=mprotect protection={record['protection']}")
        
        elif event.event_type == 2: # vm_writev
            record["event"] = "vm_writev"
            record["target_pid"] = int(event.target_pid)
            print(f"[MEM] PID={record['pid']} comm={record['comm']} event=vm_writev target_pid={record['target_pid']}")
        
        write_record(record)

    b["events"].open_perf_buffer(handle_event)
    print(f"[+] memory_agent 已启动，日志保存至: {OUT_FILE}")
    print("[*] 按 Ctrl+C 或发送 SIGTERM 停止采集")

    def handle_sig(signum, frame):
        print("\n[!] memory_agent 停止运行")
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