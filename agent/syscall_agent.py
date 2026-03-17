#!/usr/bin/env python3
"""
syscall_agent.py
增强版：监控一组预定义的高风险/可疑系统调用。
记录发起调用的 PID、进程名和被调用的 syscall 名称。
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
OUT_FILE = os.path.join(OUT_DIR, "syscall.jsonl")


# 监控的系统调用列表
SUSPICIOUS_SYSCALLS = [
    "ptrace",
    "bpf",
    "setuid",
    "setgid",
    "setreuid",
    "setresuid",
    "kexec_load",
    "mount",
    "unshare",
    "ioperm",
    "iopl",
]

# BPF 程序 - 基础模板
# --- 修复: 移除了 C 宏 'TRACE_SYSCALL' ---
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u64 ts_ns;
    char comm[TASK_COMM_LEN];
    char syscall_name[64];
};

BPF_PERF_OUTPUT(events);

// C 函数将由 Python 动态生成并附加到这里
"""

def write_record(record: dict):
    """写入 JSONL 文件"""
    try:
        with open(OUT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[!] 写入日志失败: {e}")

def main():
    print("[*] 正在加载 BPF 程序 (Suspicious Syscall Monitor)...")
    
    # --- 修复: 动态构建完整的 C 函数，而不是使用宏 ---
    
    # 1. 定义 Python f-string 模板来创建 C 函数
    c_function_template = """
int trace_{syscall_name}(struct tracepoint__syscalls__sys_enter_{syscall_name} *args) {{
    struct data_t data = {{}};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // 直接将系统调用名称作为字符串常量写入
    const char *name = "{syscall_name}";
    bpf_probe_read_kernel_str(&data.syscall_name, sizeof(data.syscall_name), name);
    
    events.perf_submit((void *)args, &data, sizeof(data));
    return 0;
}}
"""
    
    # 2. 从基础 BPF 程序开始
    bpf_text = BPF_PROGRAM
    
    # 3. 为列表中的每个 syscall 生成 C 函数并附加到 BPF 文本
    for syscall_name in SUSPICIOUS_SYSCALLS:
        bpf_text += c_function_template.format(syscall_name=syscall_name)
    
    # 4. 使用生成的完整 BPF C 代码初始化 BPF
    b = BPF(text=bpf_text)
    # --- 修复结束 ---


    # 挂载 tracepoints
    attached_count = 0
    for syscall_name in SUSPICIOUS_SYSCALLS:
        tracepoint_name = f"syscalls:sys_enter_{syscall_name}"
        function_name = f"trace_{syscall_name}"
        try:
            b.attach_tracepoint(tracepoint_name, function_name)
            attached_count += 1
        except Exception as e:
            print(f"[!] 挂载 {tracepoint_name} 失败: {e} (可能内核不支持或拼写错误)")
            
    if attached_count == 0:
        print("[!] 未能挂载任何可疑系统调用 tracepoint，退出。")
        sys.exit(1)
        
    print(f"[+] 成功挂载 {attached_count} 个可疑系统调用 tracepoints")

    def handle_event(cpu, data, size):
        event = b["events"].event(data)
        record = {
            "source": "syscall",
            "pid": int(event.pid),
            "comm": event.comm.decode('utf-8', 'replace').strip("\x00"),
            "ts_ns": int(event.ts_ns),
            "event": "suspicious_syscall",
            "syscall_name": event.syscall_name.decode('utf-8', 'replace').strip("\x00"),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # 控制台打印日志
        print(f"[SYSCALL] PID={record['pid']} comm={record['comm']} called -> {record['syscall_name']}")

        write_record(record)

    b["events"].open_perf_buffer(handle_event)
    print(f"[+] syscall_agent 已启动，日志保存至: {OUT_FILE}")
    print("[*] 按 Ctrl+C 或发送 SIGTERM 停止采集")

    # 安全退出信号处理
    def handle_sig(signum, frame):
        print("\n[!] syscall_agent 停止运行")
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
