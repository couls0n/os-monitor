#!/usr/bin/env python3
"""
dns_agent.py
增强版：监控用户态 DNS 查询 (getaddrinfo)。
记录 PID、进程名、查询的域名和时间戳。
需要 root 权限运行 (用于 BPF) 且需要 libc 符号。
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
OUT_FILE = os.path.join(OUT_DIR, "dns.jsonl")

# BPF 程序
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u64 ts_ns;
    char comm[TASK_COMM_LEN];
    char host[256];
};

BPF_PERF_OUTPUT(events);

int trace_getaddrinfo(struct pt_regs *ctx, const char *node) {
    if (node == NULL) {
        return 0;
    }

    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // 从用户空间读取域名字符串
    bpf_probe_read_user_str(&data.host, sizeof(data.host), (void *)node);

    events.perf_submit(ctx, &data, sizeof(data));
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
    print("[*] 正在加载 BPF 程序 (DNS Monitor)...")
    b = BPF(text=BPF_PROGRAM)

    # 挂载 uprobe 到 C 库的 getaddrinfo 函数
    # 这是用户态探测，不是内核态
    try:
        b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="trace_getaddrinfo")
        print("[+] uprobe getaddrinfo 挂载成功")
    except Exception as e:
        print(f"[!] uprobe getaddrinfo 挂载失败: {e}")
        print("[!] 提示: 确保 libc 已安装且符号可见。")
        sys.exit(1)

    def handle_event(cpu, data, size):
        event = b["events"].event(data)
        record = {
            "pid": int(event.pid),
            "comm": event.comm.decode('utf-8', 'replace').strip("\x00"),
            "ts_ns": int(event.ts_ns),
            "event": "dns_query",
            "host": event.host.decode('utf-8', 'replace').strip("\x00"),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # 控制台打印日志
        print(f"[DNS] PID={record['pid']} comm={record['comm']} query={record['host']}")

        write_record(record)

    b["events"].open_perf_buffer(handle_event)
    print(f"[+] dns_agent 已启动，日志保存至: {OUT_FILE}")
    print("[*] 按 Ctrl+C 或发送 SIGTERM 停止采集")

    # 安全退出信号处理
    def handle_sig(signum, frame):
        print("\n[!] dns_agent 停止运行")
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