#!/usr/bin/env python3
"""
net_agent.py
增强版：监控 TCP 连接事件，记录 PID、目标 IP、目标端口和时间戳。
需要 root 权限运行。
"""

from bcc import BPF
import json
import os
import socket
import struct
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from monitoring.time_utils import monotonic_ns_to_utc_iso

OUT_DIR = "/var/log/os_monitor_log"
os.makedirs(OUT_DIR, exist_ok=True)
OUT_FILE = os.path.join(OUT_DIR, "net.jsonl")
# BPF 程序
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct data_t {
    u32 pid;
    u64 ts_ns;
    int family;
    u16 dport;
    u32 daddr;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    struct data_t data = {};
    u16 dport = 0;
    u32 daddr = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    data.dport = ntohs(dport);
    data.daddr = daddr;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts_ns = bpf_ktime_get_ns();
    data.family = sk->__sk_common.skc_family;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
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

def ipv4_from_int(n):
    """将整数 IP 转为点分十进制"""
    try:
        return socket.inet_ntoa(struct.pack("!I", n))
    except Exception:
        return ""

def main():
    print("[*] 正在加载 BPF 程序...")
    b = BPF(text=BPF_PROGRAM)

    # 尝试挂载不同内核函数
    attached = False
    for func in ["tcp_v4_connect", "inet_sock_connect"]:
        try:
            b.attach_kprobe(event=func, fn_name="trace_connect")
            attached = True
            print(f"[+] kprobe {func} 挂载成功")
            break
        except Exception as e:
            print(f"[!] kprobe {func} 挂载失败: {e}")

    if not attached:
        print("[!] 未能挂载任何网络 kprobe，退出")
        return

    def handle_event(cpu, data, size):
        event = b["events"].event(data)
        record = {
            "source": "net",
            "pid": int(event.pid),
            "comm": event.comm.decode('utf-8', 'replace').strip("\x00"),
            "ts_ns": int(event.ts_ns),
            "family": int(event.family),
            "dport": int(event.dport),
            "daddr": int(event.daddr),
            "daddr_str": ipv4_from_int(int(event.daddr)),
            "event": "connect",
            "timestamp": monotonic_ns_to_utc_iso(int(event.ts_ns)),
        }

        # 控制台打印日志
        print(
            f"[NET] PID={record['pid']} comm={record['comm']} "
            f"-> {record['daddr_str']}:{record['dport']}"
        )

        write_record(record)

    b["events"].open_perf_buffer(handle_event)
    print(f"[+] net_agent 已启动，日志保存至: {OUT_FILE}")
    print("[*] 按 Ctrl+C 停止采集")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n[!] net_agent 停止运行")

if __name__ == "__main__":
    main()
