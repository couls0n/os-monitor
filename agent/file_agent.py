#!/usr/bin/env python3
"""
file_agent.py
增强版：监控文件系统活动，捕获 openat 与 write 系统调用事件。
记录 PID、事件类型、时间戳、文件名及写入字节数。
需要 root 权限运行。
"""

from bcc import BPF
import os
import json
from datetime import datetime, timezone


# 输出目录配置
OUT_DIR = "/var/log/os_monitor_log"
os.makedirs(OUT_DIR, exist_ok=True)
OUT_FILE = os.path.join(OUT_DIR, "fileio.jsonl")
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/limits.h>

struct data_t {
    u32 pid;
    u64 ts_ns;
    int event; // 1=openat, 2=write
    char fname[256];
    long count;
};

BPF_PERF_OUTPUT(events);

// tracepoint 追踪 openat 系统调用（读取文件名）
int trace_openat(struct tracepoint__syscalls__sys_enter_openat *args) {
    struct data_t data = {};
    data.ts_ns = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.event = 1;
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->filename);
    events.perf_submit((void *)args, &data, sizeof(data));
    return 0;
}

// kprobe 追踪 write 系统调用（记录写入字节数）
int trace_write(struct pt_regs *ctx, int fd, const char __user *buf, size_t count) {
    struct data_t data = {};
    data.ts_ns = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.event = 2;
    data.count = count;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

def write_record(record: dict):
    """写入单条 JSON 记录"""
    try:
        with open(OUT_FILE, "a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[!] 写入日志失败: {e}")

def main():
    print("[*] 正在加载 BPF 程序...")
    b = BPF(text=BPF_PROGRAM)

    # 挂载 tracepoint 和 kprobe
    try:
        b.attach_tracepoint("syscalls:sys_enter_openat", "trace_openat")
        print("[+] tracepoint sys_enter_openat 挂载成功")
    except Exception as e:
        print(f"[!] sys_enter_openat tracepoint 挂载失败: {e}")

    try:
        b.attach_kprobe(event="__x64_sys_write", fn_name="trace_write")
        print("[+] kprobe __x64_sys_write 挂载成功")
    except Exception:
        try:
            b.attach_kprobe(event="sys_write", fn_name="trace_write")
            print("[+] kprobe sys_write 挂载成功")
        except Exception as e:
            print(f"[!] write kprobe 挂载失败: {e}")

    def handle_event(cpu, data, size):
        event = b["events"].event(data)
        record = {
            "pid": int(event.pid),
            "ts_ns": int(event.ts_ns),
            "event": "openat" if event.event == 1 else "write",
            "count": int(event.count),
            "fname": event.fname.decode("utf-8", "replace").strip("\x00"),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # 打印到控制台方便确认
        if record["event"] == "openat":
            print(f"[OPEN] PID={record['pid']} -> {record['fname']}")
        else:
            print(f"[WRITE] PID={record['pid']} count={record['count']} bytes")

        write_record(record)

    b["events"].open_perf_buffer(handle_event)
    print(f"[+] file_agent 已启动，日志保存至: {OUT_FILE}")
    print("[*] 按 Ctrl+C 停止采集")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n[!] file_agent 停止运行")

if __name__ == "__main__":
    main()
