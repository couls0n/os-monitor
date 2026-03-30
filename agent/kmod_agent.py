#!/usr/bin/env python3
"""
kmod_agent.py
增强版：监控内核模块加载事件。
记录 PID、进程名 (如 insmod, modprobe) 以及加载的模块名。
需要 root 权限运行。
"""

from bcc import BPF
import json
import os
import signal
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from monitoring.time_utils import monotonic_ns_to_utc_iso

# 与其他 agent 保持一致的输出目录
OUT_DIR = "/var/log/os_monitor_log"
os.makedirs(OUT_DIR, exist_ok=True)
OUT_FILE = os.path.join(OUT_DIR, "kmod.jsonl")

# BPF 程序
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/module.h> // 需要此头文件来解析 'struct module'

struct data_t {
    u32 pid;
    u64 ts_ns;
    char comm[TASK_COMM_LEN];
    char mod_name[MODULE_NAME_LEN];
};

BPF_PERF_OUTPUT(events);

// 挂载到 'do_init_module' 内核函数，它在 'init_module' 系统调用内部被调用
int trace_kmod_load(struct pt_regs *ctx, struct module *mod) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // 从 'struct module' 结构中读取模块名称
    bpf_probe_read_kernel_str(&data.mod_name, sizeof(data.mod_name), mod->name);

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
    print("[*] 正在加载 BPF 程序 (Kernel Module Monitor)...")
    b = BPF(text=BPF_PROGRAM)

    # 挂载 kprobe 到 do_init_module
    try:
        b.attach_kprobe(event="do_init_module", fn_name="trace_kmod_load")
        print("[+] kprobe do_init_module 挂载成功")
    except Exception as e:
        print(f"[!] kprobe do_init_module 挂载失败: {e}")
        print("[!] 提示: 确认内核符号 'do_init_module' 是否存在。")
        sys.exit(1)

    def handle_event(cpu, data, size):
        event = b["events"].event(data)
        record = {
            "source": "kmod",
            "pid": int(event.pid),
            "comm": event.comm.decode('utf-8', 'replace').strip("\x00"),
            "ts_ns": int(event.ts_ns),
            "event": "kmod_load",
            "module_name": event.mod_name.decode('utf-8', 'replace').strip("\x00"),
            "timestamp": monotonic_ns_to_utc_iso(int(event.ts_ns)),
        }

        # 控制台打印日志
        print(f"[KMOD] PID={record['pid']} comm={record['comm']} loaded_module={record['module_name']}")

        write_record(record)

    b["events"].open_perf_buffer(handle_event)
    print(f"[+] kmod_agent 已启动，日志保存至: {OUT_FILE}")
    print("[*] 按 Ctrl+C 或发送 SIGTERM 停止采集")

    # 安全退出信号处理
    def handle_sig(signum, frame):
        print("\n[!] kmod_agent 停止运行")
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
