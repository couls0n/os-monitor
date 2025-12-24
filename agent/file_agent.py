#!/usr/bin/env python3
"""
file_agent.py (Sampling Edition)
均衡版：监控文件系统活动，通过对 write 事件进行降频采样来平衡性能与检测能力。

特性：
1. Open/Delete/Rename: 全量记录 (高价值，低频)。
2. Write: 随机采样记录 (低价值，极高频)。默认采样率 1/50。
3. 路径过滤: 忽略系统噪音。
"""

from bcc import BPF
import os
import json
from datetime import datetime, timezone

# --- 配置区域 ---
# 采样率：每多少次 write 操作记录一次？
# 100GB / 50 = 2GB，这是一个比较合理的日志大小。
WRITE_SAMPLE_RATE = 50 

# 输出目录
OUT_DIR = "/var/log/os_monitor_log"
os.makedirs(OUT_DIR, exist_ok=True)
OUT_FILE = os.path.join(OUT_DIR, "fileio.jsonl")

# BPF 程序
BPF_PROGRAM = f"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/limits.h>

// 定义采样率宏
#define SAMPLE_RATE {WRITE_SAMPLE_RATE}

struct data_t {{
    u32 pid;
    u64 ts_ns;
    int event_type; // 1=open, 2=write, 3=unlink, 4=rename
    char fname[256];
    char new_fname[256]; // 用于 rename
    u64 write_bytes;     // 记录写入字节数
}};

BPF_PERF_OUTPUT(events);

// 1. 监控文件打开 (Open) - 全量记录
int trace_openat(struct tracepoint__syscalls__sys_enter_openat *args) {{
    struct data_t data = {{}};
    data.ts_ns = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.event_type = 1;
    
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->filename);
    
    // 简单的内核过滤：忽略空名
    if (data.fname[0] == 0) return 0;

    events.perf_submit((void *)args, &data, sizeof(data));
    return 0;
}}

// 2. 监控文件写入 (Write) - 采样记录 !!!
int trace_write(struct pt_regs *ctx, int fd, const char __user *buf, size_t count) {{
    // [关键] 随机采样逻辑
    // bpf_get_prandom_u32() 返回一个伪随机数
    if (bpf_get_prandom_u32() % SAMPLE_RATE != 0) {{
        return 0; // 丢弃大部分事件
    }}

    struct data_t data = {{}};
    data.ts_ns = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.event_type = 2;
    data.write_bytes = count;
    
    // 注意：在 sys_write 中获取文件名非常复杂（需要从 fd 反查 file 结构体），
    // 为了保持性能和稳定性，这里通常不记录文件名，或者需要极其复杂的逻辑。
    // 在溯源图中，我们通常依靠 pid + 时间戳 将 write 事件关联到最近一次该 pid 的 open 事件上。
    // 因此这里 fname留空或只填个占位符是可接受的。
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}}

// 3. 监控文件删除 (Unlink) - 全量记录
int trace_unlinkat(struct tracepoint__syscalls__sys_enter_unlinkat *args) {{
    struct data_t data = {{}};
    data.ts_ns = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.event_type = 3;
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->pathname);
    events.perf_submit((void *)args, &data, sizeof(data));
    return 0;
}}

// 4. 监控文件重命名 (Rename) - 全量记录
int trace_renameat(struct tracepoint__syscalls__sys_enter_renameat *args) {{
    struct data_t data = {{}};
    data.ts_ns = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.event_type = 4;
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->oldname);
    bpf_probe_read_user_str(&data.new_fname, sizeof(data.new_fname), (void *)args->newname);
    events.perf_submit((void *)args, &data, sizeof(data));
    return 0;
}}
"""

def write_record(record: dict):
    """写入单条 JSON 记录"""
    try:
        with open(OUT_FILE, "a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass

def is_noise(path):
    """Python 端路径过滤"""
    if not path:
        return False # Write 事件可能没有路径，不能过滤掉
    if path.startswith("/proc") or path.startswith("/sys") or path.startswith("/dev"):
        return True
    if "/var/log/os_monitor_log" in path:
        return True
    return False

def main():
    print(f"[*] 正在加载 BPF 程序 (Write Sampling Rate: 1/{WRITE_SAMPLE_RATE})...")
    b = BPF(text=BPF_PROGRAM)

    # --- 挂载点 ---
    
    # Open
    try:
        b.attach_tracepoint("syscalls:sys_enter_openat", "trace_openat")
        print("[+] tracepoint openat 挂载成功")
    except Exception as e:
        print(f"[!] openat 挂载失败: {e}")

    # Write (Kprobe)
    # 尝试多种 write 系统调用名以适配不同内核
    write_attached = False
    for sym in ["__x64_sys_write", "sys_write", "__sys_write"]:
        try:
            b.attach_kprobe(event=sym, fn_name="trace_write")
            write_attached = True
            print(f"[+] kprobe {sym} (Write) 挂载成功 [采样模式]")
            break
        except Exception:
            continue
    if not write_attached:
        print("[!] 警告: 无法挂载 write 系统调用，将丢失写入数据")

    # Unlink
    try:
        b.attach_tracepoint("syscalls:sys_enter_unlinkat", "trace_unlinkat")
        print("[+] tracepoint unlinkat 挂载成功")
    except:
        pass

    # Rename
    try:
        b.attach_tracepoint("syscalls:sys_enter_renameat", "trace_renameat")
        print("[+] tracepoint renameat 挂载成功")
    except:
        pass

    print(f"[+] file_agent 已启动，日志保存至: {OUT_FILE}")

    def handle_event(cpu, data, size):
        event = b["events"].event(data)
        
        # 基础数据
        record = {
            "pid": int(event.pid),
            "ts_ns": int(event.ts_ns),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # 解析事件类型
        if event.event_type == 1:
            record["event"] = "open"
            record["fname"] = event.fname.decode("utf-8", "replace").strip("\x00")
            if is_noise(record["fname"]): return

        elif event.event_type == 2:
            record["event"] = "write"
            record["count"] = int(event.write_bytes)
            # Write 事件通常无法在 syscall 层简单获取文件名，
            # 这里留空，分析时依靠 (pid, time) 关联到最近的 open
            record["fname"] = "" 
            
        elif event.event_type == 3:
            record["event"] = "delete"
            record["fname"] = event.fname.decode("utf-8", "replace").strip("\x00")
            if is_noise(record["fname"]): return
            
        elif event.event_type == 4:
            record["event"] = "rename"
            record["fname"] = event.fname.decode("utf-8", "replace").strip("\x00")
            record["new_fname"] = event.new_fname.decode("utf-8", "replace").strip("\x00")
            if is_noise(record["fname"]): return

        # 仅打印非 write 的日志，防止控制台刷屏
        if record["event"] != "write":
            print(f"[FILE] {record['event'].upper()} PID={record['pid']} {record.get('fname', '')}")
            
        write_record(record)

    b["events"].open_perf_buffer(handle_event)
    
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n[!] file_agent 停止运行")

if __name__ == "__main__":
    main()