#!/usr/bin/env python3
"""
file_agent.py (Stack-Safe Edition)
修复版：解决了 "BPF stack limit of 512 bytes is exceeded" 错误。
原理：使用 BPF_PERCPU_ARRAY 替代栈分配，支持大结构体传输。

功能保持不变：
1. Open/Delete/Rename: 全量记录。
2. Write: 1/50 采样记录。
3. 路径过滤: 忽略系统噪音。
"""

from bcc import BPF
import os
import json
from datetime import datetime, timezone

# --- 配置区域 ---
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

#define SAMPLE_RATE {WRITE_SAMPLE_RATE}

struct data_t {{
    u32 pid;
    u64 ts_ns;
    int event_type; // 1=open, 2=write, 3=unlink, 4=rename
    char fname[256];
    char new_fname[256];
    u64 write_bytes;
}};

// 【关键修复】使用 Per-CPU Array 存储大结构体，避免栈溢出
BPF_PERCPU_ARRAY(temp_buffer, struct data_t, 1);

BPF_PERF_OUTPUT(events);

// 辅助函数：获取 buffer 并清零
static __always_inline struct data_t* get_data_buffer() {{
    u32 zero = 0;
    struct data_t *data = temp_buffer.lookup(&zero);
    if (!data) return NULL;
    
    // 手动重置关键字段 (比 memset 更节省指令)
    data->pid = 0;
    data->ts_ns = 0;
    data->event_type = 0;
    data->write_bytes = 0;
    data->fname[0] = 0;
    data->new_fname[0] = 0;
    return data;
}}

// 1. 监控文件打开 (Open)
int trace_openat(struct tracepoint__syscalls__sys_enter_openat *args) {{
    struct data_t *data = get_data_buffer();
    if (!data) return 0;

    data->ts_ns = bpf_ktime_get_ns();
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->event_type = 1;
    
    bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->filename);
    
    if (data->fname[0] == 0) return 0;

    events.perf_submit((void *)args, data, sizeof(*data));
    return 0;
}}

// 2. 监控文件写入 (Write) - 采样
int trace_write(struct pt_regs *ctx, int fd, const char __user *buf, size_t count) {{
    if (bpf_get_prandom_u32() % SAMPLE_RATE != 0) {{
        return 0;
    }}

    struct data_t *data = get_data_buffer();
    if (!data) return 0;

    data->ts_ns = bpf_ktime_get_ns();
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->event_type = 2;
    data->write_bytes = count;
    // fname 留空
    
    events.perf_submit(ctx, data, sizeof(*data));
    return 0;
}}

// 3. 监控文件删除 (Unlink)
int trace_unlinkat(struct tracepoint__syscalls__sys_enter_unlinkat *args) {{
    struct data_t *data = get_data_buffer();
    if (!data) return 0;

    data->ts_ns = bpf_ktime_get_ns();
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->event_type = 3;
    
    bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->pathname);
    
    events.perf_submit((void *)args, data, sizeof(*data));
    return 0;
}}

// 4. 监控文件重命名 (Rename)
int trace_renameat(struct tracepoint__syscalls__sys_enter_renameat *args) {{
    struct data_t *data = get_data_buffer();
    if (!data) return 0;

    data->ts_ns = bpf_ktime_get_ns();
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->event_type = 4;
    
    bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (void *)args->oldname);
    bpf_probe_read_user_str(&data->new_fname, sizeof(data->new_fname), (void *)args->newname);
    
    events.perf_submit((void *)args, data, sizeof(*data));
    return 0;
}}
"""

def write_record(record: dict):
    try:
        with open(OUT_FILE, "a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass

def is_noise(path):
    if not path: return False
    if path.startswith("/proc") or path.startswith("/sys") or path.startswith("/dev") or path.startswith("/run"):
        return True
    if "/var/log/os_monitor_log" in path:
        return True
    return False

def main():
    print(f"[*] 正在加载 BPF 程序 (Stack-Safe, Sampling Rate: 1/{WRITE_SAMPLE_RATE})...")
    
    # 增加 allow_rlimit 以防止 map 创建失败
    b = BPF(text=BPF_PROGRAM)

    # --- 挂载 ---
    try:
        b.attach_tracepoint("syscalls:sys_enter_openat", "trace_openat")
        print("[+] tracepoint openat 挂载成功")
    except Exception as e:
        print(f"[!] openat 挂载失败: {e}")

    write_attached = False
    for sym in ["__x64_sys_write", "sys_write", "__sys_write"]:
        try:
            b.attach_kprobe(event=sym, fn_name="trace_write")
            write_attached = True
            print(f"[+] kprobe {sym} (Write) 挂载成功")
            break
        except Exception:
            continue
    if not write_attached:
        print("[!] 警告: 无法挂载 write")

    try:
        b.attach_tracepoint("syscalls:sys_enter_unlinkat", "trace_unlinkat")
        print("[+] tracepoint unlinkat 挂载成功")
    except:
        pass

    try:
        b.attach_tracepoint("syscalls:sys_enter_renameat", "trace_renameat")
        print("[+] tracepoint renameat 挂载成功")
    except:
        pass

    print(f"[+] file_agent 已启动，日志保存至: {OUT_FILE}")

    def handle_event(cpu, data, size):
        event = b["events"].event(data)
        
        record = {
            "pid": int(event.pid),
            "ts_ns": int(event.ts_ns),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        if event.event_type == 1:
            record["event"] = "open"
            record["fname"] = event.fname.decode("utf-8", "replace").strip("\x00")
            if is_noise(record["fname"]): return

        elif event.event_type == 2:
            record["event"] = "write"
            record["count"] = int(event.write_bytes)
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