#!/usr/bin/env python3
"""
file_agent.py (Optimized)
合理版：监控关键文件系统活动 (Open, Delete, Rename)。
优化策略：
1. 移除/禁用高频的 'write' 监控，解决日志体积过大问题。
2. 新增 'unlink' (删除) 和 'rename' (重命名) 监控，这对检测勒索软件至关重要。
3. 增加路径白名单/黑名单过滤，减少系统噪音。
"""

from bcc import BPF
import os
import json
import ctypes
from datetime import datetime, timezone

# 输出目录配置
OUT_DIR = "/var/log/os_monitor_log"
os.makedirs(OUT_DIR, exist_ok=True)
OUT_FILE = os.path.join(OUT_DIR, "fileio.jsonl")

# BPF 程序
# 注意：write 相关的代码已被注释，以节省空间
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/limits.h>

struct data_t {
    u32 pid;
    u64 ts_ns;
    int event_type; // 1=open, 2=write(disabled), 3=unlink, 4=rename
    char fname[256];
    char new_fname[256]; // 用于 rename 的新文件名
};

BPF_PERF_OUTPUT(events);

// 1. 监控文件打开 (Open)
int trace_openat(struct tracepoint__syscalls__sys_enter_openat *args) {
    struct data_t data = {};
    data.ts_ns = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.event_type = 1;
    
    // 读取文件名
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->filename);
    
    // 简单的内核态过滤：忽略过短的文件名（可选）
    if (data.fname[0] == 0) return 0;

    events.perf_submit((void *)args, &data, sizeof(data));
    return 0;
}

// 2. 监控文件删除 (Unlink) - 勒索软件特征
int trace_unlinkat(struct tracepoint__syscalls__sys_enter_unlinkat *args) {
    struct data_t data = {};
    data.ts_ns = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.event_type = 3;
    
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->pathname);
    
    events.perf_submit((void *)args, &data, sizeof(data));
    return 0;
}

// 3. 监控文件重命名 (Rename) - 勒索软件特征
int trace_renameat(struct tracepoint__syscalls__sys_enter_renameat *args) {
    struct data_t data = {};
    data.ts_ns = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.event_type = 4;
    
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->oldname);
    bpf_probe_read_user_str(&data.new_fname, sizeof(data.new_fname), (void *)args->newname);
    
    events.perf_submit((void *)args, &data, sizeof(data));
    return 0;
}

/* // [已禁用] 监控写入 (Write)
// 警告：开启此项会导致日志体积每天增加 50GB+，仅在调试时开启。
int trace_write(struct pt_regs *ctx, int fd, const char __user *buf, size_t count) {
    // ... 代码省略 ...
    return 0;
}
*/
"""

def write_record(record: dict):
    """写入单条 JSON 记录"""
    try:
        with open(OUT_FILE, "a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:
        # 避免 stderr 刷屏
        pass

def is_noise(path):
    """Python 端过滤：忽略常见的系统噪音路径"""
    if not path:
        return True
    # 忽略虚拟文件系统
    if path.startswith("/proc") or path.startswith("/sys") or path.startswith("/dev"):
        return True
    # 忽略常见的库文件读取 (可选，视需求而定)
    if path.startswith("/usr/lib") or path.startswith("/lib"):
        return True
    # 忽略自身日志
    if "/var/log/os_monitor_log" in path:
        return True
    return False

def main():
    print("[*] 正在加载 BPF 程序 (Optimized File Monitor)...")
    b = BPF(text=BPF_PROGRAM)

    # --- 挂载 Tracepoints ---
    
    # 1. Openat
    try:
        b.attach_tracepoint("syscalls:sys_enter_openat", "trace_openat")
        print("[+] tracepoint sys_enter_openat 挂载成功")
    except Exception as e:
        print(f"[!] sys_enter_openat 挂载失败: {e}")

    # 2. Unlinkat (Delete)
    try:
        b.attach_tracepoint("syscalls:sys_enter_unlinkat", "trace_unlinkat")
        print("[+] tracepoint sys_enter_unlinkat 挂载成功 (用于检测删除/勒索)")
    except Exception as e:
        print(f"[!] sys_enter_unlinkat 挂载失败: {e} (尝试 sys_enter_unlink)")
        try:
            b.attach_tracepoint("syscalls:sys_enter_unlink", "trace_unlinkat")
            print("[+] tracepoint sys_enter_unlink 挂载成功")
        except:
            pass

    # 3. Renameat (Rename)
    try:
        b.attach_tracepoint("syscalls:sys_enter_renameat", "trace_renameat")
        print("[+] tracepoint sys_enter_renameat 挂载成功 (用于检测移动/重命名)")
    except Exception as e:
        # 尝试适配旧内核
        try:
            b.attach_tracepoint("syscalls:sys_enter_rename", "trace_renameat")
            print("[+] tracepoint sys_enter_rename 挂载成功")
        except:
            pass

    print(f"[+] file_agent 已启动，日志保存至: {OUT_FILE}")
    print("[*] 注意: 已禁用 Write 监控以优化性能")

    def handle_event(cpu, data, size):
        event = b["events"].event(data)
        
        # 获取文件名
        fname = event.fname.decode("utf-8", "replace").strip("\x00")
        
        # --- 过滤噪音 ---
        if is_noise(fname):
            return
        # ----------------
        
        event_type_map = {1: "open", 2: "write", 3: "delete", 4: "rename"}
        etype_str = event_type_map.get(event.event_type, "unknown")

        record = {
            "pid": int(event.pid),
            "ts_ns": int(event.ts_ns),
            "event": etype_str,
            "fname": fname,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # 如果是重命名，添加新文件名
        if event.event_type == 4:
            record["new_fname"] = event.new_fname.decode("utf-8", "replace").strip("\x00")

        # 控制台简略输出
        if event.event_type == 3: # Delete
            print(f"[FILE] PID={record['pid']} DELETE -> {fname}")
        elif event.event_type == 4: # Rename
            print(f"[FILE] PID={record['pid']} RENAME -> {fname} TO {record['new_fname']}")
        elif event.event_type == 1: # Open (只打印非 .so 结尾的，防止刷屏)
            if not fname.endswith(".so") and not fname.endswith(".cache"):
                print(f"[FILE] PID={record['pid']} OPEN -> {fname}")

        write_record(record)

    b["events"].open_perf_buffer(handle_event)
    
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n[!] file_agent 停止运行")

if __name__ == "__main__":
    main()