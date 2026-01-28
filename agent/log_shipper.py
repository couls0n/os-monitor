#!/usr/bin/env python3
"""
log_shipper.py
运行在【虚拟机】中。
功能：实时读取(Tail)所有7个日志文件，通过网络发送到物理机。
优势：无需修改任何 Agent 代码，非侵入式，抗加密。
"""
import time
import socket
import os
import glob
import threading

# --- 配置区域 ---
# 【重要】请修改为您物理机的 IP 地址
REMOTE_IP = "192.168.174.1"  
REMOTE_PORT = 9999
LOG_DIR = "/var/log/os_monitor_log"
# ----------------

def follow(file_obj):
    """生成器：类似 tail -f 的功能"""
    file_obj.seek(0, os.SEEK_END)
    while True:
        line = file_obj.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def ship_file(filename):
    """单个文件的搬运线程"""
    # 等待文件创建
    while not os.path.exists(filename):
        time.sleep(1)
    
    print(f"[*] Started shipping: {os.path.basename(filename)}")
    
    try:
        # 建立到物理机的连接 (每个文件一个连接，或共用一个)
        # 为了简单稳定，这里采用短连接或长连接池比较复杂，
        # 我们简单地尝试每个文件流复用一个长连接
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((REMOTE_IP, REMOTE_PORT))
        
        with open(filename, "r") as f:
            for line in follow(f):
                try:
                    # 发送数据
                    s.sendall(line.encode('utf-8'))
                except BrokenPipeError:
                    print(f"[!] Connection broken for {filename}, reconnecting...")
                    s.close()
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((REMOTE_IP, REMOTE_PORT))
                    s.sendall(line.encode('utf-8'))
    except Exception as e:
        print(f"[!] Error shipping {filename}: {e}")

def main():
    print(f"[*] Log Shipper starting... Target: {REMOTE_IP}:{REMOTE_PORT}")
    
    # 定义要监控的7个文件
    log_files = [
        "process.jsonl", "fileio.jsonl", "net.jsonl", "dns.jsonl",
        "kmod.jsonl", "memory.jsonl", "syscall.jsonl"
    ]
    
    threads = []
    for log_name in log_files:
        full_path = os.path.join(LOG_DIR, log_name)
        t = threading.Thread(target=ship_file, args=(full_path,))
        t.daemon = True
        t.start()
        threads.append(t)
        
    print(f"[*] Monitoring {len(threads)} log files. Press Ctrl+C to stop.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shipper stopped.")

if __name__ == "__main__":
    main()