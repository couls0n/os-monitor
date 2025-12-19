#!/usr/bin/env python3
import time
import random
import os
import subprocess
import shutil
import sys
from datetime import datetime

# 模拟的工作目录
WORK_DIR = "/tmp/benign_simulation_workplace"

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [BENIGN-SIM] {msg}")

def setup_env():
    if os.path.exists(WORK_DIR):
        shutil.rmtree(WORK_DIR)
    os.makedirs(WORK_DIR, exist_ok=True)

# 1. 模拟网络浏览 (Web Browsing / Streaming Mock)
def activity_network():
    domains = ["www.google.com", "www.github.com", "www.stackoverflow.com", "www.python.org"]
    target = random.choice(domains)
    log(f"Simulating web browsing to {target}...")
    try:
        # -I 仅获取头部，减少流量，但足以触发 DNS 和 Net Agent
        subprocess.run(["curl", "-I", f"https://{target}"], 
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    except Exception:
        pass

# 2. 模拟开发行为 (Developer: Find, Tar, Grep)
def activity_developer():
    log("Simulating developer tasks (find, grep, tar)...")
    try:
        # 模拟查找文件
        subprocess.run(["find", "/usr/include", "-name", "*.h", "-maxdepth", "2"], 
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # 模拟压缩备份
        dummy_file = os.path.join(WORK_DIR, "project_src.dat")
        with open(dummy_file, "w") as f:
            f.write("int main() { return 0; }" * 1000)
        
        subprocess.run(["tar", "-czf", os.path.join(WORK_DIR, "backup.tar.gz"), dummy_file],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

# 3. 模拟办公文件操作 (Office: Read/Write)
def activity_office():
    log("Simulating office file operations...")
    fname = os.path.join(WORK_DIR, f"report_{random.randint(1, 100)}.txt")
    try:
        # 写入
        with open(fname, "w") as f:
            f.write("Quarterly Report Data " * 500)
        # 读取
        with open(fname, "r") as f:
            _ = f.read()
        # 删除 (偶尔)
        if random.random() < 0.3:
            os.remove(fname)
    except Exception:
        pass

# 4. 模拟系统空闲 (Idle)
def activity_idle():
    duration = random.randint(5, 60)
    log(f"User is idle/away for {duration} seconds...")
    time.sleep(duration)

def main():
    setup_env()
    print("=== Starting Long-Term Benign Activity Simulation ===")
    print(f"Working Directory: {WORK_DIR}")
    print("Press Ctrl+C to stop manually.")
    
    try:
        while True:
            # 随机选择一种行为模式
            action = random.choice([
                activity_network, 
                activity_network, # 增加网络活动权重
                activity_developer, 
                activity_office, 
                activity_office,
                activity_idle
            ])
            action()
            
            # 动作间隔，防止日志量爆炸
            time.sleep(random.uniform(1, 5))
            
    except KeyboardInterrupt:
        print("\nSimulation stopped.")
        shutil.rmtree(WORK_DIR)

if __name__ == "__main__":
    main()