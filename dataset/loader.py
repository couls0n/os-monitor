#!/usr/bin/env python3
"""
loader.py (Argument Support Edition)
修复：部分勒索软件样本需要指定加密目录作为参数才能运行。
此版本会自动将 TARGET_DIR 作为参数传递给样本。
"""
import os
import subprocess
import time
import datetime
import shutil
import stat

# --- 配置区域 ---
# 存放病毒样本的目录
MALWARE_DIR = "/home/victim01/Desktop/os-monitor/dataset/malware_samples"
# 存放诱饵文件的目录
TARGET_DIR = "/home/victim01/Desktop/documents_to_encrypt" 

def setup_target_files():
    """重置被攻击的诱饵文件，确保每次运行环境一致"""
    print(f"[*] Resetting target directory: {TARGET_DIR}")
    if os.path.exists(TARGET_DIR):
        # 处理权限问题，防止上次加密后无法删除
        def on_rm_error(func, path, exc_info):
            os.chmod(path, stat.S_IWRITE)
            func(path)
        shutil.rmtree(TARGET_DIR, onerror=on_rm_error)
        
    os.makedirs(TARGET_DIR, exist_ok=True)
    # 创建 100 个模拟文档 (数量适中即可，太多会跑太久)
    for i in range(100):
        with open(os.path.join(TARGET_DIR, f"doc_{i}.docx"), "w") as f:
            f.write("Confidential Data " * 100)

def run_sample(sample_path):
    sample_name = os.path.basename(sample_path)
    print(f"[*] [REAL] Detonating {sample_name} at {datetime.datetime.now().isoformat()}")
    
    # 1. 赋予执行权限
    os.chmod(sample_path, 0o777)
    
    # 2. 构造命令
    # 许多 Linux 勒索软件用法: ./ransomware <target_dir>
    # 我们尝试两种方式：带参数和不带参数
    
    cmd_with_arg = [sample_path, TARGET_DIR]
    
    try:
        print(f"    -> Executing: {' '.join(cmd_with_arg)}")
        # 运行样本，设置 60 秒超时
        # cwd 设置为 TARGET_DIR，有些样本会加密当前目录
        subprocess.run(cmd_with_arg, timeout=60, cwd=TARGET_DIR)
        
    except subprocess.TimeoutExpired:
        print("[!] Sample execution timed out (Likely running & encrypting...)")
    except Exception as e:
        print(f"[!] Error running sample: {e}")

def main():
    # 1. 检查样本目录
    if not os.path.exists(MALWARE_DIR):
        print(f"[!] Error: Malware directory not found: {MALWARE_DIR}")
        return

    samples = [f for f in os.listdir(MALWARE_DIR) if os.path.isfile(os.path.join(MALWARE_DIR, f))]
    if not samples:
        print("[!] No samples found.")
        return

    # 2. 准备诱饵
    setup_target_files()
    
    # 3. 运行样本 (建议每次只跑一个，避免混合)
    # 取第一个样本运行
    sample_to_run = samples[0]
    path = os.path.join(MALWARE_DIR, sample_to_run)
    
    run_sample(path)
    
    # 4. 留出时间给勒索软件加密
    print("[*] Waiting 30s for encryption activity...")
    time.sleep(30)
    
    print("-" * 40)
    print("[*] Detonation finished.")
    print("[*] 1. Stop monitoring (sudo bash stop_monitoring.sh)")
    print("[*] 2. Collect logs (python3 fast_collector.py)")
    print("[*] 3. REVERT VM SNAPSHOT immediately!")

if __name__ == "__main__":
    main()