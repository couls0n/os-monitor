#!/usr/bin/env python3
import os
import subprocess
import time
import datetime
import shutil

# 配置：样本存放目录
MALWARE_DIR = "/home/coulson/Desktop/os-monitor1/dataset/malware_samples"
# 确保这是测试机！
TARGET_DIR = "/home/coulson/Desktop/documents_to_encrypt" 

def setup_target_files():
    """重置被攻击的诱饵文件，确保每次运行环境一致"""
    if os.path.exists(TARGET_DIR):
        shutil.rmtree(TARGET_DIR)
    os.makedirs(TARGET_DIR)
    # 创建 1000 个模拟文档
    for i in range(1000):
        with open(os.path.join(TARGET_DIR, f"doc_{i}.docx"), "w") as f:
            f.write("Confidential Data " * 100)

def run_sample(sample_path):
    sample_name = os.path.basename(sample_path)
    print(f"[*] [REAL] Detonating {sample_name} at {datetime.datetime.now().isoformat()}")
    
    # 赋予执行权限
    os.chmod(sample_path, 0o777)
    
    try:
        # 运行样本，设置 60 秒超时
        # 你的 process_agent 会捕获这个执行
        subprocess.run([sample_path], timeout=60, cwd=TARGET_DIR)
    except subprocess.TimeoutExpired:
        print("[!] Sample execution timed out (Process likely running in background)")
    except Exception as e:
        print(f"[!] Error running sample: {e}")

def main():
    setup_target_files()
    samples = [f for f in os.listdir(MALWARE_DIR) if os.path.isfile(os.path.join(MALWARE_DIR, f))]
    
    for sample in samples:
        path = os.path.join(MALWARE_DIR, sample)
        run_sample(path)
        # 等待攻击完成
        time.sleep(10)
        # 清理环境（杀进程、重置文件）是复杂的，建议每次运行后 revert VM 快照
        print("[*] Please revert VM snapshot or manually clean up before next sample.")
        break # 建议一次跑一个，手动控制

if __name__ == "__main__":
    main()