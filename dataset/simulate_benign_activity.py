#!/usr/bin/env python3
"""
simulate_benign_activity.py (Enhanced Edition)
高级良性行为模拟器：用于生成高质量的 EBPF 训练数据集背景流量。

功能增强：
1. 完整的软件构建生命周期 (Write -> Compile -> Run -> Git Commit)。
2. 真实的用户态工具调用 (gcc, make, git, wget, curl, zip, ps, grep)。
3. 高强度的文件系统压力测试 (Deep tree creation, Bulk I/O)。
4. 随机化的行为调度与休眠，模拟真实人类操作。
"""

import os
import sys
import time
import random
import subprocess
import shutil
import logging
import string
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# --- 配置区域 ---
WORK_DIR = os.path.expanduser("~/benign_simulation_workspace")
LOG_FILE = "benign_simulation.log"

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("BenignSim")

class BenignSimulator:
    def __init__(self):
        self.running = True
        self.tasks = [
            (self.task_developer_daily, 3), # (任务函数, 权重)
            (self.task_office_heavy, 2),
            (self.task_web_browsing, 3),
            (self.task_sysadmin_noise, 1),
            (self.task_idle, 1)
        ]
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/91.0.4472.114",
            "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
        ]

    def setup_env(self):
        """初始化工作环境"""
        if os.path.exists(WORK_DIR):
            try:
                shutil.rmtree(WORK_DIR)
            except Exception as e:
                logger.warning(f"Cleanup failed: {e}")
        os.makedirs(WORK_DIR, exist_ok=True)
        logger.info(f"Environment initialized at {WORK_DIR}")

    def _run_cmd(self, cmd, cwd=None, ignore_errors=True):
        """执行 Shell 命令的辅助函数"""
        try:
            # 模拟真实的 Shell 执行，产生 execve 事件
            subprocess.run(
                cmd, 
                shell=True, 
                cwd=cwd or WORK_DIR, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                timeout=30
            )
        except Exception as e:
            if not ignore_errors:
                logger.error(f"Command failed: {cmd} | {e}")

    def _create_random_file(self, path, size_kb=10):
        """创建指定大小的随机内容文件"""
        try:
            with open(path, 'wb') as f:
                f.write(os.urandom(size_kb * 1024))
        except Exception:
            pass

    # ==========================
    # 任务模块 1: 真实开发模拟
    # ==========================
    def task_developer_daily(self):
        """模拟：Git 初始化 -> 编写 C 代码 -> Makefile -> 编译 -> 运行"""
        project_name = f"project_{random.randint(1000, 9999)}"
        proj_dir = os.path.join(WORK_DIR, "dev_projects", project_name)
        os.makedirs(proj_dir, exist_ok=True)
        
        logger.info(f"[Dev] Starting new project: {project_name}")

        # 1. Git Init
        self._run_cmd("git init", cwd=proj_dir)
        
        # 2. Write C Code
        c_code = """
        #include <stdio.h>
        #include <stdlib.h>
        #include <unistd.h>
        int main() {
            printf("Hello from Benign Simulation!\\n");
            int i;
            for(i=0; i<10000; i++) { rand(); } 
            return 0;
        }
        """
        code_path = os.path.join(proj_dir, "main.c")
        with open(code_path, "w") as f:
            f.write(c_code)

        # 3. Create Makefile
        makefile = f"""
        all:
        \tgcc -o app main.c
        clean:
        \trm -f app
        """
        with open(os.path.join(proj_dir, "Makefile"), "w") as f:
            f.write(makefile)

        # 4. Compile & Run
        self._run_cmd("make", cwd=proj_dir)
        if os.path.exists(os.path.join(proj_dir, "app")):
            self._run_cmd("./app", cwd=proj_dir)
        
        # 5. Git Commit
        self._run_cmd("git add .", cwd=proj_dir)
        self._run_cmd("git config user.email 'sim@bot.com'", cwd=proj_dir)
        self._run_cmd("git config user.name 'SimBot'", cwd=proj_dir)
        self._run_cmd("git commit -m 'Initial commit'", cwd=proj_dir)

        # 6. Cleanup (occasional)
        if random.random() < 0.5:
            self._run_cmd("make clean", cwd=proj_dir)
        
        logger.info(f"[Dev] Project {project_name} workflow complete.")

    # ==========================
    # 任务模块 2: 重度办公/文件 I/O
    # ==========================
    def task_office_heavy(self):
        """模拟：深层目录创建、大文件复制、压缩解压、查找"""
        logger.info("[Office] Starting heavy file operations...")
        
        # 1. Deep Tree Creation
        base_dir = os.path.join(WORK_DIR, "documents", datetime.now().strftime("%H%M%S"))
        os.makedirs(base_dir, exist_ok=True)
        
        # Create 100 random text files
        for i in range(20):
            fname = os.path.join(base_dir, f"doc_{i}.txt")
            with open(fname, "w") as f:
                f.write("Confidential " * 1000)
        
        # 2. Compress (Trigger heavy read/cpu)
        archive_name = f"{base_dir}.tar.gz"
        self._run_cmd(f"tar -czf {archive_name} -C {base_dir} .")
        
        # 3. Copy & Move
        backup_dir = os.path.join(WORK_DIR, "backups")
        os.makedirs(backup_dir, exist_ok=True)
        if os.path.exists(archive_name):
            self._run_cmd(f"cp {archive_name} {backup_dir}/")
            self._run_cmd(f"mv {archive_name} {base_dir}/archive_internal.tar.gz")

        # 4. Search (Trigger 'find' and 'grep' noise)
        self._run_cmd(f"grep -r 'Confidential' {WORK_DIR} | head -n 5")
        self._run_cmd(f"find {WORK_DIR} -name '*.txt' | wc -l")

    # ==========================
    # 任务模块 3: 拟真网络浏览
    # ==========================
    def task_web_browsing(self):
        """模拟：Wget 下载、Curl 访问、DNS 查询"""
        targets = [
            "https://www.google.com", "https://github.com", 
            "https://stackoverflow.com", "https://www.python.org",
            "https://pypi.org", "https://kernel.org"
        ]
        target = random.choice(targets)
        ua = random.choice(self.user_agents)
        
        logger.info(f"[Web] Browsing to {target}")
        
        # 1. Simple Curl
        self._run_cmd(f"curl -A '{ua}' -s -o /dev/null {target}")
        
        # 2. Wget page resource (simulating download)
        # 使用 -O /dev/null 防止写磁盘，仅产生网络流量和 exec 事件
        self._run_cmd(f"wget --user-agent='{ua}' -q -O /dev/null {target}")
        
        # 3. DNS Lookup (Trigger dns_agent)
        domain = target.replace("https://", "").split("/")[0]
        try:
            # Python 级别的 DNS 查询
            import socket
            socket.gethostbyname(domain)
        except:
            pass

    # ==========================
    # 任务模块 4: 系统管理噪音
    # ==========================
    def task_sysadmin_noise(self):
        """模拟：系统状态检查、进程查看"""
        cmds = [
            "ps aux --sort=-%mem | head -n 5",
            "df -h",
            "free -m",
            "uname -a",
            "uptime",
            "lsof | head -n 10",
            "cat /proc/cpuinfo | grep 'model name' | head -n 1"
        ]
        cmd = random.choice(cmds)
        logger.info(f"[Sys] Running monitor command: {cmd.split()[0]}")
        self._run_cmd(cmd)

    # ==========================
    # 任务模块 5: 随机空闲
    # ==========================
    def task_idle(self):
        """模拟用户思考/离开"""
        sleep_time = random.randint(2, 10)
        logger.info(f"[Idle] User is away for {sleep_time}s...")
        time.sleep(sleep_time)

    # ==========================
    # 主循环
    # ==========================
    def run(self):
        self.setup_env()
        logger.info("Simulation started. Press Ctrl+C to stop.")
        
        # 权重列表展开
        weighted_tasks = []
        for task, weight in self.tasks:
            weighted_tasks.extend([task] * weight)
            
        try:
            while self.running:
                # 随机选择任务
                task = random.choice(weighted_tasks)
                
                # 执行任务
                try:
                    task()
                except Exception as e:
                    logger.error(f"Task execution error: {e}")
                
                # 任务间歇
                time.sleep(random.uniform(0.5, 3.0))
                
        except KeyboardInterrupt:
            logger.info("Simulation stopped by user.")
        finally:
            logger.info("Cleaning up...")
            # 可以在这里添加清理逻辑，或者保留文件供后续观察
            # shutil.rmtree(WORK_DIR)

if __name__ == "__main__":
    sim = BenignSimulator()
    sim.run()