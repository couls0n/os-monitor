#!/usr/bin/env python3
"""
simulate_benign_activity.py (Production Edition)
企业级良性行为模拟器：用于生成高拟真度的 EBPF 安全数据集背景流量。

改进点：
1. [Dev] 多语言开发栈 (C, Python, Shell)。
2. [File] 强制触发 openat/write/rename/unlink，确保 file_agent 不为空。
3. [Net] 50+ 真实网站类别，动态 URL 参数，随机 UA。
4. [Sys] 扩展至 20+ 种常见运维命令。
5. [Human] 引入"长/短休息"机制，模拟真实人类作息。
6. [Safety] 磁盘水位检测，权限自动修复，Git 配置隔离。
"""

import os
import sys
import time
import random
import subprocess
import shutil
import logging
import uuid
import stat
from datetime import datetime

# --- 配置区域 ---
WORK_DIR = os.path.expanduser("~/benign_simulation_workspace")
LOG_FILE = "benign_simulation.log"
MIN_DISK_FREE_GB = 2  # 磁盘剩余空间少于 2GB 时停止写入大文件

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
        # 任务列表与权重 (权重越高执行频率越高)
        self.tasks = [
            (self.task_dev_c_lang, 3),      # C 语言编译流
            (self.task_dev_python, 3),      # Python 开发流
            (self.task_office_editing, 4),  # 文档编辑 (高频 IO)
            (self.task_file_management, 2), # 归档/移动/清理
            (self.task_web_surfing_tech, 3),# 技术网站浏览
            (self.task_web_surfing_life, 3),# 生活娱乐浏览
            (self.task_sysadmin_ops, 2),    # 系统运维命令
            (self.task_short_break, 3),     # 短暂思考 (5-15s)
            (self.task_coffee_break, 1)     # 喝咖啡休息 (1-5min)
        ]
        
        # 模拟真实浏览器指纹
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
        ]

        # 丰富的 URL 库
        self.urls_tech = [
            "https://github.com", "https://stackoverflow.com", "https://www.python.org",
            "https://kubernetes.io", "https://www.docker.com", "https://aws.amazon.com",
            "https://developer.mozilla.org", "https://pypi.org", "https://go.dev"
        ]
        self.urls_life = [
            "https://www.google.com", "https://www.bing.com", "https://www.wikipedia.org",
            "https://www.nytimes.com", "https://www.bbc.com", "https://www.cnn.com",
            "https://www.amazon.com", "https://www.ebay.com", "https://www.reddit.com",
            "https://www.youtube.com", "https://www.netflix.com", "https://www.twitch.tv"
        ]

        # 扩展运维命令集
        self.sys_cmds = [
            "ps aux --sort=-%cpu | head -n 5", "ps -ef | grep python",
            "df -hT", "lsblk", "mount | head -n 5",
            "free -h", "vmstat 1 3", "uptime",
            "lscpu", "cat /proc/meminfo | head -n 5",
            "ss -tulpn", "ip addr show", "ip route", "netstat -rn",
            "journalctl -n 10", "dmesg | tail -n 5",
            "crontab -l", "systemctl status sshd",
            "whoami", "id", "groups", "last -n 5"
        ]

    def setup_env(self):
        """初始化环境，处理权限问题"""
        logger.info(f"Initializing workspace: {WORK_DIR}")
        if os.path.exists(WORK_DIR):
            self._force_remove(WORK_DIR)
        os.makedirs(WORK_DIR, exist_ok=True)

    def _force_remove(self, path):
        """强力删除，处理只读文件权限问题 (Git 常见问题)"""
        def on_rm_error(func, path, exc_info):
            # 如果删除失败，尝试添加写权限再删
            os.chmod(path, stat.S_IWRITE)
            try:
                func(path)
            except Exception:
                pass # 忽略最终失败，避免脚本崩溃

        shutil.rmtree(path, onerror=on_rm_error)

    def _check_disk_space(self):
        """检查磁盘空间，防止填满磁盘"""
        try:
            total, used, free = shutil.disk_usage(WORK_DIR)
            return (free // (2**30)) > MIN_DISK_FREE_GB
        except:
            return True

    def _run_cmd(self, cmd, cwd=None, timeout=60):
        """执行命令，捕获异常但不中断主流程"""
        try:
            # shell=True 产生 sh -> cmd 进程树，符合真实习惯
            # stdout/stderr 导向 DEVNULL 减少干扰，除非调试
            subprocess.run(
                cmd, 
                shell=True, 
                cwd=cwd or WORK_DIR, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                timeout=timeout
            )
            return True
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out: {cmd[:20]}...")
            return False
        except Exception as e:
            logger.error(f"Cmd failed: {cmd[:20]}... | {e}")
            return False

    # ==========================
    # 任务组 1: 多语言开发模拟
    # ==========================
    def task_dev_c_lang(self):
        """C 语言开发流：代码 -> Make -> 运行 -> Git"""
        proj_name = f"c_proj_{str(uuid.uuid4())[:6]}"
        proj_dir = os.path.join(WORK_DIR, "dev", proj_name)
        os.makedirs(proj_dir, exist_ok=True)
        
        logger.info(f"[Dev-C] Working on {proj_name}")
        
        # 1. Git Init
        self._run_cmd("git init", cwd=proj_dir)
        # 使用 --local 避免全局冲突
        self._run_cmd("git config --local user.email 'dev@sim.com'", cwd=proj_dir)
        self._run_cmd("git config --local user.name 'DevSim'", cwd=proj_dir)

        # 2. 编写代码 (Open+Write)
        code = """
        #include <stdio.h>
        #include <stdlib.h>
        #include <unistd.h>
        int main() {
            printf("Processing data...\\n");
            usleep(10000); 
            return 0;
        }
        """
        with open(os.path.join(proj_dir, "main.c"), "w") as f:
            f.write(code)

        # 3. 编译与运行
        self._run_cmd("gcc -O2 -o app main.c", cwd=proj_dir)
        if os.path.exists(os.path.join(proj_dir, "app")):
            self._run_cmd("./app", cwd=proj_dir)

        # 4. Git 提交
        self._run_cmd("git add .", cwd=proj_dir)
        self._run_cmd("git commit -m 'Update logic'", cwd=proj_dir)

    def task_dev_python(self):
        """Python 开发流：Venv -> Pip模拟 -> 脚本运行"""
        proj_name = f"py_script_{random.randint(100,999)}"
        proj_dir = os.path.join(WORK_DIR, "scripts")
        os.makedirs(proj_dir, exist_ok=True)

        logger.info(f"[Dev-Py] Running script {proj_name}")

        # 1. 编写 Python 脚本
        py_file = os.path.join(proj_dir, f"{proj_name}.py")
        content = f"""
import time
import os
def task():
    print("Simulating logic...")
    time.sleep(0.1)
    with open("{proj_name}.log", "w") as f:
        f.write(str(time.time()))

if __name__ == "__main__":
    task()
"""
        with open(py_file, "w") as f:
            f.write(content)

        # 2. 运行脚本 (触发 execve python)
        self._run_cmd(f"python3 {py_file}", cwd=proj_dir)

        # 3. 模拟 pip 安装 (不仅是联网，还有文件解压)
        # 这里只做 dry-run 或者模拟命令，防止真实安装污染环境
        self._run_cmd("python3 -m pip download requests -d /tmp/pip_cache --no-deps", cwd=proj_dir)

    # ==========================
    # 任务组 2: 办公与文件 IO (确保 File Agent 捕获)
    # ==========================
    def task_office_editing(self):
        """模拟文档编辑：打开 -> 多次写入 -> 保存 -> 重命名"""
        if not self._check_disk_space():
            logger.warning("Disk space low, skipping IO task")
            return

        doc_dir = os.path.join(WORK_DIR, "documents")
        os.makedirs(doc_dir, exist_ok=True)
        fname = f"report_{datetime.now().strftime('%M%S')}.txt"
        fpath = os.path.join(doc_dir, fname)

        logger.info(f"[Office] Editing {fname}")

        # 1. 创建并写入 (Open, Write)
        with open(fpath, "w") as f:
            f.write("Project Report 2025\n")
            f.write("="*20 + "\n")
        
        # 2. 模拟思考后追加写入 (Open, Write again)
        time.sleep(random.uniform(0.5, 2.0))
        with open(fpath, "a") as f:
            f.write(f"Timestamp: {time.time()}\n")
            f.write("Data: " + "X"*random.randint(100, 500) + "\n")

        # 3. 重命名 (Rename)
        final_name = fpath.replace(".txt", "_final.txt")
        try:
            os.rename(fpath, final_name)
        except OSError:
            pass
        
        # 4. 偶尔删除旧文件 (Unlink)
        if random.random() < 0.3:
            try:
                os.remove(final_name)
            except OSError:
                pass

    def task_file_management(self):
        """文件管理：查找、打包、清理"""
        target_dir = WORK_DIR
        # 1. 查找文件 (产生大量 open/getdents)
        # 限制深度防止资源耗尽
        self._run_cmd(f"find {target_dir} -maxdepth 4 -name '*.txt' | wc -l")
        self._run_cmd(f"grep -r 'Project' {target_dir} 2>/dev/null | head -n 5")

        # 2. 归档 (产生大量读操作)
        if self._check_disk_space():
            backup_name = os.path.join(WORK_DIR, "backup.tar.gz")
            # 排除自身防止死循环
            self._run_cmd(f"tar -czf {backup_name} --exclude=backup.tar.gz .", cwd=WORK_DIR)
            if os.path.exists(backup_name):
                os.remove(backup_name) # 立即清理

    # ==========================
    # 任务组 3: 真实网络浏览
    # ==========================
    def _browse(self, url_list, tag):
        url = random.choice(url_list)
        ua = random.choice(self.user_agents)
        # 添加随机参数防止缓存，模拟动态访问
        noisy_url = f"{url}/?ts={int(time.time())}&ref={str(uuid.uuid4())[:8]}"
        
        logger.info(f"[Web-{tag}] Visiting {url}")
        
        # 1. Curl 模拟页面访问
        # -L 跟随重定向, --max-time 设置超时
        self._run_cmd(f"curl -L -A '{ua}' --max-time 10 -s -o /dev/null '{noisy_url}'")
        
        # 2. 模拟资源加载 (偶尔执行 Wget)
        if random.random() < 0.3:
             self._run_cmd(f"wget -U '{ua}' --timeout=10 -q -O /dev/null '{url}'")

    def task_web_surfing_tech(self):
        self._browse(self.urls_tech, "Tech")

    def task_web_surfing_life(self):
        self._browse(self.urls_life, "Life")

    # ==========================
    # 任务组 4: 运维与系统噪音
    # ==========================
    def task_sysadmin_ops(self):
        """执行随机系统检查命令"""
        cmd = random.choice(self.sys_cmds)
        logger.info(f"[Sys] Exec: {cmd.split()[0]}")
        self._run_cmd(cmd)

    # ==========================
    # 任务组 5: 人类行为模拟
    # ==========================
    def task_short_break(self):
        """短暂停顿：模拟思考、切换窗口"""
        sleep_t = random.uniform(5, 15)
        logger.info(f"[Human] Thinking... ({sleep_t:.1f}s)")
        time.sleep(sleep_t)

    def task_coffee_break(self):
        """长休息：模拟喝咖啡、上厕所、开会"""
        sleep_t = random.uniform(60, 300) # 1-5 分钟
        logger.info(f"[Human] Coffee Break ☕ ... ({sleep_t/60:.1f} min)")
        time.sleep(sleep_t)

    # ==========================
    # 主程序
    # ==========================
    def run(self):
        self.setup_env()
        logger.info("=== Benign Simulation Started (Press Ctrl+C to stop) ===")
        logger.info(f"Root privileges: {'Yes' if os.geteuid()==0 else 'No'}")
        
        # 展开加权任务列表
        task_pool = []
        for func, weight in self.tasks:
            task_pool.extend([func] * weight)
            
        try:
            while self.running:
                # 随机选择任务
                task = random.choice(task_pool)
                
                # 执行任务 (自带异常捕获)
                try:
                    task()
                except Exception as e:
                    logger.error(f"Task Crashed: {e}")
                
                # 任务间歇 (模拟手速)
                time.sleep(random.uniform(1.0, 4.0))
                
        except KeyboardInterrupt:
            logger.info("\nStopped by user.")
        finally:
            logger.info("Cleaning up workspace...")
            self._force_remove(WORK_DIR)
            logger.info("Done.")

if __name__ == "__main__":
    # 简单的运行前检查
    if not shutil.which("git"):
        print("Warning: 'git' not found. Dev tasks may fail.")
    if not shutil.which("curl"):
        print("Warning: 'curl' not found. Web tasks may fail.")
        
    sim = BenignSimulator()
    sim.run()