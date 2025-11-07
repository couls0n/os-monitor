#!/usr/bin/env python3
"""
dashboard_server.py
一个基于 Flask + SocketIO + Watchdog 的实时监控仪表盘后端。

功能:
1. 启动一个 Web 服务器。
2. 启动一个 'watchdog' 观察者，监控 '/var/log/os_monitor_log/' 目录。
3. 当该目录下的 *.jsonl 文件被修改时，它会读取新写入的行。
4. 解析 JSON 数据，并通过 WebSocket 将数据实时发送到前端 Web 页面。
"""
import os
import time
import json
import threading
from flask import Flask, render_template
from flask_socketio import SocketIO
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- 配置 ---
LOG_DIR = "/var/log/os_monitor_log"
# 确保目录存在 - 备注：此目录应由 agent (sudo) 创建
os.makedirs(LOG_DIR, exist_ok=True)

AGENT_FILES = {
    "process.jsonl": "process_event",
    "fileio.jsonl": "file_event",
    "net.jsonl": "net_event",
    "dns.jsonl": "dns_event",
    "kmod.jsonl": "kmod_event",
    "memory.jsonl": "memory_event",
    "syscall.jsonl": "syscall_event"
}

# --- Flask & SocketIO 设置 ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-for-os-monitor'
socketio = SocketIO(app, async_mode='threading')

# --- 核心：文件监控与日志读取 ---

file_pointers = {}

# --- 修复后的函数 ---
def initialize_file_pointers():
    """
    初始化时，将所有文件的指针设为文件末尾。
    此函数现在只尝试 '读取' (r) 文件，不再 '追加' (a)，以避免权限错误。
    """
    print("[*] 扫描日志文件，将指针移至末尾...")
    for filename in AGENT_FILES.keys():
        path = os.path.join(LOG_DIR, filename)
        
        # 修复：我们只检查文件是否存在并读取，不再尝试创建它。
        # 创建文件是 agent (root) 的责任。
        if os.path.exists(path):
            try:
                # 尝试以只读 'r' 模式打开
                with open(path, 'r') as f:
                    f.seek(0, 2) # 移动到文件末尾
                    file_pointers[path] = f.tell() # 记录末尾位置
            except PermissionError:
                print(f"[!] 权限错误：无法读取 {path}。")
                print(f"[!] 请确保运行此脚本的用户 ('{os.getlogin()}') 对该文件有读权限。")
                print(f"[!] 提示: 尝试运行 'sudo chmod o+r {path}'")
            except Exception as e:
                print(f"[!] 无法打开 {path}: {e}")
        else:
            # 文件不存在，没关系，watchdog 会在它被创建时捕获。
            print(f"[i] 日志文件 {path} 尚不存在，将等待 agent 创建...")
            # 即使文件不存在，也初始化指针，以便 watchdog 可以处理
            file_pointers[path] = 0
            
    print(f"[*] 指针初始化完成: {file_pointers}")
# --- 修复结束 ---


class LogFileEventHandler(FileSystemEventHandler):
    """
    当文件系统事件发生时（即 Agent 写入日志），此类将介入处理。
    """
    def on_modified(self, event):
        """当一个文件被修改时调用"""
        if event.is_directory:
            return

        filepath = event.src_path
        
        # 检查这个被修改的文件是否是我们关心的 7 个文件之一
        if filepath not in file_pointers:
            # 可能是新创建的文件，之前 initialize_file_pointers 没扫到
            base_filename = os.path.basename(filepath)
            if base_filename in AGENT_FILES:
                print(f"[+] 检测到新日志文件: {filepath}")
                file_pointers[filepath] = 0 # 从头开始读
            else:
                return # 无关文件

        # 是我们关心的文件，读取新内容
        try:
            with open(filepath, 'r') as f:
                f.seek(file_pointers[filepath])
                new_lines = f.readlines()
                file_pointers[filepath] = f.tell()

            if not new_lines:
                return 

            event_name = AGENT_FILES.get(os.path.basename(filepath), "unknown_event")
            
            for line in new_lines:
                if not line.strip():
                    continue
                try:
                    log_data = json.loads(line)
                    socketio.emit(event_name, log_data)
                except json.JSONDecodeError:
                    print(f"[!] 无法解析 JSON: {line}")

        except FileNotFoundError:
             print(f"[!] 文件 {filepath} 消失了。")
             file_pointers.pop(filepath, None)
        except PermissionError:
             print(f"[!] 权限错误: 无法读取 {filepath}。请检查权限。")
        except Exception as e:
            print(f"[!] 处理文件 {filepath} 出错: {e}")

# --- Web 路由 ---

@app.route('/')
def index():
    """提供 index.html 页面"""
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    print('[+] 客户端已连接')

@socketio.on('disconnect')
def handle_disconnect():
    print('[-] 客户端已断开')

# --- 启动器 ---

def start_watchdog():
    """在单独的线程中启动文件监控"""
    print("[*] 正在启动文件系统观察者 (Watchdog)...")
    event_handler = LogFileEventHandler()
    observer = Observer()
    observer.schedule(event_handler, LOG_DIR, recursive=True) # 设为 True 以捕获新文件创建
    observer.start()
    print(f"[*] 正在监控目录: {LOG_DIR}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == '__main__':
    initialize_file_pointers()

    watchdog_thread = threading.Thread(target=start_watchdog, daemon=True)
    watchdog_thread.start()

    print("[*] 正在启动实时仪表盘 Web 服务器...")
    print(f"[*] 请在浏览器中打开: http://127.0.0.1:5000")
    try:
        socketio.run(app, host='127.0.0.1', port=5000, allow_unsafe_werkzeug=True)
    except OSError as e:
        if "Address already in use" in str(e):
            print("[!] 错误: 端口 5000 已被占用。")
            print("[!] 请关闭占用该端口的程序，或修改此脚本中的端口号。")
        else:
            raise