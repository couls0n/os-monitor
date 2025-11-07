#!/bin/bash
# start_monitoring.sh — 一键启动所有数据采集 Agent
#sudo bash start_monitoring.sh

# 确保脚本以 root 权限运行
if [ "$EUID" -ne 0 ]; then
  echo "❌ 请使用 sudo 运行此脚本"
  exit 1
fi

# 定义日志输出目录
LOG_DIR="/var/log/os_monitor"
mkdir -p $LOG_DIR

# 启动各采集器
nohup python3 agent/process_agent.py > $LOG_DIR/process_agent.log 2>&1 &
echo "✅ 进程采集器已启动 (PID $!)"

nohup python3 agent/file_agent.py > $LOG_DIR/file_agent.log 2>&1 &
echo "✅ 文件采集器已启动 (PID $!)"

nohup python3 agent/net_agent.py > $LOG_DIR/net_agent.log 2>&1 &
echo "✅ 网络采集器已启动 (PID $!)"
# ... (原有 process, file, net agent 启动命令)

nohup python3 agent/dns_agent.py > $LOG_DIR/dns_agent.log 2>&1 &
echo "✅ DNS 采集器已启动 (PID $!)"

nohup python3 agent/kmod_agent.py > $LOG_DIR/kmod_agent.log 2>&1 &
echo "✅ 内核模块采集器已启动 (PID $!)"

# ... (原有脚本结尾)
# 显示运行状态
echo "--------------------------------------"
echo "📡 所有 Agent 已启动，日志输出目录：$LOG_DIR"
echo "可使用 'ps aux | grep agent' 查看进程状态"
echo "使用 'sudo pkill -f agent' 可一键停止所有 Agent"
echo "--------------------------------------"
