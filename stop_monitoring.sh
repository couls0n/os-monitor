#!/bin/bash
# stop_monitoring.sh — 一键停止所有数据采集 Agent 和 multitail 仪表盘
# sudo bash stop_monitoring.sh

# 确保脚本以 root 权限运行
if [ "$EUID" -ne 0 ]; then
  echo "❌ 请使用 sudo 运行此脚本"
  exit 1
fi

# 定义要查找的进程模式
# 1. 匹配所有 7 个 agent 脚本
AGENT_PATTERN='process_agent\.py|file_agent\.py|net_agent\.py|dns_agent\.py|kmod_agent\.py|memory_agent\.py|syscall_agent\.py'
# 2. 匹配由 run_dashboard.sh 启动的 multitail 进程
DASHBOARD_PATTERN='multitail.*os_monitor_log'

# 查找所有相关进程的 PID
PIDS=$(ps aux | grep -E "${AGENT_PATTERN}|${DASHBOARD_PATTERN}" | grep -v grep | awk '{print $2}')

if [ -z "$PIDS" ]; then
  echo "⚠️ 未发现正在运行的采集器或仪表盘进程。"
  exit 0
fi

echo "🛑 正在停止以下相关进程："
# -f 标志会显示更详细的进程信息
ps -f -p $PIDS

echo "" # 换行

# 使用 kill -9 强制停止
kill -9 $PIDS

echo "✅ 所有相关进程已停止。"
echo "--------------------------------------"
echo "可使用 'ps aux | grep agent' 验证停止状态"
echo "--------------------------------------"