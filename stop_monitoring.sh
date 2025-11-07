#!/bin/bash
# stop_monitoring.sh — 一键停止所有数据采集 Agent
#sudo bash stop_monitoring.sh

# 确保脚本以 root 权限运行
if [ "$EUID" -ne 0 ]; then
  echo "❌ 请使用 sudo 运行此脚本"
  exit 1
fi

# 停止所有相关采集进程
PIDS=$(ps aux | grep -E 'process_agent\.py|file_agent\.py|net_agent\.py' | grep -v grep | awk '{print $2}')

if [ -z "$PIDS" ]; then
  echo "⚠️ 未发现正在运行的采集器进程。"
  exit 0
fi

echo "🛑 正在停止以下采集器进程："
echo "$PIDS"
kill -9 $PIDS

echo "✅ 所有 Agent 已停止。"
echo "--------------------------------------"
echo "可使用 'ps aux | grep agent' 验证停止状态"
echo "--------------------------------------"
