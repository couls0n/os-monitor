#!/bin/bash
# stop_monitoring.sh
# Gracefully stop agents, detector and the dashboard.

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "❌ 请使用 sudo 运行此脚本"
  exit 1
fi

PATTERNS=(
  "agent/process_agent.py"
  "agent/file_agent.py"
  "agent/net_agent.py"
  "agent/dns_agent.py"
  "agent/kmod_agent.py"
  "agent/memory_agent.py"
  "agent/syscall_agent.py"
  "detector/realtime_blocker.py"
  "multitail.*os_monitor_log"
)

PIDS=()
for pattern in "${PATTERNS[@]}"; do
  while IFS= read -r pid; do
    if [ -n "$pid" ]; then
      PIDS+=("$pid")
    fi
  done < <(pgrep -f "$pattern" || true)
done

if [ "${#PIDS[@]}" -eq 0 ]; then
  echo "⚠️ 未发现正在运行的采集器、检测器或仪表盘。"
  exit 0
fi

PIDS=($(printf "%s\n" "${PIDS[@]}" | sort -u))

echo "🛑 正在停止以下进程："
ps -fp "${PIDS[@]}" || true

kill "${PIDS[@]}" 2>/dev/null || true
sleep 1

REMAINING=()
for pid in "${PIDS[@]}"; do
  if kill -0 "$pid" 2>/dev/null; then
    REMAINING+=("$pid")
  fi
done

if [ "${#REMAINING[@]}" -gt 0 ]; then
  echo "⚠️ 以下进程未响应 SIGTERM，升级为 SIGKILL： ${REMAINING[*]}"
  kill -9 "${REMAINING[@]}" 2>/dev/null || true
fi

echo "✅ 已停止所有相关进程。"
