#!/bin/bash
# start_monitoring.sh
# Start all eBPF agents and the optional real-time detector.

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "❌ 请使用 sudo 运行此脚本"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/os_monitor_log"
ENABLE_DETECTOR="${ENABLE_DETECTOR:-1}"
DETECTOR_MODE="${DETECTOR_MODE:-detect}"
DETECTOR_WINDOW_MS="${DETECTOR_WINDOW_MS:-500}"
DETECTOR_BLOCK_SCORE="${DETECTOR_BLOCK_SCORE:-7}"

mkdir -p "$LOG_DIR"
touch "$LOG_DIR/alerts.jsonl"

start_python() {
  local label="$1"
  local script_path="$2"
  local log_name="$3"

  nohup python3 "$SCRIPT_DIR/$script_path" > "$LOG_DIR/$log_name" 2>&1 &
  echo "✅ $label 已启动 (PID $!)"
}

echo "[*] 记录主机元数据..."
python3 "$SCRIPT_DIR/aggregator/metadata_writer.py" > "$LOG_DIR/metadata_writer.log" 2>&1 || true

start_python "进程采集器" "agent/process_agent.py" "process_agent.log"
start_python "文件采集器" "agent/file_agent.py" "file_agent.log"
start_python "网络采集器" "agent/net_agent.py" "net_agent.log"
start_python "DNS 采集器" "agent/dns_agent.py" "dns_agent.log"
start_python "内核模块采集器" "agent/kmod_agent.py" "kmod_agent.log"
start_python "内存采集器" "agent/memory_agent.py" "memory_agent.log"
start_python "可疑系统调用采集器" "agent/syscall_agent.py" "syscall_agent.log"

if [ "$ENABLE_DETECTOR" = "1" ]; then
  nohup python3 "$SCRIPT_DIR/detector/realtime_blocker.py" \
    --mode "$DETECTOR_MODE" \
    --window-ms "$DETECTOR_WINDOW_MS" \
    --block-score "$DETECTOR_BLOCK_SCORE" \
    > "$LOG_DIR/realtime_blocker.log" 2>&1 &
  echo "✅ 实时检测器已启动 (PID $!, mode=$DETECTOR_MODE, window=${DETECTOR_WINDOW_MS}ms)"
else
  echo "ℹ️ 已跳过实时检测器 (ENABLE_DETECTOR=$ENABLE_DETECTOR)"
fi

echo "--------------------------------------"
echo "📡 采集目录：$LOG_DIR"
echo "🔎 实时检测：$DETECTOR_MODE (设置 DETECTOR_MODE=block 可启用即时阻断)"
echo "🛑 停止命令：sudo bash stop_monitoring.sh"
echo "📋 状态查看：sudo bash check_status.sh"
echo "--------------------------------------"
