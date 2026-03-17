#!/bin/bash
# run_dashboard.sh
# Start monitoring and open a multitail dashboard for raw events and alerts.

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "❌ 请使用 sudo 运行此脚本"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/os_monitor_log"

if ! command -v multitail >/dev/null 2>&1; then
  echo "[*] 安装 multitail ..."
  apt update
  apt install -y multitail
fi

bash "$SCRIPT_DIR/start_monitoring.sh"

sleep 2
mkdir -p "$LOG_DIR"
touch \
  "$LOG_DIR/process.jsonl" \
  "$LOG_DIR/fileio.jsonl" \
  "$LOG_DIR/net.jsonl" \
  "$LOG_DIR/dns.jsonl" \
  "$LOG_DIR/kmod.jsonl" \
  "$LOG_DIR/memory.jsonl" \
  "$LOG_DIR/syscall.jsonl" \
  "$LOG_DIR/alerts.jsonl"

chmod o+rx "$LOG_DIR"
chmod o+r "$LOG_DIR"/*.jsonl 2>/dev/null || true

echo "[*] 启动实时仪表盘..."
echo "    原始事件 + alerts.jsonl 会一起显示。按 q 退出。"

multitail -s 4 "$LOG_DIR"/*.jsonl
