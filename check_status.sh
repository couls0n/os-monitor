#!/bin/bash
# check_status.sh
# Show the current status of agents and the real-time blocker.

set -euo pipefail

PATTERNS=(
  "agent/process_agent.py"
  "agent/file_agent.py"
  "agent/net_agent.py"
  "agent/dns_agent.py"
  "agent/kmod_agent.py"
  "agent/memory_agent.py"
  "agent/syscall_agent.py"
  "detector/realtime_blocker.py"
)

echo "=== OS-Monitor 运行状态 ==="
for pattern in "${PATTERNS[@]}"; do
  pid="$(pgrep -f "$pattern" | paste -sd "," - || true)"
  if [ -n "$pid" ]; then
    printf "✅ %-35s PID=%s\n" "$pattern" "$pid"
  else
    printf "❌ %-35s 未运行\n" "$pattern"
  fi
done
