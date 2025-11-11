#!/bin/bash
# run_dashboard.sh: 
# 一键启动所有采集器并打开 multitail 仪表盘。
# 必须使用 sudo 运行此脚本。

# --- 0. 权限检查 ---
if [ "$EUID" -ne 0 ]; then
  echo "❌ 请使用 sudo 运行此脚本 (e.g., sudo bash run_dashboard.sh)"
  exit 1
fi

echo "[*] 1/4 检查依赖：multitail..."
if ! command -v multitail &> /dev/null; then
    echo "   -> multitail 未安装，正在尝试自动安装..."
    apt update
    apt install -y multitail
    echo "   -> multitail 安装完毕。"
else
    echo "   -> multitail 已安装。"
fi

echo "[*] 2/4 正在启动所有 7 个采集器..."
# 调用现有的启动脚本
bash start_monitoring.sh

# 给予 Agent 1-2 秒的时间来创建初始日志文件
echo "[*] 3/4 正在设置日志文件权限 (等待 2 秒)..."
sleep 2 

# 授予读取权限，以便 multitail (即使作为非 root) 也能读取
chmod o+rx /var/log/os_monitor_log
# 隐藏 'No such file or directory' 错误，因为某些 .jsonl 可能还未创建
chmod o+r /var/log/os_monitor_log/*.jsonl &> /dev/null

echo "[*] 4/4 启动 multitail 实时仪表盘..."
echo "    (按 'q' 键退出仪表盘)"
echo "    (退出后，Agent 仍会在后台运行)"
echo "-----------------------------------------------------"

# 启动 multitail，分 4 列显示所有 .jsonl 文件
# 我们仍然作为 root 运行它，因为它最简单且权限足够
multitail -s 4 /var/log/os_monitor_log/*.jsonl

echo "-----------------------------------------------------"
echo "[*] multitail 已退出。"
echo "提醒：采集器 Agent 仍在后台运行。"
echo "如需停止，请运行: sudo bash stop_monitoring.sh"