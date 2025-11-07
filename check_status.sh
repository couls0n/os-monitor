#!/bin/bash
# ----------------------------------------------
# check_status.sh
# 用途：检查数据采集进程是否在运行
# 作者：张忠硕
# 日期：2025-10-29
# ----------------------------------------------

process_name="data_collector.py"

# 查找进程
pid=$(pgrep -f $process_name)

if [ -z "$pid" ]; then
    echo "❌ 数据采集进程（$process_name）未运行。"
else
    echo "✅ 数据采集进程（$process_name）正在运行，PID: $pid"
    # 显示进程的详细信息
    ps -fp $pid
fi

