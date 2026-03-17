#!/usr/bin/env python3
"""
fast_collector.py
内存优化版的日志聚合工具。
采用流式读写 (Streaming Read/Write) 替代全量加载，
仅在内存中维护去重指纹 (HashSet)，极大幅度降低内存占用。
"""
import glob
import json
import os
import sys
from datetime import datetime

# 配置日志目录
LOG_DIR = "/var/log/os_monitor_log"
# 输出目录
OUTPUT_DIR = "logs"

def main():
    # 确保输出目录存在
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # 生成输出文件名
    timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    out_file = os.path.join(OUTPUT_DIR, f'aggregated_{timestamp}.jsonl')
    
    # 获取所有 jsonl 文件
    files = [
        path
        for path in glob.glob(os.path.join(LOG_DIR, '*.jsonl'))
        if not path.endswith('alerts.jsonl')
    ]
    print(f"[*] Found files: {files}")
    
    if not files:
        print("[!] No log files found in", LOG_DIR)
        return

    seen = set()
    count = 0
    dup_count = 0

    print(f"[*] Starting aggregation to {out_file} ...")

    # 打开输出文件准备写入
    try:
        with open(out_file, 'w', encoding='utf-8') as f_out:
            for path in files:
                print(f" -> Processing {path} ...")
                try:
                    with open(path, 'r', encoding='utf-8') as f_in:
                        for line in f_in:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                obj = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            
                            # 提取去重键
                            key = (
                                obj.get('source'),
                                obj.get('pid'), 
                                obj.get('ppid'),
                                obj.get('ts_ns'), 
                                obj.get('event'), 
                                obj.get('comm'),
                                obj.get('fname'),
                                obj.get('new_fname'),
                                obj.get('host'),
                                obj.get('daddr_str'),
                                obj.get('dport'),
                            )
                            
                            if key in seen:
                                dup_count += 1
                                continue
                            
                            # 记录指纹并立即写入文件
                            seen.add(key)
                            f_out.write(json.dumps(obj, ensure_ascii=False) + '\n')
                            count += 1
                            
                            # 可选：定期打印进度
                            if count % 100000 == 0:
                                print(f"    Processed {count} records...")
                                
                except Exception as e:
                    print(f"[!] Error reading {path}: {e}")
                    
        print("-" * 30)
        print(f"✅ Aggregation Complete!")
        print(f"[*] Total valid records: {count}")
        print(f"[*] Duplicates skipped:  {dup_count}")
        print(f"[*] Output saved to:     {out_file}")

    except Exception as e:
        print(f"❌ Critical Error: {e}")

if __name__ == "__main__":
    main()
