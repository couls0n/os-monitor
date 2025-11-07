#!/usr/bin/env python3
"""
collector.py
Simple aggregator that reads JSONL files from /var/log/os_monitor, deduplicates by
(pid, ts_ns, event, comm), annotates with host metadata, and writes to a sqlite DB or merged JSONL.
"""
import argparse
import glob
import json
import os
import sqlite3
from datetime import datetime

LOG_DIR = "/var/log/os_monitor"

parser = argparse.ArgumentParser()
parser.add_argument('--out', choices=['sqlite','file'], default='file')
parser.add_argument('--db', default='logs/events.db')
args = parser.parse_args()

os.makedirs(os.path.dirname(args.db), exist_ok=True)

files = glob.glob(os.path.join(LOG_DIR, '*.jsonl'))
print(f"found files: {files}")

records = []
seen = set()
for path in files:
    with open(path) as f:
        for line in f:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            key = (obj.get('pid'), obj.get('ts_ns'), obj.get('event'), obj.get('comm'))
            if key in seen:
                continue
            seen.add(key)
            records.append(obj)

print(f"collected {len(records)} events")

if args.out == 'sqlite':
    conn = sqlite3.connect(args.db)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS events (
        pid INTEGER,
        ppid INTEGER,
        comm TEXT,
        ts TEXT,
        ts_ns INTEGER,
        event INTEGER,
        raw TEXT
    )''')
    for r in records:
        c.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?)', (
            r.get('pid'),
            r.get('ppid'),
            r.get('comm'),
            r.get('ts'),
            r.get('ts_ns'),
            r.get('event'),
            json.dumps(r)))
    conn.commit()
    conn.close()
    print("wrote to sqlite db:", args.db)
else:
    out_file = 'logs/aggregated_{}.jsonl'.format(datetime.utcnow().strftime('%Y%m%dT%H%M%SZ'))
    os.makedirs('logs', exist_ok=True)
    with open(out_file, 'w') as f:
        for r in records:
            f.write(json.dumps(r) + '\n')
    print('wrote', out_file)
