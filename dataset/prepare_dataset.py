#!/usr/bin/env python3
"""
prepare_dataset.py
Reads aggregated JSONL events and groups them into 'sessions' (time windows per host)
and serializes sessions for feature extraction.

Outputs: dataset/raw_sessions.pkl
"""
import argparse
import glob
import json
from datetime import datetime, timedelta
import pandas as pd
import os
import pickle

parser = argparse.ArgumentParser()
parser.add_argument('--input', default='/var/log/os_monitor')
parser.add_argument('--out', default='dataset/raw_sessions.pkl')
parser.add_argument('--window', type=int, default=60, help='session window size in seconds')
args = parser.parse_args()

files = glob.glob(os.path.join(args.input, '*.jsonl'))
rows = []
for path in files:
    with open(path) as f:
        for line in f:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            rows.append(obj)

if not rows:
    print('no rows found in', args.input)
    exit(1)

# normalize timestamps
for r in rows:
    if 'ts' in r and r['ts']:
        try:
            r['_ts'] = datetime.fromisoformat(r['ts'])
        except Exception:
            r['_ts'] = datetime.utcnow()
    elif 'ts_ns' in r and r['ts_ns']:
        try:
            r['_ts'] = datetime.utcfromtimestamp(r['ts_ns']/1e9)
        except Exception:
            r['_ts'] = datetime.utcnow()
    else:
        r['_ts'] = datetime.utcnow()

# build DataFrame
df = pd.DataFrame(rows)
df = df.sort_values('_ts')

# sliding window sessions: assign session_id based on gap > window
sessions = []
current = []
last_ts = None
for _, row in df.iterrows():
    if last_ts is None:
        current = [row.to_dict()]
        last_ts = row['_ts']
    else:
        if (row['_ts'] - last_ts).total_seconds() > args.window:
            sessions.append(current)
            current = [row.to_dict()]
        else:
            current.append(row.to_dict())
        last_ts = row['_ts']
if current:
    sessions.append(current)

# convert sessions to serializable form
serial = []
for s in sessions:
    serial.append({
        'start': s[0]['_ts'].isoformat(),
        'end': s[-1]['_ts'].isoformat(),
        'events': [dict(x) for x in s]
    })

os.makedirs(os.path.dirname(args.out), exist_ok=True)
with open(args.out, 'wb') as f:
    pickle.dump(serial, f)
print('wrote', args.out, 'sessions:', len(serial))
