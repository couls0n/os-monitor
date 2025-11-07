#!/usr/bin/env python3
"""
feature_builder.py
Takes sessions (from dataset/raw_sessions.pkl) and extracts tabular features and graph-based features.
Outputs a parquet file of features (one row per session) and a small graphs file (optional).
"""
import argparse
import pickle
import pandas as pd
import numpy as np
from datetime import datetime
import os
from features.graph_utils import build_process_tree
import networkx as nx

parser = argparse.ArgumentParser()
parser.add_argument('--infile', required=True, help='raw sessions pickle')
parser.add_argument('--outfile', dest='outfile', default='dataset/features.parquet')
parser.add_argument('--graphs_out', dest='graphs_out', default='dataset/graphs.pkl')
args = parser.parse_args()

with open(args.infile, 'rb') as f:
    sessions = pickle.load(f)

rows = []
graphs = []
for idx, s in enumerate(sessions):
    evs = s['events']
    # compute basic stats
    start = datetime.fromisoformat(s['start'])
    end = datetime.fromisoformat(s['end'])
    duration = (end - start).total_seconds()
    pids = set()
    commands = {}
    create_count = 0
    exit_count = 0
    write_bytes = 0
    net_conns = 0
    for e in evs:
        if 'pid' in e and e['pid'] is not None:
            try:
                pids.add(int(e['pid']))
            except Exception:
                pass
        if int(e.get('event') or 0) == 1:
            create_count += 1
        if int(e.get('event') or 0) == 3:
            exit_count += 1
        if int(e.get('event') or 0) == 2 and e.get('count'):
            try:
                write_bytes += int(e.get('count') or 0)
            except Exception:
                pass
        if e.get('dport') is not None:
            net_conns += 1
        if e.get('comm'):
            commands[e.get('comm')] = commands.get(e.get('comm'), 0) + 1
    unique_cmds = len(commands)
    top_cmd = sorted(commands.items(), key=lambda x: -x[1])[0][0] if commands else ''

    # build process tree graph
    G = build_process_tree(evs)
    nodes = G.number_of_nodes()
    edges = G.number_of_edges()
    max_depth = 0
    try:
        if nodes > 0:
            depths = []
            roots = [n for n,d in G.in_degree() if G.in_degree(n)==0]
            for r in roots:
                # compute longest path from root r
                lengths = nx.single_source_shortest_path_length(G, r)
                if lengths:
                    depths.append(max(lengths.values()))
            max_depth = max(depths) if depths else 0
    except Exception:
        max_depth = 0

    row = {
        'start': s['start'],
        'end': s['end'],
        'duration': duration,
        'num_pids': len(pids),
        'create_count': create_count,
        'exit_count': exit_count,
        'write_bytes': write_bytes,
        'net_conns': net_conns,
        'unique_cmds': unique_cmds,
        'top_cmd': top_cmd,
        'graph_nodes': nodes,
        'graph_edges': edges,
        'graph_maxdepth': max_depth
    }
    rows.append(row)
    graphs.append({'session_index': idx, 'graph': G})

# write features
os.makedirs(os.path.dirname(args.outfile), exist_ok=True)
df = pd.DataFrame(rows)
df.to_parquet(args.outfile, index=False)
print('wrote features to', args.outfile)

# write graphs pickle (optional; can be large)
os.makedirs(os.path.dirname(args.graphs_out), exist_ok=True)
with open(args.graphs_out, 'wb') as f:
    pickle.dump(graphs, f)
print('wrote graphs to', args.graphs_out)
