#!/usr/bin/env python3
"""
graph_utils.py
Helpers to convert a list of events into a process-tree graph (networkx). Handles PID reuse by
using creation timestamp to build unique node ids.
"""
import networkx as nx
from datetime import datetime

def build_process_tree(events):
    """
    events: list of event dicts with pid, ppid, event, ts (iso)
    We create nodes keyed by (pid, create_ts) to handle reuse.
    Creation event defined as event==1 (exec) or event==2 (fork).
    """
    G = nx.DiGraph()
    creation = {}  # pid -> node_key
    first_seen = {}  # pid -> ts

    for e in events:
        # skip events without pid
        try:
            pid = int(e.get('pid'))
        except Exception:
            continue
        etype = e.get('event')
        ts = e.get('ts') or e.get('_ts') or ''
        try:
            t = datetime.fromisoformat(ts)
            ts_str = t.isoformat()
        except Exception:
            ts_str = str(ts)

        # treat exec or fork as creation
        if int(etype) in (1, 2):
            key = (pid, ts_str)
            # register creation time (first seen)
            if pid not in first_seen:
                first_seen[pid] = ts_str
            creation[pid] = key
            if not G.has_node(key):
                G.add_node(key, comm=e.get('comm'), ts=ts_str)
            ppid = e.get('ppid')
            try:
                ppid = int(ppid)
            except Exception:
                ppid = None
            if ppid and ppid in creation:
                G.add_edge(creation[ppid], key)

    return G
