#!/usr/bin/env python3
"""
visualize_tree.py
Visualize process tree from a single session (load pickled sessions).
Usage:
  python3 tools/visualize_tree.py dataset/raw_sessions.pkl 0
"""
import pickle
import networkx as nx
import matplotlib.pyplot as plt
import sys
from features.graph_utils import build_process_tree

if len(sys.argv) < 2:
    print("Usage: python3 tools/visualize_tree.py <raw_sessions.pkl> [session_index]")
    sys.exit(1)

path = sys.argv[1]
session_index = int(sys.argv[2]) if len(sys.argv) > 2 else 0

with open(path, 'rb') as f:
    sessions = pickle.load(f)

s = sessions[session_index]
G = build_process_tree(s['events'])
plt.figure(figsize=(10, 8))
pos = nx.spring_layout(G, seed=42)
nx.draw(G, pos, with_labels=False, node_size=40, arrows=True)
# annotate some nodes
labels = {n: (d.get('comm') or '')[:10] for n, d in G.nodes(data=True)}
nx.draw_networkx_labels(G, pos, labels, font_size=8)
plt.title(f"Process tree for session {session_index} ({s['start']} -> {s['end']})")
plt.show()
