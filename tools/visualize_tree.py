#!/usr/bin/env python3
"""Visualize either the process tree or full provenance graph for one session."""

from __future__ import annotations

import argparse
import pickle
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from features.graph_utils import build_process_tree, build_provenance_graph


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("sessions")
    parser.add_argument("session_index", type=int, nargs="?", default=0)
    parser.add_argument("--mode", choices=["process", "provenance"], default="provenance")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    with open(args.sessions, "rb") as handle:
        sessions = pickle.load(handle)

    session = sessions[args.session_index]
    if args.mode == "process":
        graph = build_process_tree(session["events"])
    else:
        graph = build_provenance_graph(session["events"])

    plt.figure(figsize=(12, 9))
    pos = nx.spring_layout(graph, seed=42)
    node_colors = []
    for _, attrs in graph.nodes(data=True):
        node_type = attrs.get("node_type")
        if node_type == "process":
            node_colors.append("#1f77b4")
        elif node_type == "file":
            node_colors.append("#ff7f0e")
        elif node_type == "network":
            node_colors.append("#2ca02c")
        elif node_type == "dns":
            node_colors.append("#9467bd")
        elif node_type == "memory":
            node_colors.append("#d62728")
        else:
            node_colors.append("#7f7f7f")

    nx.draw(graph, pos, with_labels=False, node_size=90, node_color=node_colors, arrows=True)
    labels = {node: attrs.get("label", "")[:18] for node, attrs in graph.nodes(data=True)}
    nx.draw_networkx_labels(graph, pos, labels, font_size=7)
    plt.title(f"{args.mode} graph for session {args.session_index} ({session['start']} -> {session['end']})")
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    main()
