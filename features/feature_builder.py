#!/usr/bin/env python3
"""
feature_builder.py

Extracts sliding-window features and provenance graphs from normalized sessions.
The output is suitable for both classical ML and graph learning experiments.
"""

from __future__ import annotations

import argparse
import os
import pickle
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

import networkx as nx
import pandas as pd

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from features.graph_utils import build_provenance_graph
from monitoring.window_engine import (
    ThresholdProfile,
    aggregate_pid_metrics,
    extract_window_metrics,
    group_events_by_pid,
    score_pid_metrics,
    window_duration_seconds,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--infile", required=True, help="raw sessions pickle")
    parser.add_argument("--outfile", default="dataset/features.parquet")
    parser.add_argument("--graphs-out", default="dataset/graphs.pkl")
    return parser.parse_args()


def graph_summary(graph: nx.MultiDiGraph) -> Dict[str, Any]:
    """Summarize graph topology and node-type composition."""
    node_types = Counter(attrs.get("node_type", "unknown") for _, attrs in graph.nodes(data=True))
    process_subgraph = nx.DiGraph()
    for node_id, attrs in graph.nodes(data=True):
        if attrs.get("node_type") == "process":
            process_subgraph.add_node(node_id, **attrs)
    for source, target, attrs in graph.edges(data=True):
        if (
            graph.nodes[source].get("node_type") == "process"
            and graph.nodes[target].get("node_type") == "process"
            and attrs.get("source") == "process"
        ):
            process_subgraph.add_edge(source, target, **attrs)

    max_process_depth = 0
    if process_subgraph.number_of_nodes() > 0:
        roots = [node for node, indegree in process_subgraph.in_degree() if indegree == 0]
        for root in roots:
            lengths = nx.single_source_shortest_path_length(process_subgraph, root)
            if lengths:
                max_process_depth = max(max_process_depth, max(lengths.values()))

    summary = {
        "graph_nodes": graph.number_of_nodes(),
        "graph_edges": graph.number_of_edges(),
        "graph_process_depth": max_process_depth,
    }
    for node_type, count in node_types.items():
        summary[f"graph_nodes_{node_type}"] = count
    return summary


def flatten_counts(prefix: str, counts: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten a count dictionary into feature columns."""
    flattened = {}
    for key, value in counts.items():
        column = key.replace(".", "_")
        flattened[f"{prefix}_{column}"] = value
    return flattened


def build_row(session: Dict[str, Any], thresholds: ThresholdProfile) -> Dict[str, Any]:
    """Build one tabular feature row for a session."""
    events = session["events"]
    per_pid_events = group_events_by_pid(events)
    per_pid_metrics = {pid: extract_window_metrics(pid_events) for pid, pid_events in per_pid_events.items()}
    aggregate_metrics = aggregate_pid_metrics(per_pid_metrics)
    session_metrics = extract_window_metrics(events)
    pid_scores = {pid: score_pid_metrics(metrics, thresholds)[0] for pid, metrics in per_pid_metrics.items()}

    graph = build_provenance_graph(events)

    row = {
        "session_index": session.get("session_index"),
        "start": session["start"],
        "end": session["end"],
        "window_ms": session.get("window_ms"),
        "stride_ms": session.get("stride_ms"),
        "event_count": session.get("event_count", len(events)),
        "primary_pid": session.get("primary_pid"),
        "duration_s": window_duration_seconds(events),
        "unique_pids": len(per_pid_events),
        "peak_pid_score": max(pid_scores.values()) if pid_scores else 0,
        "mean_pid_score": (sum(pid_scores.values()) / len(pid_scores)) if pid_scores else 0.0,
    }
    row.update(flatten_counts("session", session_metrics))
    row.update(aggregate_metrics)
    row.update(graph_summary(graph))

    return row


def main() -> None:
    args = parse_args()

    with open(args.infile, "rb") as handle:
        sessions: List[Dict[str, Any]] = pickle.load(handle)

    thresholds = ThresholdProfile()
    rows: List[Dict[str, Any]] = []
    graphs = []

    for index, session in enumerate(sessions):
        if session.get("session_index") is None:
            session["session_index"] = index

        row = build_row(session, thresholds)
        rows.append(row)
        graphs.append(
            {
                "session_index": session["session_index"],
                "start": session["start"],
                "end": session["end"],
                "graph": build_provenance_graph(session["events"]),
            }
        )

    out_path = Path(args.outfile)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(rows)
    df.to_parquet(out_path, index=False)
    print("wrote features to", str(out_path))

    graphs_out = Path(args.graphs_out)
    graphs_out.parent.mkdir(parents=True, exist_ok=True)
    with graphs_out.open("wb") as handle:
        pickle.dump(graphs, handle)
    print("wrote graphs to", str(graphs_out))


if __name__ == "__main__":
    main()
