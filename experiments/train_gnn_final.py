#!/usr/bin/env python3
"""Train a provenance-graph GNN on session-level labels."""

from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import sys
from math import log1p
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from torch import nn

try:
    from torch_geometric.loader import DataLoader
except ImportError:  # pragma: no cover - fallback for older PyG
    from torch_geometric.data import DataLoader

from torch_geometric.data import Data
from torch_geometric.nn import GINEConv, global_max_pool, global_mean_pool

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from experiments.split_utils import prepare_split_frame, time_split_boundary


NODE_TYPES = ("process", "file", "network", "dns", "memory", "syscall", "module", "unknown")
TYPE_INDEX = {node_type: index for index, node_type in enumerate(NODE_TYPES)}
EDGE_SOURCES = ("process", "file", "net", "dns", "memory", "syscall", "kmod", "unknown")
EDGE_SOURCE_INDEX = {source: index for index, source in enumerate(EDGE_SOURCES)}
TOKEN_BUCKETS = 16
EDGE_BUCKETS = 16


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--graphs", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--hidden-dim", type=int, default=64)
    parser.add_argument("--lr", type=float, default=0.005)
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--split-strategy", choices=["auto", "time", "random"], default="auto")
    parser.add_argument("--allow-overlap-windows", action="store_true")
    parser.add_argument("--sampling-phase", type=int, default=0)
    parser.add_argument("--out", default="models/gnn_provenance.pt")
    parser.add_argument("--metrics-out", default="models/gnn_provenance_metrics.json")
    return parser.parse_args()


def stable_bucket(text: str) -> int:
    """Hash text into a stable feature bucket."""
    digest = hashlib.blake2b(text.encode("utf-8", errors="ignore"), digest_size=4).digest()
    return int.from_bytes(digest, byteorder="big") % TOKEN_BUCKETS


def build_node_features(node_data: Dict[str, object], in_degree: int, out_degree: int) -> List[float]:
    """Build a compact feature vector for one node."""
    features = [0.0] * (len(NODE_TYPES) + TOKEN_BUCKETS + 6)
    node_type = str(node_data.get("node_type") or "unknown")
    type_index = TYPE_INDEX.get(node_type, TYPE_INDEX["unknown"])
    features[type_index] = 1.0

    label = str(
        node_data.get("label")
        or node_data.get("comm")
        or node_data.get("path")
        or node_data.get("host")
        or node_data.get("ip")
        or node_data.get("module")
        or node_data.get("syscall")
        or "unknown"
    )
    bucket = stable_bucket(label)
    features[len(NODE_TYPES) + bucket] = 1.0

    numeric_hint = float(
        node_data.get("length")
        or node_data.get("port")
        or 0.0
    )
    features[-6] = 1.0 if node_data.get("pid") is not None else 0.0
    features[-5] = min(log1p(float(in_degree)) / 3.0, 1.0)
    features[-4] = min(log1p(float(out_degree)) / 3.0, 1.0)
    features[-3] = min(log1p(max(numeric_hint, 0.0)) / 16.0, 1.0)
    features[-2] = 1.0 if node_data.get("protection") else 0.0
    features[-1] = min(len(label) / 128.0, 1.0)
    return features


def edge_feature_dim() -> int:
    return len(EDGE_SOURCES) + (EDGE_BUCKETS * 2) + 4


def build_edge_features(edge_data: Dict[str, object]) -> List[float]:
    """Build an edge feature vector from provenance metadata."""
    features = [0.0] * edge_feature_dim()
    source = str(edge_data.get("source") or "unknown")
    source_index = EDGE_SOURCE_INDEX.get(source, EDGE_SOURCE_INDEX["unknown"])
    features[source_index] = 1.0

    event_key = str(
        edge_data.get("event_key")
        or f"{source}.{edge_data.get('action') or 'unknown'}"
    )
    relation = str(edge_data.get("relation") or event_key)
    event_bucket = stable_bucket(event_key) % EDGE_BUCKETS
    relation_bucket = stable_bucket(relation) % EDGE_BUCKETS

    features[len(EDGE_SOURCES) + event_bucket] = 1.0
    features[len(EDGE_SOURCES) + EDGE_BUCKETS + relation_bucket] = 1.0
    features[-4] = min(log1p(float(edge_data.get("write_bytes") or 0.0)) / 16.0, 1.0)
    features[-3] = min(log1p(float(edge_data.get("delta_ns") or 0.0)) / 32.0, 1.0)
    features[-2] = 1.0 if "lineage" in relation or source == "process" else 0.0
    features[-1] = 1.0 if "target" in relation else 0.0
    return features


def merge_graphs_and_labels(graphs: List[Dict[str, object]], labels: pd.DataFrame) -> pd.DataFrame:
    """Align graphs with labels by session_index when available."""
    graph_df = pd.DataFrame(
        {
            "session_index": [item.get("session_index") for item in graphs],
            "start": [item.get("start") for item in graphs],
            "start_ts": [item.get("start_ts") for item in graphs],
            "window_ms": [item.get("window_ms") for item in graphs],
            "stride_ms": [item.get("stride_ms") for item in graphs],
            "_graph_obj": graphs,
        }
    )

    if "session_index" in labels.columns and graph_df["session_index"].notna().all():
        merged = pd.merge(graph_df, labels, on="session_index", how="inner")
    else:
        merged = pd.merge(graph_df, labels, on="start", how="inner")

    if merged.empty:
        raise SystemExit("failed to align graphs with labels; provide session_index or start columns")

    return merged


def to_pyg_data(graph_item: Dict[str, object], label_id: int) -> Data:
    """Convert a NetworkX provenance graph into a PyG Data object."""
    graph = graph_item["graph"]
    node_ids = list(graph.nodes())
    node_map = {node_id: index for index, node_id in enumerate(node_ids)}
    in_degree = dict(graph.in_degree())
    out_degree = dict(graph.out_degree())

    x = torch.tensor(
        [
            build_node_features(
                graph.nodes[node_id],
                in_degree.get(node_id, 0),
                out_degree.get(node_id, 0),
            )
            for node_id in node_ids
        ],
        dtype=torch.float,
    )

    edge_pairs = []
    edge_features = []
    for source, target, attrs in graph.edges(data=True):
        edge_pairs.append((node_map[source], node_map[target]))
        edge_features.append(build_edge_features(attrs))

    if edge_pairs:
        edge_index = torch.tensor(edge_pairs, dtype=torch.long).t().contiguous()
        edge_attr = torch.tensor(edge_features, dtype=torch.float)
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long)
        edge_attr = torch.empty((0, edge_feature_dim()), dtype=torch.float)

    return Data(
        x=x,
        edge_index=edge_index,
        edge_attr=edge_attr,
        y=torch.tensor(label_id, dtype=torch.long),
        session_index=int(graph_item.get("session_index") or -1),
    )


class ProvenanceGNN(nn.Module):
    """Edge-aware graph classifier for provenance sessions."""

    def __init__(self, input_dim: int, edge_dim: int, hidden_dim: int, num_classes: int) -> None:
        super().__init__()
        self.node_encoder = nn.Linear(input_dim, hidden_dim)
        self.conv1 = GINEConv(
            nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, hidden_dim),
            ),
            edge_dim=edge_dim,
        )
        self.conv2 = GINEConv(
            nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, hidden_dim),
            ),
            edge_dim=edge_dim,
        )
        self.conv3 = GINEConv(
            nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, hidden_dim),
            ),
            edge_dim=edge_dim,
        )
        self.lin = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(p=0.3),
            nn.Linear(hidden_dim, num_classes),
        )

    def forward(self, data: Data) -> torch.Tensor:
        x, edge_index, edge_attr, batch = data.x, data.edge_index, data.edge_attr, data.batch
        x = self.node_encoder(x)
        x = self.conv1(x, edge_index, edge_attr)
        x = F.relu(x)
        x = F.dropout(x, p=0.3, training=self.training)
        x = self.conv2(x, edge_index, edge_attr)
        x = F.relu(x)
        x = self.conv3(x, edge_index, edge_attr)
        pooled = torch.cat(
            [global_mean_pool(x, batch), global_max_pool(x, batch)],
            dim=1,
        )
        return self.lin(pooled)


def choose_split_indices(
    labels: np.ndarray,
    sample_count: int,
    args: argparse.Namespace,
) -> tuple[list[int], list[int], str]:
    """Pick a train/test split while preferring chronological holdout."""
    all_classes = set(labels.tolist())

    if args.split_strategy in {"auto", "time"}:
        split_at = time_split_boundary(sample_count, args.test_size)
        train_idx = list(range(split_at))
        test_idx = list(range(split_at, sample_count))
        train_classes = set(labels[train_idx].tolist())
        test_classes = set(labels[test_idx].tolist())
        if args.split_strategy == "time" or (train_classes == all_classes and test_classes):
            return train_idx, test_idx, "time"
        print("[*] time split would drop class coverage; falling back to random split")

    stratify = labels if len(all_classes) > 1 else None
    try:
        train_idx, test_idx = train_test_split(
            list(range(sample_count)),
            test_size=args.test_size,
            random_state=args.random_state,
            stratify=stratify,
        )
    except ValueError:
        train_idx, test_idx = train_test_split(
            list(range(sample_count)),
            test_size=args.test_size,
            random_state=args.random_state,
            stratify=None,
        )
    return sorted(train_idx), sorted(test_idx), "random"


def main() -> None:
    args = parse_args()

    with open(args.graphs, "rb") as handle:
        raw_graphs = pickle.load(handle)
    labels = pd.read_csv(args.labels)
    aligned = merge_graphs_and_labels(raw_graphs, labels)
    prepared, disjoint_step = prepare_split_frame(
        aligned,
        allow_overlap_windows=args.allow_overlap_windows,
        sampling_phase=args.sampling_phase,
    )
    if prepared.empty:
        raise SystemExit("no aligned graphs remain after overlap filtering")
    if len(prepared) != len(aligned):
        print(f"[*] overlap-aware downsampling kept {len(prepared)}/{len(aligned)} windows (step={disjoint_step})")

    label_encoder = LabelEncoder()
    encoded_labels = label_encoder.fit_transform(prepared["label"])
    data_list = []
    filtered_labels: List[int] = []
    for graph_item, label_id in zip(prepared["_graph_obj"], encoded_labels):
        data = to_pyg_data(graph_item, int(label_id))
        if data.x.size(0) == 0:
            continue
        data_list.append(data)
        filtered_labels.append(int(label_id))
    if not data_list:
        raise SystemExit("no graphs available for training")

    label_array = np.array(filtered_labels, dtype=np.int64)
    train_idx, test_idx, effective_split = choose_split_indices(label_array, len(data_list), args)
    train_data = [data_list[index] for index in train_idx]
    test_data = [data_list[index] for index in test_idx]

    train_loader = DataLoader(train_data, batch_size=args.batch_size, shuffle=True)
    test_loader = DataLoader(test_data, batch_size=args.batch_size, shuffle=False)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = ProvenanceGNN(
        input_dim=data_list[0].x.size(1),
        edge_dim=data_list[0].edge_attr.size(1),
        hidden_dim=args.hidden_dim,
        num_classes=len(label_encoder.classes_),
    ).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=5e-4)

    print(f"[*] training GNN on {device} for {args.epochs} epochs")
    for epoch in range(args.epochs):
        model.train()
        total_loss = 0.0
        for batch in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            logits = model(batch)
            loss = F.cross_entropy(logits, batch.y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        if (epoch + 1) % 10 == 0:
            print(f"epoch {epoch + 1}/{args.epochs} loss={total_loss / max(len(train_loader), 1):.4f}")

    model.eval()
    y_true: List[int] = []
    y_pred: List[int] = []
    y_prob: List[np.ndarray] = []

    with torch.no_grad():
        for batch in test_loader:
            batch = batch.to(device)
            logits = model(batch)
            probabilities = torch.softmax(logits, dim=1)
            predictions = probabilities.argmax(dim=1)

            y_true.extend(batch.y.cpu().tolist())
            y_pred.extend(predictions.cpu().tolist())
            y_prob.extend(probabilities.cpu().numpy())

    metrics = {
        "classes": label_encoder.classes_.tolist(),
        "split_strategy": effective_split,
        "allow_overlap_windows": args.allow_overlap_windows,
        "disjoint_step": disjoint_step,
        "samples_before_filter": int(len(aligned)),
        "samples_after_filter": int(len(prepared)),
        "graphs_used_for_training": int(len(data_list)),
        "classification_report": classification_report(
            y_true,
            y_pred,
            target_names=label_encoder.classes_.tolist(),
            output_dict=True,
            zero_division=0,
        ),
    }
    try:
        prob_array = np.array(y_prob)
        if len(label_encoder.classes_) == 2:
            metrics["roc_auc"] = float(roc_auc_score(y_true, prob_array[:, 1]))
        else:
            metrics["roc_auc_ovr"] = float(roc_auc_score(y_true, prob_array, multi_class="ovr"))
    except ValueError:
        pass

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "model_state_dict": model.state_dict(),
            "label_classes": label_encoder.classes_.tolist(),
            "input_dim": data_list[0].x.size(1),
            "edge_dim": data_list[0].edge_attr.size(1),
            "hidden_dim": args.hidden_dim,
            "num_classes": len(label_encoder.classes_),
        },
        out_path,
    )
    print("wrote model to", str(out_path))

    metrics_path = Path(args.metrics_out)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    with metrics_path.open("w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2, ensure_ascii=False)
    print("wrote metrics to", str(metrics_path))


if __name__ == "__main__":
    main()
