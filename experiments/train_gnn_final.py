#!/usr/bin/env python3
"""Train a provenance-graph GNN on session-level labels."""

from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import sys
from pathlib import Path
from typing import Dict, List, Tuple

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
from torch_geometric.nn import GCNConv, global_mean_pool

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


NODE_TYPES = ("process", "file", "network", "dns", "memory", "syscall", "module", "unknown")
TYPE_INDEX = {node_type: index for index, node_type in enumerate(NODE_TYPES)}
TOKEN_BUCKETS = 16


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--graphs", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--hidden-dim", type=int, default=64)
    parser.add_argument("--lr", type=float, default=0.005)
    parser.add_argument("--out", default="models/gnn_provenance.pt")
    parser.add_argument("--metrics-out", default="models/gnn_provenance_metrics.json")
    return parser.parse_args()


def stable_bucket(text: str) -> int:
    """Hash text into a stable feature bucket."""
    digest = hashlib.blake2b(text.encode("utf-8", errors="ignore"), digest_size=4).digest()
    return int.from_bytes(digest, byteorder="big") % TOKEN_BUCKETS


def build_node_features(node_data: Dict[str, object]) -> List[float]:
    """Build a compact feature vector for one node."""
    features = [0.0] * (len(NODE_TYPES) + TOKEN_BUCKETS + 2)
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

    pid = node_data.get("pid")
    if pid is not None:
        features[-2] = 1.0
    features[-1] = 1.0 if node_type == "process" else 0.0
    return features


def merge_graphs_and_labels(graphs: List[Dict[str, object]], labels: pd.DataFrame) -> List[Tuple[Dict[str, object], object]]:
    """Align graphs with labels by session_index when available."""
    graph_df = pd.DataFrame(
        {
            "session_index": [item.get("session_index") for item in graphs],
            "start": [item.get("start") for item in graphs],
            "_graph_obj": graphs,
        }
    )

    if "session_index" in labels.columns and graph_df["session_index"].notna().all():
        merged = pd.merge(graph_df, labels, on="session_index", how="inner")
    else:
        merged = pd.merge(graph_df, labels, on="start", how="inner")

    if merged.empty:
        raise SystemExit("failed to align graphs with labels; provide session_index or start columns")

    return list(zip(merged["_graph_obj"], merged["label"]))


def to_pyg_data(graph_item: Dict[str, object], label_id: int) -> Data:
    """Convert a NetworkX provenance graph into a PyG Data object."""
    graph = graph_item["graph"]
    node_ids = list(graph.nodes())
    node_map = {node_id: index for index, node_id in enumerate(node_ids)}

    x = torch.tensor(
        [build_node_features(graph.nodes[node_id]) for node_id in node_ids],
        dtype=torch.float,
    )

    edge_pairs = [(node_map[source], node_map[target]) for source, target in graph.edges()]
    if edge_pairs:
        edge_index = torch.tensor(edge_pairs, dtype=torch.long).t().contiguous()
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long)

    return Data(
        x=x,
        edge_index=edge_index,
        y=torch.tensor(label_id, dtype=torch.long),
        session_index=int(graph_item.get("session_index") or -1),
    )


class ProvenanceGCN(nn.Module):
    """Simple graph classifier for provenance sessions."""

    def __init__(self, input_dim: int, hidden_dim: int, num_classes: int) -> None:
        super().__init__()
        self.conv1 = GCNConv(input_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        self.conv3 = GCNConv(hidden_dim, hidden_dim)
        self.lin = nn.Linear(hidden_dim, num_classes)

    def forward(self, data: Data) -> torch.Tensor:
        x, edge_index, batch = data.x, data.edge_index, data.batch
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=0.3, training=self.training)
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        x = self.conv3(x, edge_index)
        x = global_mean_pool(x, batch)
        x = F.dropout(x, p=0.3, training=self.training)
        return self.lin(x)


def main() -> None:
    args = parse_args()

    with open(args.graphs, "rb") as handle:
        raw_graphs = pickle.load(handle)
    labels = pd.read_csv(args.labels)
    aligned = merge_graphs_and_labels(raw_graphs, labels)

    label_encoder = LabelEncoder()
    encoded_labels = label_encoder.fit_transform([label for _, label in aligned])
    data_list = []
    filtered_labels: List[int] = []
    for (graph_item, _), label_id in zip(aligned, encoded_labels):
        data = to_pyg_data(graph_item, label_id)
        if data.x.size(0) == 0:
            continue
        data_list.append(data)
        filtered_labels.append(label_id)
    if not data_list:
        raise SystemExit("no graphs available for training")

    stratify = filtered_labels if len(set(filtered_labels)) > 1 else None
    train_data, test_data = train_test_split(
        data_list,
        test_size=0.3,
        random_state=42,
        stratify=stratify,
    )

    train_loader = DataLoader(train_data, batch_size=args.batch_size, shuffle=True)
    test_loader = DataLoader(test_data, batch_size=args.batch_size, shuffle=False)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = ProvenanceGCN(
        input_dim=data_list[0].x.size(1),
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
