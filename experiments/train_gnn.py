#!/usr/bin/env python3
"""
train_gnn.py
A template for GNN training. This file is a stub that outlines steps to convert process-tree graphs
into a format suitable for PyTorch Geometric. To run an actual GNN you need torch + torch_geometric installed
and to implement dataset-specific node/edge features.

This file intentionally does not execute training; it's a guide scaffold.
"""
import textwrap

print(textwrap.dedent("""
GNN Training Stub
-----------------
1) Install torch and torch_geometric (follow official installation instructions for your CUDA/Py versions).
2) Load dataset graphs saved by features/feature_builder.py (dataset/graphs.pkl).
3) For each graph:
   - convert networkx graph to torch_geometric.data.Data
   - build node features (e.g., one-hot of comm tokens, pid lifetime, write_bytes)
   - build edge index from directed edges
4) Create a PyG Dataset and DataLoader, then implement a GNN model (GCN/GraphSAGE/GAT).
5) Train with supervision (session-level label) or use pooling to aggregate node embeddings -> session embedding -> classifier.

This file is a placeholder. If you want I can expand this into runnable code for your environment (tell me whether you have GPU / torch versions).
"""))
