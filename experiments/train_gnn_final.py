#!/usr/bin/env python3
"""
experiments/train_gnn_final.py
基于图神经网络 (GNN) 的进程行为图分类器。
实现了论文中提到的 "Process Behavior Graph" 分析算法。

Usage:
    python3 experiments/train_gnn_final.py --graphs dataset/graphs.pkl --labels dataset/labels.csv
"""

import argparse
import pickle
import pandas as pd
import numpy as np
import torch
import torch.nn.functional as F
from torch_geometric.data import Data, DataLoader
from torch_geometric.nn import GCNConv, global_mean_pool
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import LabelEncoder

# --- 1. 参数配置 ---
parser = argparse.ArgumentParser()
parser.add_argument('--graphs', required=True, help='Path to dataset/graphs.pkl')
parser.add_argument('--labels', required=True, help='Path to labels.csv (start,label)')
parser.add_argument('--epochs', type=int, default=50)
parser.add_argument('--batch_size', type=int, default=32)
parser.add_argument('--hidden_dim', type=int, default=64)
parser.add_argument('--lr', type=float, default=0.01)
args = parser.parse_args()

# --- 2. 数据加载与预处理 ---
print("[*] Loading graphs from", args.graphs)
with open(args.graphs, 'rb') as f:
    raw_graphs_list = pickle.load(f)  # List of dicts: {'session_index': int, 'graph': nx.DiGraph}

print("[*] Loading labels from", args.labels)
# labels.csv 必须包含 'session_index' 或通过 'start' 时间匹配。
# 这里假设 labels.csv 有一列 'session_index' 和 'label'，或者你需要手动将 labels 和 graphs 对应起来。
# 为了简化，我们假设 labels.csv 的行顺序与 graphs.pkl 的列表顺序一致 (0 to N)。
try:
    df_labels = pd.read_csv(args.labels)
    y_all = df_labels['label'].values
except Exception as e:
    print(f"[!] Error loading labels: {e}")
    exit(1)

if len(y_all) != len(raw_graphs_list):
    print(f"[!] Warning: Label count {len(y_all)} != Graph count {len(raw_graphs_list)}. Truncating to min.")
    min_len = min(len(y_all), len(raw_graphs_list))
    y_all = y_all[:min_len]
    raw_graphs_list = raw_graphs_list[:min_len]

# --- 3. 特征工程: 将 NetworkX 图转换为 PyG Data 对象 ---

# 构建命令词汇表 (用于将 comm 字符串转为 One-Hot/Embedding)
all_comms = set()
for item in raw_graphs_list:
    G = item['graph']
    for node_id, node_data in G.nodes(data=True):
        comm = node_data.get('comm', 'unknown')
        if comm:
            all_comms.add(comm)

# 使用 LabelEncoder 将 comm 映射为数字
comm_encoder = LabelEncoder()
comm_encoder.fit(list(all_comms))
num_node_features = len(comm_encoder.classes_)
print(f"[*] Unique process commands (Node Features Dim): {num_node_features}")

data_list = []
for i, item in enumerate(raw_graphs_list):
    G = item['graph']
    label = int(y_all[i])
    
    # 3.1 构建节点特征矩阵 (x)
    # 简单的 One-Hot 编码：每一行是该进程 comm 的 one-hot 向量
    node_indices = list(G.nodes())
    node_map = {n: i for i, n in enumerate(node_indices)} # NetworkX node ID -> 0..N index
    
    x_features = []
    for node in node_indices:
        comm = G.nodes[node].get('comm', 'unknown')
        # Handle unseen labels carefully if strictly needed, here assumes closed set or 'unknown' handling
        try:
            comm_idx = comm_encoder.transform([comm])[0]
        except:
            comm_idx = 0 # fallback
        
        # Create one-hot vector
        vec = [0.0] * num_node_features
        vec[comm_idx] = 1.0
        x_features.append(vec)
    
    x = torch.tensor(x_features, dtype=torch.float)
    
    # 3.2 构建边索引 (edge_index)
    edge_sources = []
    edge_targets = []
    for u, v in G.edges():
        edge_sources.append(node_map[u])
        edge_targets.append(node_map[v])
    
    edge_index = torch.tensor([edge_sources, edge_targets], dtype=torch.long)
    
    # 3.3 封装为 PyG Data
    # 即使是孤立节点图也可以处理
    if x.size(0) == 0:
        continue # Skip empty graphs
        
    data = Data(x=x, edge_index=edge_index, y=torch.tensor([label], dtype=torch.long))
    data_list.append(data)

print(f"[*] Created {len(data_list)} PyG graph objects.")

# --- 4. 数据集划分 ---
train_data, test_data = train_test_split(data_list, test_size=0.3, random_state=42)
train_loader = DataLoader(train_data, batch_size=args.batch_size, shuffle=True)
test_loader = DataLoader(test_data, batch_size=args.batch_size, shuffle=False)

# --- 5. GNN 模型定义 (GCN) ---
class ProcessGCN(torch.nn.Module):
    def __init__(self, input_dim, hidden_dim, num_classes):
        super(ProcessGCN, self).__init__()
        # Graph Convolution Layers
        self.conv1 = GCNConv(input_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        self.conv3 = GCNConv(hidden_dim, hidden_dim)
        # Linear Classifier
        self.lin = torch.nn.Linear(hidden_dim, num_classes)

    def forward(self, data):
        x, edge_index, batch = data.x, data.edge_index, data.batch
        
        # 1. 节点嵌入学习 (Node Embeddings)
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=0.5, training=self.training)
        
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        
        x = self.conv3(x, edge_index)
        
        # 2. 图读出/池化 (Readout): 将节点特征聚合为图特征
        # global_mean_pool 将属于同一个图的所有节点特征取平均
        x = global_mean_pool(x, batch)  # [batch_size, hidden_dim]
        
        # 3. 分类
        x = F.dropout(x, p=0.5, training=self.training)
        x = self.lin(x)
        
        return F.log_softmax(x, dim=1)

# --- 6. 训练与评估循环 ---
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model = ProcessGCN(input_dim=num_node_features, hidden_dim=args.hidden_dim, num_classes=2).to(device)
optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=5e-4)

print(f"[*] Starting training on {device} for {args.epochs} epochs...")

for epoch in range(args.epochs):
    model.train()
    total_loss = 0
    for batch in train_loader:
        batch = batch.to(device)
        optimizer.zero_grad()
        out = model(batch)
        loss = F.nll_loss(out, batch.y)
        loss.backward()
        optimizer.step()
        total_loss += loss.item()
    
    if (epoch + 1) % 10 == 0:
        print(f"Epoch {epoch+1}/{args.epochs}, Loss: {total_loss / len(train_loader):.4f}")

# --- 7. 测试集评估 ---
model.eval()
y_true = []
y_pred = []
y_probs = []

with torch.no_grad():
    for batch in test_loader:
        batch = batch.to(device)
        out = model(batch)
        pred = out.argmax(dim=1)
        prob = torch.exp(out)[:, 1] # Probability of class 1
        
        y_true.extend(batch.y.cpu().numpy())
        y_pred.extend(pred.cpu().numpy())
        y_probs.extend(prob.cpu().numpy())

print("\n--- Evaluation Report ---")
print(classification_report(y_true, y_pred, target_names=['Benign', 'Malicious']))
try:
    auc = roc_auc_score(y_true, y_probs)
    print(f"ROC-AUC Score: {auc:.4f}")
except Exception:
    pass