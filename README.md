# OS-Monitor: Multi-Dimensional Runtime Security & Provenance Graph Framework

**OS-Monitor** 是一个针对 Linux 环境的\*\*内核级溯源图（Kernel-level Provenance Graph, KPG）\*\*构建与威胁检测框架。

本项目基于 **eBPF (Extended Berkeley Packet Filter)** 技术，实现了 **7个维度** 的全景数据采集（用户态+内核态），并包含一套完整的**图神经网络 (GNN)** 行为分析管道。该平台旨在解决传统单点检测（如仅监控文件哈希）无法应对“无文件攻击”、“慢速攻击”和“数据窃取”的问题，支持构建 **EBPF-7D-Security-Dataset** 数据集。

-----

## 📚 核心创新点 (Research Innovations)

本项目对应论文《Multi-Dimensional Runtime Security Monitoring and Provenance Graph Analysis via eBPF》的工程实现，包含以下核心特性：

1.  **7维度全景感知 (7-Dimensional eBPF Sensing)**:
    突破传统监控局限，通过 7 个定制 Agent 并发采集：

      * **Process**: 进程生命周期 (`fork`, `exec`, `exit`)。
      * **Memory**: 内存代码注入与权限变更 (`mprotect`, `process_vm_writev`)。
      * **Network**: TCP 连接状态 (`tcp_v4_connect`)。
      * **File I/O**: 敏感文件读写 (`openat`, `write`)。
      * **DNS**: 用户态域名查询语义 (`getaddrinfo`)。
      * **Kmod**: 内核模块加载 (`do_init_module`)。
      * **Syscall**: 高危系统调用序列 (`ptrace`, `setuid` 等)。

2.  **动态溯源图构建 (Provenance Graph Construction)**:
    利用 `graph_utils.py` 将离散的系统事件转化为有向图。通过进程派生关系（Parent-Child）和交互行为（Connect, Write），将攻击链路可视化、结构化，有效检测 APT 攻击和无文件攻击。

3.  **图神经网络检测 (GNN-based Detection)**:
    内置 GNN 训练管道 (`experiments/train_gnn_final.py`)，通过学习进程行为图的拓扑结构和节点语义（命令行、文件名、IP），实现对恶意会话的高精度分类。

-----

## 🛠 项目结构

```
os-monitor/
├── agent/                  # eBPF 采集层 (Kernel Probes/Tracepoints)
│   ├── process_agent.py    # 进程树基础
│   ├── memory_agent.py     # 内存注入检测 (关键创新)
│   ├── dns_agent.py        # 隐蔽隧道检测
│   └── ... (其他 4 个 Agent)
├── dataset/                # 数据集构建与攻击模拟
│   ├── simulate_attacks.py       # 基础攻击脚本
│   ├── advanced_attack_simulator.py # 高级攻击场景 (勒索、无文件、Rootkit)
│   ├── prepare_dataset.py        # 会话切分与清洗
│   └── loader.py                 # 真实样本投放工具
├── features/               # 特征工程层
│   ├── graph_utils.py      # 核心算法：事件流 -> NetworkX 图
│   └── feature_builder.py  # 图特征与统计特征提取
├── experiments/            # 模型训练与评估层
│   ├── train_baseline.py   # 基线模型 (RandomForest)
│   └── train_gnn_final.py  # 核心模型 (GCN/GraphSAGE)
├── run_dashboard.sh        # 实时监控仪表盘 (Multitail)
└── env_setup.sh            # 环境依赖安装
```

-----

## 🚀 快速开始 (实验复现流程)

**环境要求**: Linux Kernel 5.4+ (推荐 Ubuntu 20.04/22.04), Python 3.8+, Root 权限。

### 1\. 环境搭建

```bash
# 安装 BCC, Linux Headers, Python 依赖 (PyTorch, PyG, Pandas)
sudo bash env_setup.sh
```

### 2\. 数据采集 (Data Acquisition)

启动所有 Agent 进行数据收集。建议在隔离的虚拟机中运行。

```bash
# 方式 A: 启动后台采集 (推荐用于制作数据集)
sudo bash start_monitoring.sh

# 方式 B: 启动实时可视化仪表盘 (推荐用于调试)
sudo bash run_dashboard.sh
```

,

### 3\. 攻击模拟 (Attack Simulation)

在采集开启时，运行攻击脚本以生成恶意样本数据。

```bash
# 模拟复杂攻击场景：勒索软件、DNS隧道、内存注入
sudo python3 dataset/advanced_attack_simulator.py

# 或者运行特定基础攻击
sudo python3 dataset/simulate_attacks.py --attack forkbomb
```

,

*注：对于真实病毒样本，请使用 `dataset/loader.py` 并在断网沙箱中运行。*

### 4\. 数据处理与图构建 (Graph Construction)

采集完成后，停止监控 (`sudo bash stop_monitoring.sh`)，然后进行数据聚合与图转化。

```bash
# 1. 聚合分散的 JSONL 日志
python3 aggregator/collector.py --out file

# 2. 切分会话 (Sessionization)
# --input 指向日志目录, --out 输出原始会话
python3 dataset/prepare_dataset.py --input /var/log/os_monitor_log --out dataset/raw_sessions.pkl

# 3. 特征工程与构图 (关键步骤)
# 将会话转化为 Graph 对象，输出 dataset/graphs.pkl (用于 GNN) 和 features.parquet (用于 RF)
python3 features/feature_builder.py --infile dataset/raw_sessions.pkl --outfile dataset/features.parquet
```

,,

### 5\. 模型训练与评估 (Evaluation)

**训练图神经网络 (GNN):**
这实现了论文中的图分类算法。需先准备 `dataset/labels.csv` (格式: `session_index,label`)。

```bash
python3 experiments/train_gnn_final.py --graphs dataset/graphs.pkl --labels dataset/labels.csv
```

**基线对比 (Random Forest):**

```bash
python3 experiments/train_baseline.py --features dataset/features.parquet --labels dataset/labels.csv
```

-----

## 📊 数据集 (Dataset)

本框架支持生成 **EBPF-7D-Security-Dataset**，包含以下几类数据：

1.  **Benign**: 编译内核、Web 浏览、文件压缩等正常背景噪声。
2.  **Ransomware**: 模拟 LockBit/WannaCry 的文件遍历与加密行为。
3.  **Fileless**: 内存执行 (Memory Execution) 与代码注入。
4.  **Exfiltration**: DNS 隐蔽隧道数据外传。

-----

## ⚠️ 免责声明

本工具包含具有攻击性的模拟脚本 (`dataset/advanced_attack_simulator.py`) 和内核级监控功能。**严禁在生产环境或未授权的系统上运行。** 开发者不对因使用本工具造成的任何损坏负责。请仅在隔离的测试环境中使用。