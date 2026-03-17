# OS-Monitor: Multi-Dimensional Runtime Security & Provenance Graph Framework

**OS-Monitor** 是一个针对 Linux 环境的\*\*内核级溯源图（Kernel-level Provenance Graph, KPG）\*\*构建与威胁检测框架。

本项目基于 **eBPF (Extended Berkeley Packet Filter)** 技术，实现了 **7个维度** 的全景数据采集（用户态+内核态），并补齐了**滑动时间窗口特征工程 + 用户态实时阻断**闭环。当前代码既支持离线构建 **EBPF-7D-Security-Dataset** 数据集，也支持在运行中按 PID 做短窗口行为聚合，并在满足阈值时进入告警/阻断流程。

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
    内置 GNN 训练管道 (`experiments/train_gnn_final.py`)，通过学习多维 Provenance Graph 的拓扑结构和节点语义（命令、文件、IP、DNS、内存、模块等），实现对恶意会话的分类。

4.  **实时检测与阻断 (Real-time Detection & Blocking)**:
    新增 `detector/realtime_blocker.py`，对 7 个 Agent 的 JSONL 流做 100ms/500ms 级别滑窗聚合，可基于文件突增、序列模式、可执行内存模式、DNS 突发等规则实时告警，并在 `block` 模式下直接终止可疑进程。

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
│   ├── prepare_dataset.py        # 滑动时间窗口切分
│   └── loader.py                 # 真实样本投放工具
├── detector/               # 实时检测与阻断
│   └── realtime_blocker.py # 按 PID 滑窗特征计算并可即时 kill
├── features/               # 特征工程层
│   ├── graph_utils.py      # 核心算法：事件流 -> Provenance Graph
│   └── feature_builder.py  # 序列特征、资源特征与图特征提取
├── experiments/            # 模型训练与评估层
│   ├── train_baseline.py   # 基线模型 (RandomForest)
│   └── train_gnn_final.py  # 核心模型 (GCN/GraphSAGE)
├── run_dashboard.sh        # 实时监控仪表盘 (Multitail + alerts)
└── env_setup.sh            # 环境依赖安装
```

-----

## 🚀 快速开始 (实验复现流程)

**环境要求**: Linux Kernel 5.4+ (推荐 Ubuntu 20.04/22.04), Python 3.8+, Root 权限。

### 极简工作流

如果你在 Ubuntu 上希望尽量少记命令，推荐直接使用统一入口 `os_monitor.py`：

```bash
# 1) 一条命令启动监控栈
sudo python3 os_monitor.py up --mode detect

# 2) 一条命令启动并直接打开仪表盘
sudo python3 os_monitor.py watch --mode block

# 3) 一条命令完成：启动 -> 跑高级攻击场景 -> 停止 -> 自动构建特征
sudo python3 os_monitor.py quick --scenario advanced --mode block --build

# 4) 一条命令完成：启动 -> 跑指定攻击 -> 停止 -> 自动构建特征
sudo python3 os_monitor.py quick --scenario attack --attack ransom --mode detect --build

# 5) 查看状态 / 停止
python3 os_monitor.py status
sudo python3 os_monitor.py down
```

`quick` 命令默认会把旧日志归档后再开始新一轮运行，适合做数据集采集和复现实验。

### 1\. 环境搭建

```bash
# 安装 BCC, Linux Headers, Python 依赖 (PyTorch, PyG, Pandas)
sudo bash env_setup.sh
```

### 2\. 数据采集 (Data Acquisition)

启动所有 Agent 进行数据收集。建议在隔离的虚拟机中运行。

```bash
# 方式 A: 推荐，统一入口启动后台采集 + detect 模式实时分析
sudo python3 os_monitor.py up --mode detect

# 方式 B: 启动后台采集 + block 模式即时阻断
sudo python3 os_monitor.py up --mode block

# 方式 C: 启动实时可视化仪表盘 (推荐用于调试)
sudo python3 os_monitor.py watch --mode detect
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

采集完成后，停止监控 (`sudo python3 os_monitor.py down`)，然后进行数据聚合与图转化。

```bash
# 1. 聚合分散的 JSONL 日志
python3 aggregator/collector.py --out file

# 2. 切分滑动窗口 (Sessionization)
# 默认 500ms 窗口 / 250ms 步长；也可改成 100ms / 50ms
python3 dataset/prepare_dataset.py --input /var/log/os_monitor_log --out dataset/raw_sessions.pkl --window-ms 500 --stride-ms 250

# 3. 特征工程与构图 (关键步骤)
# 将会话转化为 Graph 对象，输出 dataset/graphs.pkl (用于 GNN) 和 features.parquet (用于 RF)
python3 features/feature_builder.py --infile dataset/raw_sessions.pkl --outfile dataset/features.parquet --graphs-out dataset/graphs.pkl
```

也可以直接用统一入口离线构建：

```bash
python3 os_monitor.py build --input /var/log/os_monitor_log --out-dir runs/manual_build
```

,,

### 5\. 模型训练与评估 (Evaluation)

**训练图神经网络 (GNN):**
需先准备 `dataset/labels.csv` (推荐格式: `session_index,label`)。

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
