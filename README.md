# OS Monitor (7 维度 eBPF 采集平台)

本项目是一个全面的、基于 eBPF/BCC 的操作系统级别行为监控与分析管道。它旨在从隔离的 VM 中采集多维度数据，用于安全研究、高级威胁检测和机器学习。

此增强版包括一个 7 维度的采集系统和一个由 `multitail` 驱动的高性能实时仪表盘。

## 核心特性

  * **7 维度 eBPF 采集**: 并发监控 7 个维度的系统事件：
    1.  **进程**: `exec`, `fork`, `exit` 事件。
    2.  **文件 I/O**: `openat`, `write` 事件。
    3.  **网络**: TCP 连接 (`tcp_v4_connect`)。
    4.  **DNS**: 用户态 `getaddrinfo` 域名查询。
    5.  **内核模块**: `do_init_module` (Rootkit 检测)。
    6.  **内存**: `mprotect` (PROT\_EXEC) 和 `process_vm_writev` (注入检测)。
    7.  **可疑系统调用**: `ptrace`, `setuid`, `bpf` 等高风险调用。
  * **高性能实时仪表盘**: 使用 `multitail` 在终端中实现的高性能、不卡顿的分屏日志监控。
  * **机器学习管道**: 包含数据聚合、会话切分、图特征工程 和基线模型训练。
  * **攻击模拟**: 包含用于生成测试数据的攻击脚本 (`forkbomb`, `ransom` 等)。

## 项目结构

```
os-monitor/
├── agent/                # 7 个 eBPF 采集器
│   ├── process_agent.py
│   ├── file_agent.py
│   ├── net_agent.py
│   ├── dns_agent.py
│   ├── kmod_agent.py
│   ├── memory_agent.py
│   └── syscall_agent.py
├── aggregator/           # 日志聚合脚本
│   └── collector.py
├── dataset/              # 数据集处理与攻击模拟
│   ├── prepare_dataset.py
│   └── simulate_attacks.py
├── features/             # 特征工程 (含图构建)
│   ├── feature_builder.py
│   └── graph_utils.py
├── experiments/          # 机器学习实验
│   ├── train_baseline.py
│   └── train_gnn.py
├── tools/
│   └── visualize_tree.py
├── run_dashboard.sh      # (新) 一键启动采集器和 multitail 仪表盘
├── start_monitoring.sh   # 仅启动 7 个 Agent
├── stop_monitoring.sh    # 一键停止所有 Agent 和仪表盘
├── env_setup.sh          # 环境安装脚本
├── requirements.txt      # (新) Python 依赖
└── README.md             # 本文件
```

*(注意: `run_dashboard.sh` 脚本应从 `agent/` 目录移动到项目根目录，以便与 `start_monitoring.sh` 一起使用)*

## 1\. 安装

**警告：仅在隔离的 VM（建议快照）上运行。**

1.  **安装系统依赖 (BPF/BCC, Kernel Headers, Python)**：
    (此脚本会安装 `bpfcc-tools`, `python3-pip`, `linux-headers` 等)

    ```bash
    sudo bash env_setup.sh
    ```

    *注意：`multitail` 依赖会由 `run_dashboard.sh` 自动安装。*

2.  **安装 Python 依赖 (ML 管道)**：
    (此命令将安装 `pandas`, `sklearn`, `networkx` 等)

    ```bash
    pip3 install -r requirements.txt
    ```

## 2\. 如何运行

### 流程 A: 实时仪表盘 (推荐)

这是验证 Agent 是否正常工作，并实时监控系统的最快方式。

**1. 一键启动**
此脚本会自动检查 `multitail`，启动所有 7 个 Agent，并打开仪表盘。

```bash
sudo bash run_dashboard.sh
```

*您的终端将变为一个分屏的实时仪表盘。*

**2. (可选) 生成测试数据**
打开**第 2 个终端**，运行攻击模拟脚本，观察仪表盘的实时变化：

```bash
# 触发进程、网络和 DNS
ping -c 1 google.com
curl http://example.com

# 模拟勒索软件行为 (大量文件 I/O)
sudo python3 dataset/simulate_attacks.py --attack ransom
```

**3. 停止采集**

  * 在仪表盘终端（终端 1）按 `q` 键退出 `multitail`。
  * 运行 `stop_monitoring.sh` 停止所有后台 Agent 进程：
    ` bash     sudo bash stop_monitoring.sh      `

### 流程 B: 机器学习 (ML) 管道

此流程用于生成特征集以训练模型。

**重要提示**: 原始的 `aggregator/collector.py` 和 `dataset/prepare_dataset.py` 脚本**必须**被修改。它们指向旧的日志目录 (`/var/log/os_monitor`)。

**在运行前，请确保将这两个文件中指向日志目录的变量修改为:**
`LOG_DIR = "/var/log/os_monitor_log"`

**1. 采集数据**
(见上文流程 A 的步骤 1)

```bash
# (或者，如果您不需要看仪表盘，只在后台收集)
sudo bash start_monitoring.sh

# ... (运行模拟攻击, 产生日志) ...

sudo bash stop_monitoring.sh
```

**2. 聚合日志**
(确保已修改 `collector.py` 中的 `LOG_DIR` 路径)

```bash
python3 aggregator/collector.py --out file
```

*这将从 `/var/log/os_monitor_log` 读取所有 `.jsonl` 文件，并输出一个聚合日志文件 (例如 `logs/aggregated_....jsonl`)。*

**3. 准备会话 (Session)**
(确保已修改 `prepare_dataset.py` 中的 `default` input 路径)

```bash
python3 dataset/prepare_dataset.py --input /var/log/os_monitor_log --out dataset/raw_sessions.pkl
```

*这将把事件流按 60 秒窗口切分为会话，输出 `dataset/raw_sessions.pkl`。*

**4. 构建特征**
此脚本会读取 `raw_sessions.pkl`，计算统计特征和图特征 (进程树)。

```bash
python3 features/feature_builder.py --infile dataset/raw_sessions.pkl --outfile dataset/features.parquet
```

**5. 训练模型**
您需要一个 `labels.csv` 文件 (需手动创建)，该文件包含会话 `start` 时间戳和对应的 `label` (0=良性, 1=恶意)。

```bash
python3 experiments/train_baseline.py --features dataset/features.parquet --labels dataset/labels.csv
```

*这将训练一个随机森林模型并输出分类报告。*

```
```