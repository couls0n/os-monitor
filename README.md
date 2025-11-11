# OS Monitor Research (增强版)

本项目是一个全面的、基于 eBPF/BCC 的操作系统级别行为监控与分析管道。它旨在从隔离的 VM 中采集多维度数据，用于安全研究、攻击检测和机器学习。

**此增强版包括一个 7 维度的采集系统和一个实时 Web 仪表盘。**

## 核心特性

  * **多维度 eBPF 采集**: 并发监控 7 个维度的系统事件：
    1.  **进程**: `exec`, `fork`, `exit` 事件。
    2.  **文件 I/O**: `openat`, `write` 事件。
    3.  **网络**: TCP 连接 (`tcp_v4_connect`)。
    4.  **DNS**: 用户态 `getaddrinfo` 域名查询。
    5.  **内核模块**: `do_init_module` (Rootkit 检测)。
    6.  **内存**: `mprotect` (PROT\_EXEC) 和 `process_vm_writev` (注入检测)。
    7.  **可疑系统调用**: `ptrace`, `setuid`, `bpf` 等高风险调用。
  * **实时仪表盘**: 一个 Flask-SocketIO 服务器 (`dashboard_server.py`)，通过 `templates/index.html` 在浏览器中实时显示所有 7 个 Agent 的数据流。
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
├── templates/            # Web 仪表盘前端
│   └── index.html
├── dashboard_server.py   # Web 仪表盘后端
├── start_monitoring.sh   # 一键启动所有 Agent
├── stop_monitoring.sh    # 一键停止所有 Agent
├── env_setup.sh          # 环境安装脚本
└── README.md             # 本文件
```

## 1\. 安装

**警告：仅在隔离的 VM（建议快照）上运行。**

1.  **安装 BPF/BCC 和基础依赖**：
    (此脚本会安装 bcc-tools, python3-pip, 内核头文件等)

    ```bash
    sudo bash env_setup.sh
    ```

2.  **安装仪表盘依赖**：
    (此项目使用 Flask, SocketIO 和 Watchdog 来实现实时仪表盘)

    ```bash
    pip3 install Flask flask-socketio watchdog
    ```

## 2\. 如何运行

### 流程 A: 实时仪表盘 (Dashboard)

这是验证 Agent 是否正常工作的最快方式。

**1. (终端 1) 启动所有 7 个 Agent**
Agent 必须以 `sudo` 运行，它们会将日志写入 `/var/log/os_monitor_log/`。

```bash
sudo bash start_monitoring.sh
```

**2. (终端 1) 授予日志读取权限**
由于日志是由 `root` 写入的，您需要允许您的普通用户（将运行仪表盘服务器的用户）读取它们。

```bash
# 允许其他用户进入 (x) 和读取 (r) 该目录
sudo chmod o+rx /var/log/os_monitor_log

# 允许其他用户读取 (r) 该目录下所有 .jsonl 文件
sudo chmod o+r /var/log/os_monitor_log/*.jsonl
```

*(注意: 如果您停止并重启 Agent，新创建的文件可能需要重新授权)*

**3. (终端 2) 启动仪表盘服务器**
此脚本**不需要** `sudo`。

```bash
python3 dashboard_server.py
```

您应该会看到服务器在 `http://127.0.0.1:5000` 上启动。

**4. 打开浏览器**
访问 `http://127.0.0.1:5000` 即可看到实时的数据流。

**5. (可选) 生成测试数据**
打开**第 3 个终端**，运行攻击模拟脚本，观察仪表盘的实时变化：

```bash
# 模拟勒索软件行为 (大量文件 I/O)
sudo python3 dataset/simulate_attacks.py --attack ransom

# 模拟 fork 炸弹 (大量进程事件)
sudo python3 dataset/simulate_attacks.py --attack forkbomb
```

**6. 停止采集**
完成测试后，在终端 1 中运行：

```bash
sudo bash stop_monitoring.sh
```

### 流程 B: 机器学习 (ML) 管道

此流程用于生成特征集以训练模型。

**重要提示**: 原始的 `aggregator/collector.py` 和 `dataset/prepare_dataset.py` 脚本可能仍指向旧的日志目录 (`/var/log/os_monitor`)。

**在运行前，请确保将这两个文件中指向日志目录的变量修改为:**
`LOG_DIR = "/var/log/os_monitor_log"`

**1. 采集数据**
(见上文流程 A 的步骤 1)

```bash
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
# 假设 collector.py 输出到 logs/aggregated.jsonl
# 或者修改 prepare_dataset.py 以 glob 方式读取 /var/log/os_monitor_log
python3 dataset/prepare_dataset.py --input /var/log/os_monitor_log --out dataset/raw_sessions.pkl
```

*这将把事件流按 60 秒窗口切分为会话，输出 `dataset/raw_sessions.pkl`。*

**4. 构建特征**
此脚本会读取 `raw_sessions.pkl`，计算统计特征和图特征 (进程树)。

```bash
python3 features/feature_builder.py --infile dataset/raw_sessions.pkl --outfile dataset/features.parquet
```

**5. 训练模型**
您需要一个 `labels.csv` 文件 (需手动创建，或根据 `whattodo.txt` 中的提示编写自动标注脚本)，该文件包含会话 `start` 时间戳和对应的 `label` (0=良性, 1=恶意)。

```bash
python3 experiments/train_baseline.py --features dataset/features.parquet --labels dataset/labels.csv
```

*这将训练一个随机森林模型并输出分类报告。*