# OS Monitor Research - Quickstart

This project provides a reproducible pipeline for OS-level behavior data collection (eBPF/BCC),
dataset generation, feature extraction, and baseline experiments. Use only in isolated VMs.

Quick start:
1. Prepare VM snapshot.
2. Copy files into the workspace preserving paths (agent/, aggregator/, dataset/, features/, experiments/, tools/).
3. Run `sudo bash env_setup.sh`.
4. Start collectors:
   sudo python3 agent/process_agent.py &
   sudo python3 agent/file_agent.py &
   sudo python3 agent/net_agent.py &
5. Generate data (normal workloads + attacks via dataset/simulate_attacks.py in isolated VM).
6. Aggregate logs: python3 aggregator/collector.py --out file
7. Prepare sessions: python3 dataset/prepare_dataset.py --input /var/log/os_monitor --out dataset/raw_sessions.pkl
8. Build features: python3 features/feature_builder.py --infile dataset/raw_sessions.pkl --outfile dataset/features.parquet
9. Prepare labels (labels.csv) and train baseline: python3 experiments/train_baseline.py --features dataset/features.parquet --labels dataset/labels.csv
# os-monitor
# os-monitor
# os-monitor
# os-monitor
# os-monitor
# os-monitor
# os-monitor
# os-monitor
# os-monitor
