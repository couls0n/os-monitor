#!/bin/bash
set -e
sudo apt update
sudo apt install -y build-essential clang llvm libelf-dev linux-headers-$(uname -r) git python3 python3-pip python3-venv docker.io multitail
# bcc dependencies
sudo apt install -y bpfcc-tools python3-bpfcc linux-tools-$(uname -r)
python3 -m pip install --upgrade pip setuptools wheel
pip3 install -r requirements.txt

if [ "${INSTALL_GNN:-1}" = "1" ]; then
  pip3 install -r requirements-gnn.txt
fi
