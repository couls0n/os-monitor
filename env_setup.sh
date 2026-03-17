#!/bin/bash
set -e
sudo apt update
sudo apt install -y build-essential clang llvm libelf-dev linux-headers-$(uname -r) git python3 python3-pip docker.io multitail
# bcc dependencies
sudo apt install -y bpfcc-tools python3-bpfcc linux-tools-$(uname -r)
python3 -m pip install --upgrade pip
pip3 install -r requirements.txt
