#!/usr/bin/env python3
"""
metadata_writer.py
Write host/environment metadata to the log dir to help reproducibility.
"""
import platform
import subprocess
import json
import os

OUT_DIR = "/var/log/os_monitor"
os.makedirs(OUT_DIR, exist_ok=True)
OUT_FILE = os.path.join(OUT_DIR, "metadata.json")

def gather():
    meta = {}
    meta['uname'] = platform.uname()._asdict()
    try:
        dpkg = subprocess.check_output(['dpkg','-l']).decode('utf-8', errors='ignore')
        meta['packages_head'] = '\n'.join(dpkg.splitlines()[:50])
    except Exception:
        meta['packages_head'] = ''
    try:
        with open('/proc/version', 'r') as f:
            meta['proc_version'] = f.read().strip()
    except Exception:
        meta['proc_version'] = ''
    return meta

def write():
    meta = gather()
    with open(OUT_FILE, 'w') as f:
        json.dump(meta, f, indent=2)
    print("wrote metadata to", OUT_FILE)

if __name__ == "__main__":
    write()
