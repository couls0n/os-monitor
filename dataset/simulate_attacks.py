#!/usr/bin/env python3
"""
simulate_attacks.py
Generates a set of attack scripts that run in an isolated VM. These scripts aim to create
observable OS behaviors: fork bombs (high process churn), ransomware-like bulk file writes,
command injection, and simple scanning.

USAGE: run individual functions only inside an isolated VM. Do NOT run on production.
"""
import os
import argparse
import time
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--attack', choices=['forkbomb','ransom','slow-breach','scan'], required=True)
args = parser.parse_args()

def do_forkbomb():
    print("[*] starting controlled forkbomb (short-lived children)")
    for i in range(1000):
        pid = os.fork()
        if pid == 0:
            # child
            os.execvp('bash', ['bash', '-c', 'sleep 0.01; exit'])
        else:
            time.sleep(0.005)
    print("[*] forkbomb finished")

def do_ransom():
    testdir = '/tmp/testfiles_ransom'
    os.makedirs(testdir, exist_ok=True)
    print("[*] creating test files")
    for i in range(200):
        fname = os.path.join(testdir, f'f{i}.txt')
        with open(fname, 'w') as f:
            f.write('A'*10000)
    print("[*] encrypting files (openssl required)")
    for fpath in os.listdir(testdir):
        full = os.path.join(testdir, fpath)
        out = full + '.enc'
        # call openssl (installed in VM)
        subprocess.call(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt", "-in", full, "-out", out, "-k", "password"])
        time.sleep(0.01)
    print("[*] ransomware simulation finished")

def do_slow_breach():
    print("[*] starting slow stealthy behavior")
    for i in range(50):
        open(f"/tmp/slow_attack_{i}", "w").close()
        time.sleep(5)
    print("[*] slow breach finished")

def do_scan():
    print("[*] running nmap scan (requires nmap installed)")
    subprocess.call(["nmap", "-sS", "192.168.1.0/24", "-oN", "/tmp/nmap_scan.txt"])
    print("[*] scan finished")

if args.attack == 'forkbomb':
    do_forkbomb()
elif args.attack == 'ransom':
    do_ransom()
elif args.attack == 'slow-breach':
    do_slow_breach()
elif args.attack == 'scan':
    do_scan()
else:
    print("unknown attack")
    sys.exit(1)
