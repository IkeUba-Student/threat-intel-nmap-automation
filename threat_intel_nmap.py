#!/usr/bin/env python3

"""
Automated Threat Intelligence + Nmap Scanner
Course: Security Automation

This script demonstrates basic security automation by
running Nmap scans against authorized internal targets.
"""

import subprocess
from datetime import datetime

==============================
CONFIGURATION
==============================
Authorized internal target (Ubuntu VM)
targets = ["192.168.40.130"] # replace if needed

Nmap scan options
nmap_args = ["nmap", "-Pn", "-sC", "-sV"]

Output file
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
output_file = f"nmap_results_{timestamp}.txt"

==============================
MAIN LOGIC
==============================
print("[+] Starting automated Nmap scan")

with open(output_file, "w") as f:
for target in targets:
print(f"[+] Scanning target: {target}")
f.write(f"\n===== Scan Results for {target} =====\n")

    result = subprocess.run(
        nmap_args + [target],
        capture_output=True,
        text=True
    )

    print(result.stdout)
    f.write(result.stdout)
print(f"[+] Scan complete. Results saved to {output_file}")
