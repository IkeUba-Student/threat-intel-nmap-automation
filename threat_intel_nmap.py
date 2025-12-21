#!/usr/bin/env python3

"""
Automated Threat Intelligence + Nmap Scanner
Course: Security Automation

This script demonstrates basic security automation by
running Nmap scans against authorized internal targets.
"""

import subp#!/usr/bin/env python3
"""
Automated Threat Intelligence + Nmap Scanner
Course: Security Automation

This script demonstrates basic security automation by running Nmap scans
against authorized internal targets and saving results to a timestamped file.
"""

from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path
from typing import List


# ==============================
# CONFIGURATION
# ==============================
# Authorized internal target (Ubuntu VM)
TARGETS: List[str] = ["192.168.40.130"]  # Replace if needed

# Nmap scan options
NMAP_ARGS: List[str] = ["nmap", "-Pn", "-sC", "-sV"]

# Output directory (optional but cleaner)
OUTPUT_DIR = Path(".")


def build_output_file() -> Path:
    """Create a timestamped output file path for scan results."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return OUTPUT_DIR / f"nmap_results_{timestamp}.txt"


def run_scan(target: str) -> subprocess.CompletedProcess[str]:
    """
    Run an Nmap scan against a single authorized target.

    Returns:
        subprocess.CompletedProcess: The completed process including stdout/stderr.
    """
    return subprocess.run(
        NMAP_ARGS + [target],
        capture_output=True,
        text=True,
        check=False,
    )


def main() -> None:
    """Run scans for all targets and write results to a timestamped output file."""
    output_file = build_output_file()

    print("[+] Starting automated Nmap scan")

    with output_file.open("w", encoding="utf-8") as file_handle:
        for target in TARGETS:
            print(f"[+] Scanning target: {target}")
            file_handle.write(f"\n===== Scan Results for {target} =====\n")

            result = run_scan(target)

            if result.stdout:
                print(result.stdout)
                file_handle.write(result.stdout)

            if result.stderr:
                file_handle.write("\n----- STDERR -----\n")
                file_handle.write(result.stderr)

    print(f"[+] Scan complete. Results saved to {output_file}")


if __name__ == "__main__":
    main()
rocess
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
