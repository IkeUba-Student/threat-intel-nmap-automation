from typing import List, Tuple
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from ipaddress import ip_address

import requests

# -----------------------------
# Settings (keep these simple)
# -----------------------------

FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

# If the online feed fails (403), you can put IPs in this local file and the script will use it.
LOCAL_FEED_FALLBACK = "local_feed.txt"

# Keep this small for class demos
MAX_IPS_TO_SCAN = 5

# Output folder
OUTPUT_DIR = Path("scan_reports")


# -----------------------------
# Helper functions
# -----------------------------

def ensure_nmap_installed() -> None:
    """Check that nmap exists before we try to run scans."""
    nmap_path = shutil.which("nmap")
    if nmap_path is None:
        print("[!] Nmap is not installed or not on PATH.")
        print("    Install it on Ubuntu with:")
        print("    sudo apt update && sudo apt install nmap -y")
        raise SystemExit(1)
    print(f"[*] Nmap found: {nmap_path}")


def fetch_threat_feed(url: str) -> str:
    """
    Download threat feed text from the internet.
    Adds a simple User-Agent header because some sites block blank/unknown clients.
    """
    headers = {"User-Agent": "Mozilla/5.0 (StudentSecurityAutomationProject)"}
    resp = requests.get(url, headers=headers, timeout=20)
    resp.raise_for_status()
    return resp.text


def load_feed_text() -> str:
    """
    Try online feed first. If it fails, try a local fallback file.
    """
    print(f"[*] Downloading threat feed from: {FEED_URL}")
    try:
        return fetch_threat_feed(FEED_URL)
    except Exception as e:
        print(f"[!] Online feed failed: {e}")
        fallback_path = Path(LOCAL_FEED_FALLBACK)
        if fallback_path.exists():
            print(f"[*] Using local fallback feed file: {LOCAL_FEED_FALLBACK}")
            return fallback_path.read_text(encoding="utf-8", errors="ignore")
        else:
            print("[!] No local fallback feed file found.")
            print(f"    Create a file named '{LOCAL_FEED_FALLBACK}' with one IP per line.")
            raise SystemExit(1)


def extract_ipv4s(feed_text: str) -> List[str]:
    """
    Extract IP addresses from the feed text.
    This does:
    - regex find for IPv4-looking strings
    - basic validation using ipaddress.ip_address
    - de-duplicate while preserving order
    """
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    candidates = re.findall(ip_pattern, feed_text)

    unique_valid_ips: list[str] = []
    seen = set()

    for ip_str in candidates:
        if ip_str in seen:
            continue
        # validate
        try:
            parsed = ip_address(ip_str)
            # Only keep IPv4 (ip_address can parse IPv6 too if present)
            if parsed.version == 4:
                unique_valid_ips.append(ip_str)
                seen.add(ip_str)
        except ValueError:
            # Skip invalid IP like 999.999.999.999
            continue

    return unique_valid_ips


def run_nmap_scan(ip: str) -> str:
    """
    Run nmap scan for one IP.
    -sV: service detection
    -T4: faster timing
    -Pn: skip ping discovery (useful if ping blocked)
    """
    cmd = ["nmap", "-sV", "-T4", "-Pn", ip]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")


def parse_open_ports(nmap_output: str) -> list[str]:
    """
    Extract lines like: '22/tcp open ssh ...'
    Very simple parse: look for lines containing '/tcp' or '/udp' and ' open '
    """
    open_lines = []
    for line in nmap_output.splitlines():
        line_stripped = line.strip()
        if ("/tcp" in line_stripped or "/udp" in line_stripped) and " open " in line_stripped:
            open_lines.append(line_stripped)
    return open_lines


def save_scan(ip: str, output: str) -> Path:
    """Save scan output into scan_reports/scan_<ip>.txt"""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    file_path = OUTPUT_DIR / f"scan_{ip.replace('.', '_')}.txt"
    file_path.write_text(output, encoding="utf-8", errors="ignore")
    return file_path


# -----------------------------
# Main
# -----------------------------

def main() -> None:
    print("[*] Starting Automated Threat Intelligence + Nmap Scanner")
    print(f"[*] Time: {datetime.now()}")

    ensure_nmap_installed()

    feed_text = load_feed_text()

    print("[*] Extracting IPs from threat feed...")
    ips = extract_ipv4s(feed_text)
    print(f"[*] Found {len(ips)} unique valid IPv4 addresses.")

    if not ips:
        print("[!] No valid IPs found. Exiting.")
        return

    ips_to_scan = ips[:MAX_IPS_TO_SCAN]
    print(f"[*] Scanning first {len(ips_to_scan)} IPs (limit = {MAX_IPS_TO_SCAN}):")
    for ip in ips_to_scan:
        print(f"    - {ip}")

    summary: list[tuple[str, list[str], Path]] = []

    for ip in ips_to_scan:
        print(f"\n[*] Running nmap on {ip} ...")
        out = run_nmap_scan(ip)
        report_path = save_scan(ip, out)
        open_ports = parse_open_ports(out)
        summary.append((ip, open_ports, report_path))

    print("\n==================== SUMMARY ====================")
    for ip, open_ports, report_path in summary:
        print(f"\nIP: {ip}")
        print(f"Saved report: {report_path}")
        if open_ports:
            print("Open ports:")
            for line in open_ports:
                print(f"  - {line}")
        else:
            print("No open ports detected (or host did not respond).")
    print("=================================================")

    print(f"\n[*] Done. Full reports are in: {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
