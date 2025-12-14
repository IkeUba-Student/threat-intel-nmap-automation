# Automated Threat Intelligence + Nmap Scanner

## Overview
This project is a simple security automation tool that gathers threat intelligence from an open-source feed and then automatically scans a small number of suspicious IP addresses using Nmap. The goal is to demonstrate how repetitive security tasks—such as checking threat feeds and running port scans—can be automated using Python on Ubuntu.

This project was intentionally built to be easy to understand for learning purposes. Each step is clearly commented inside the code.

---

## What the Tool Does
1. **Downloads a public threat intelligence feed** (no API key required).
2. **Extracts suspicious IP addresses** from the feed.
3. **Scans the first few IPs with Nmap** (`-sV -T4 -Pn` flags).
4. **Saves the scan results** to text files.
5. **Prints a simple summary** of open ports to the terminal.

This demonstrates real security automation in a beginner-friendly way.

---

## Technologies Used
- **Python 3**
- **Nmap**
- **Ubuntu Linux**
- Python libraries:
  - `requests`
  - `re`
  - `subprocess`
  - `datetime`

---

## File Structure
## Troubleshooting note
if you see “nmap: command not found” it is cause nmap wasnt installed.


## How to Run
```bash
python3 threat_intel_nmap.py

