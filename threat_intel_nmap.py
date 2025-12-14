#!/usr/bin/env python3

"""
"""
Automated Threat Intelligence + Nmap Scanner
Author: Ikenna Ubadiniru + Kevin Maldonado
Course: Security Automation
"""


This script:
1. Downloads a public threat intelligence feed containing suspicious IPs.
2. Extracts the IPs using a simple regular expression.
3. Scans a few of those IPs using nmap.
4. Saves the results to text files.
5. Prints a short summary in the terminal.

This is a simple but real example of security automation.
"""

import requests          # For downloading the threat feed
import re                # For matching IP addresses
import subprocess        # To run nmap from Python
from datetime import datetime

# ---------------------
