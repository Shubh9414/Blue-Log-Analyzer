# Blue Log Analyzer v1.0

[![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Active%20Development-green?style=for-the-badge)](https://github.com/Shubh9414/Blue-Log-Analyzer)

## 📝 Project Overview
[cite_start]**Blue Log** is a high-performance command-line tool designed for security analysts to automate the parsing and identification of suspicious activity across diverse log formats[cite: 156]. [cite_start]This tool was engineered to bridge the gap between raw telemetry and actionable intelligence, **reducing initial investigation time by an estimated 90%** through automated IOC enrichment[cite: 33, 158].

### Key Value Propositon
* [cite_start]**Rapid Triage:** Instantly flags brute-force attempts and sensitive path access, allowing analysts to focus on high-priority alerts[cite: 156, 161, 162].
* [cite_start]**Modular Architecture:** Built with an extensible framework to support new detection rules and log types with zero code changes[cite: 157, 160].
* [cite_start]**Automation Ready:** Supports JSON and CSV exports for seamless integration with SIEM platforms or custom SOAR playbooks[cite: 167, 168].

---

## Features & Parsers
[cite_start]Blue Log utilizes dedicated logic for each log type, driven by a centralized `config.json` for easy tuning[cite: 160, 164].

* [cite_start]**SSH Parser:** Detects potential brute-force attacks by tracking failed login thresholds from source IPs[cite: 161].
* [cite_start]**Apache Parser:** Flags 404 error spikes, unauthorized access to sensitive paths (e.g., `/admin`), and suspicious User-Agent strings (e.g., `sqlmap`)[cite: 162, 183].
* [cite_start]**Windows Event Parser:** Correlates critical Event IDs including **4625** (Failed Logon), **4740** (Account Lockout), and **4688** (Suspicious Process Creation)[cite: 163].

---

## Installation & Usage

### 1. Setup
```bash
git clone [https://github.com/Shubh9414/Blue-Log-Analyzer.git](https://github.com/Shubh9414/Blue-Log-Analyzer.git)
cd Blue-Log-Analyzer
pip install -r requirements.txt
