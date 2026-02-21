# Blue Log Analyzer v1.0

[![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Active%20Development-green?style=for-the-badge)](https://github.com/Shubh9414/Blue-Log-Analyzer)

## 📝 Project Overview
**Blue Log** is a high-performance command-line tool designed for security analysts to automate the parsing and identification of suspicious activity across diverse log formats. This tool was engineered to bridge the gap between raw telemetry and actionable intelligence, **reducing initial investigation time by an estimated 90%** through automated IOC enrichment.

### Key Value Propositon
* **Rapid Triage:** Instantly flags brute-force attempts and sensitive path access, allowing analysts to focus on high-priority alerts.
* **Modular Architecture:** Built with an extensible framework to support new detection rules and log types with zero code changes.
* **Automation Ready:** Supports JSON and CSV exports for seamless integration with SIEM platforms or custom SOAR playbooks.

---

## Features & Parsers
Blue Log utilizes dedicated logic for each log type, driven by a centralized `config.json` for easy tuning.

* **SSH Parser:** Detects potential brute-force attacks by tracking failed login thresholds from source IPs.
* **Apache Parser:** Flags 404 error spikes, unauthorized access to sensitive paths (e.g., `/admin`), and suspicious User-Agent strings (e.g., `sqlmap`).
* **Windows Event Parser:** Correlates critical Event IDs including **4625** (Failed Logon), **4740** (Account Lockout), and **4688** (Suspicious Process Creation).

---

## Installation & Usage

### 1. Setup
```bash
git clone [https://github.com/Shubh9414/Blue-Log-Analyzer.git](https://github.com/Shubh9414/Blue-Log-Analyzer.git)
cd Blue-Log-Analyzer
pip install -r requirements.txt
```

###2. Execution
Run the tool by specifying the log type and the target file:

Analyze SSH Logs:

```bash
python Bluelog.py --type ssh logs/sshd.log
```

Analyze Apache (Export to CSV):

```bash
python Bluelog.py --type apache logs/apache.log --format csv --output apache_results.csv 
```

Analyze Windows Event Logs (JSON):

```bash
python Bluelog.py --type windows logs/windows.json --format json
```
