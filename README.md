# Blue Log Analyzer v1.0

Blue Log is a command-line tool designed for security analysts and blue teamers to quickly parse and identify suspicious activity in common log formats.
It is built to be modular and extensible, allowing for new detection rules and log types to be added easily.

This tool was developed as a portfolio project to demonstrate practical skills in Python scripting, log analysis, and detection engineering.

## Features

Modular Parsers – Dedicated parsing logic for each log type:

SSH – Detects potential brute-force attacks by tracking failed login attempts from source IPs.

Apache – Flags 404 errors, sensitive path access (e.g., /admin), and suspicious User-Agent strings.

Windows Event Logs – Detects critical events like failed logons (4625), account lockouts (4740), and suspicious process creation (4688).

Configuration-Driven – Detection logic is stored in config/config.json for easy updates without modifying code.

Flexible Output – Export results in:

Text (txt) – Human-readable summaries (default)

CSV – For spreadsheets or SIEM ingestion

JSON – For integration with other tools

## Installation
git clone https://github.com/your-username/Blue-Log-Analyzer.git
cd Blue-Log-Analyzer

## Usage

Run the tool from the command line by specifying the log type, log file, and optional output format.

## Analyze SSH Logs

python Bluelog.py --type ssh logs/sshd.log (path to the log)


## Analyze Apache Logs

python Bluelog.py --type apache logs/apache.log --format csv --output apache_results.csv


## Analyze Windows Event Logs (JSON)

python Bluelog.py --type windows logs/windows.json --format json

## Configuration

All detection rules are defined in:

config/config.json


### Example snippet for Apache: 
"apache": {
  "paths": ["/admin", "/wp-admin"],
  "agents": ["sqlmap", "nmap"]
}

## Future Development (v2.0 Roadmap)

YAML Config Support – Easier reading/writing of detection rules (config.yaml)

Threat Intelligence Enrichment – AbuseIPDB, VirusTotal integration

Cloud Log Support – AWS CloudTrail analysis

Database Storage – Save results in SQLite for history & trend analysis
