"""
BlueLog v1 (Unified Log Analysis Tool)
Author: Shubham 
Description:
    A command-line tool to analyze SSH, Apache, and Windows logs for suspicious activity.
    - SSH: Detect brute force attempts.
    - Apache: Detect 404 errors, sensitive path access, suspicious user agents.
    - Windows: Detect failed logons, account lockouts, suspicious process creation, and keyword matches.
"""
import argparse
import re
import json     
import sys
import os
from collections import defaultdict

#Load Configurations
CONFIG_DIR = os.path.join(os.path.dirname(__file__), "config")

#Apache Config 
try:
    config_path = os.path.join(os.path.dirname(__file__), "config", "apache-config.json")
    with open(config_path, "r") as f:
        apache_config = json.load(f)
    ApachePaths = apache_config["paths"]
    ApacheAgents = apache_config["agents"]
except FileNotFoundError:
    ApachePaths, ApacheAgents = [], []
    print("[WARNING] apache-config.json not found. Sensitive path and agent checks will be skipped.")

#Windows config

try:
    windows_config_path = os.path.join(os.path.dirname(__file__), "config", "windows-config.json")
    with open(windows_config_path, "r") as f:
        windows_config = json.load(f)
except FileNotFoundError:
    windows_config = {}
    print("[WARNING] windows-config.json not found. Windows event checks will be skipped.")

#SSH log parser

def parse_ssh_logs(log_file): #parsing SSH logs to find failed logon for each ip
    ip_count = defaultdict(int)

    with open(log_file, "r") as f:
         for line in f:
             if "Failed password" in line:
                 match = re.search(r"from (\d+\.\d+\.\d+\.\d+)",line)
                 if match:
                    ip = match.group(1)
                    ip_count[ip] += 1

         return ip_count

#Apache log parser

def parse_apache_logs(log_file):
    data=defaultdict(lambda: {"404_count":0, "sensitive_paths":[], "bad_agents":[]})

    log_artifacts = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[.*?\] "([A-Z]+) (.*?) HTTP/[\d.]+" (\d{3}) \d+ ".*?" "(.*?)"')

    with open(log_file, "r") as f:
        for line in f:
            match = log_artifacts.search(line)
            if match:
               ip, method, path, status, user_agent = match.groups()

               if status == "404":
                   data[ip]["404_count"] += 1

               for sensitive in ApachePaths:
                   if sensitive in path and path not in data[ip]["sensitive_paths"]:
                       data[ip]["sensitive_paths"].append(path)

               for agent in ApacheAgents:
                   if agent.lower() in user_agent.lower() and agent not in data[ip]["bad_agents"]:
                       data[ip]["bad_agents"].append(agent)
    return data

#Windows log parser

def parse_windows_logs(log_file):
    results = defaultdict(lambda: {"count": 0, "details": []})

    with open(log_file, "r") as f:
        try:
            logs = json.load(f)
        except json.JSONDecodeError:
            print("[ERROR] Windows log file must be JSON formatted.")
            sys.exit(1)

    for entry in logs:
        event_id = entry.get("EventID")
        
        #Matches to Event IDs in config

        for category, cat_conf in windows_config.items():
            if cat_conf.get("enabled") and "event_ids" in cat_conf:
                if event_id in cat_conf["event_ids"]:
                    results[cat_conf["_description"]]["count"] += 1
                    results[cat_conf["_description"]]["details"].append({
                        "Time": entry.get("TimeCreated"),
                        "User": entry.get("TargetUserName") or entry.get("SubjectUserName"),
                        "IP": entry.get("IpAddress", "N/A"),
                        "Reason": entry.get("FailureReason", "N/A")
                    })

        # Searches for keywords in config for all fields

        if "keywords" in windows_config and windows_config["keywords"].get("enabled"):
            for kw in windows_config["keywords"]["values"]:
                if any(kw.lower() in str(v).lower() for v in entry.values()):
                    results[f"Keyword: {kw}"]["count"] += 1
                    results[f"Keyword: {kw}"]["details"].append(entry)

    return results

#Output export formats
    
def export_txt(result):
    output = "\n--- Bluelog output ---\n"

    if all(isinstance(v, int) for v in result.values()):
        for ip, count in sorted(result.items(), key=lambda x: x[1], reverse=True):
            output += f"{ip}: {count}\n"

    elif all(isinstance(v, dict) for v in result.values()):
        for ip, data in result.items():
            output += f"\nIP: {ip}\n"
            output += f"  - 404 Errors: {data['404_count']}\n"
            output += f"  - Sensitive Paths: {', '.join(data['sensitive_paths']) if data['sensitive_paths'] else 'None'}\n"
            output += f"  - Suspicious User-Agents: {', '.join(data['bad_agents']) if data['bad_agents'] else 'None'}\n"

    else:
        output += str(result)

    return output


def export_csv(result):
    if all(isinstance(v, int) for v in result.values()):
        output = "IP,Failed_Attempts\n"
        for ip, count in sorted(result.items(), key=lambda x: x[1], reverse=True):
            output += f"{ip},{count}\n"

    elif all(isinstance(v, dict) for v in result.values()):
        output = "IP,404_Count,Sensitive_Paths,Suspicious_User_Agents\n"
        for ip, data in result.items():
            output += f"{ip},{data['404_count']}," \
                      f"\"{'|'.join(data['sensitive_paths'])}\"," \
                      f"\"{'|'.join(data['bad_agents'])}\"\n"

    else:
        output = "Data\n" + str(result) + "\n"

    return output

def export_json(result):
    return json.dumps(result, indent=4)   

#Main entry point

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BlueLog: Unified Log Analysis Tool")
    parser.add_argument("--type", required=True, choices=["apache", "ssh", "windows"], help="Type of log to analyze")
    parser.add_argument("log_file", help="Path to the log file")
    parser.add_argument("--format", choices=["txt", "csv", "json"], default="txt", help="Output format")
    parser.add_argument("--output", help="Path to save output")
    args = parser.parse_args()

    try:

        #Selecting the parser
        if args.type == "ssh":
            results = parse_ssh_logs(args.log_file)
        elif args.type == "apache":
            results = parse_apache_logs(args.log_file)
        elif args.type == "windows":
            results = parse_windows_logs(args.log_file)
        else:
            print("[ERROR] Unknown log type selected")
            sys.exit(1)
        
        #Select the export format

        if args.format == "csv":
            output = export_csv(results)
        elif args.format == "json":
            output = export_json(results)
        else:
            output = export_txt(results)

        #Save output or print it
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"[+] Output saved to {args.output}")
        else:
            print(output)

    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {args.log_file}")
    except json.JSONDecodeError:
        print(f"[ERROR] Failed to parse JSON from {args.log_file}")