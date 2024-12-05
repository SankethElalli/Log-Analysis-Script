import re
from collections import Counter, defaultdict
import csv
import pandas as pd

# Path to the log file
LOG_FILE = 'server.log'

log_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[.*\] ".*? (/.*?) .*" (\d{3})')

# Reading the log file
def read_log_file(log_file):
    with open(log_file, 'r') as file:
        logs = file.readlines()
    return logs

# Parsing the log entries
def parse_log_file(log_file):
    logs = read_log_file(log_file)
    parsed_logs = []
    
    for log in logs:
        match = log_pattern.search(log)
        if match:
            ip_address = match.group(1)
            endpoint = match.group(2)
            status_code = match.group(3)
            parsed_logs.append((ip_address, endpoint, status_code))
    
    return parsed_logs

# Counting the requests per IP Address
def count_requests_per_ip(logs):
    ip_counts = Counter(log[0] for log in logs)
    return ip_counts

# Identifing the accessed endpoint
def find_most_accessed_endpoint(logs):
    endpoint_counts = Counter(log[1] for log in logs)
    most_accessed = endpoint_counts.most_common(1)
    return most_accessed[0] if most_accessed else ("No endpoint", 0)

# Extracting IP and Endpoint functions
def extract_ip(log_line):
    match = re.match(r'(\d+\.\d+\.\d+\.\d+)', log_line)
    if match:
        return match.group(1)
    return None

def extract_endpoint(log_line):
    match = re.search(r'"[A-Z]+\s(/[^"]+)\sHTTP/1.1"', log_line)
    if match:
        return match.group(1)
    return None

# Logic for accesses to each endpoint
def count_endpoints(log_lines):
    endpoint_counts = defaultdict(int)
    for line in log_lines:
        if "GET" in line or "POST" in line:
            endpoint = extract_endpoint(line)
            endpoint_counts[endpoint] += 1
    return endpoint_counts

# Detecting suspicious activity

# Keeping threshold for failed login attempts
FAILED_LOGIN_THRESHOLD = 5

def detect_suspicious_activity(log_lines):
    suspicious_activities = defaultdict(int)
    for line in log_lines:
        if "POST /login" in line and "401" in line:
            ip = extract_ip(line)
            suspicious_activities[ip] += 1

    suspicious_activities = {ip: count for ip, count in suspicious_activities.items() if count > FAILED_LOGIN_THRESHOLD}
    return suspicious_activities

# Saving of results to CSV
OUTPUT_FILE = 'log_analysis_results.csv'

def save_results_to_csv(ip_counts, most_accessed, suspicious_activities):
    with open(OUTPUT_FILE, 'w', newline='') as file:
        writer = csv.writer(file)

        writer.writerow(["IP Address", "Request Count", "Most Accessed Endpoint", "Access Count", "Failed Login Count"])

        endpoint_access = defaultdict(int)
        for ip, count in ip_counts.items():
            endpoint, _ = most_accessed
            endpoint_access[ip] = endpoint

        for ip, count in ip_counts.items():
            failed_logins = suspicious_activities.get(ip, 0)

            endpoint = endpoint_access.get(ip, "No endpoint")

            writer.writerow([ip, count, endpoint, most_accessed[1], failed_logins])
    
    print("\nResults saved to CSV file.")

# Main function to run the analysis
def main():
    logs = parse_log_file(LOG_FILE)
    
    ip_counts = count_requests_per_ip(logs)
    print("\nRequests per IP Address:")
    print("IP Address           Request Count")
    for ip, count in ip_counts.most_common():
        print(f"{ip:<20} {count}")
    
    most_accessed = find_most_accessed_endpoint(logs)
    print(f"\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    
    suspicious_activities = detect_suspicious_activity(logs)
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activities.items():
        print(f"{ip:<20} {count}")
    
    save_results_to_csv(ip_counts, most_accessed, suspicious_activities)

if __name__ == "__main__":
    main()