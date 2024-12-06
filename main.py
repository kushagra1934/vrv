import re
import csv
from collections import Counter


import random
from datetime import datetime, timedelta

# Base log structure
log_template = (
    "{ip} - - [{timestamp}] \"{method} {endpoint} HTTP/1.1\" {status_code} {response_size}{extra}"
)

# Possible IPs, methods, endpoints, and status codes
base_ips = ["192.168.1.1", "203.0.113.5", "10.0.0.2", "198.51.100.23", "192.168.1.100"]
methods = ["GET", "POST", "PUT", "DELETE"]
endpoints = ["/home", "/login", "/register", "/about", "/contact", "/dashboard", "/profile", "/feedback", "/logout", "/settings"]
status_codes = [200, 401, 404, 500, 301]
extra_info = ["", " \"Invalid credentials\""]

# Generate random IPs
def generate_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

# Generate timestamps over a realistic range
start_time = datetime(2024, 12, 3, 10, 12, 34)
time_increment = timedelta(seconds=1)

# Generate 1000 augmented logs
augmented_logs = []
for i in range(1000):
    ip = random.choice(base_ips + [generate_random_ip()])  # Mix base and random IPs
    method = random.choice(methods)
    endpoint = random.choice(endpoints)
    status_code = random.choice(status_codes)
    response_size = random.randint(128, 2048)  # Response size in bytes
    extra = random.choice(extra_info) if status_code == 401 else ""
    timestamp = (start_time + i * time_increment).strftime("%d/%b/%Y:%H:%M:%S +0000")

    # Format the log entry
    log_entry = log_template.format(
        ip=ip,
        timestamp=timestamp,
        method=method,
        endpoint=endpoint,
        status_code=status_code,
        response_size=response_size,
        extra=extra
    )
    augmented_logs.append(log_entry)

# Save to a file
with open("sample.log", "w") as log_file:
    log_file.write("\n".join(augmented_logs))

print("1000 augmented log entries saved to 'augmented_logs.log'")

# File paths
log_file_path = "sample.log"
output_csv_path = "log_analysis_results.csv"

# Parsing the log file
with open(log_file_path, "r") as log_file:
    logs = log_file.readlines()

# Regular expressions for log parsing
ip_pattern = re.compile(r'^([\d\.]+)')
endpoint_pattern = re.compile(r'\"[A-Z]+\s(/[\w/-]*)')
status_code_pattern = re.compile(r'\"\s(\d{3})')

# Data structures
ip_counter = Counter()
endpoint_counter = Counter()
failed_login_attempts = Counter()

# Processing each log entry
for log in logs:
    ip_match = ip_pattern.match(log)
    endpoint_match = endpoint_pattern.search(log)
    status_code_match = status_code_pattern.search(log)

    if ip_match:
        ip = ip_match.group(1)
        ip_counter[ip] += 1

    if endpoint_match:
        endpoint = endpoint_match.group(1)
        endpoint_counter[endpoint] += 1

    if status_code_match:
        status_code = status_code_match.group(1)
        if status_code == "401":  # Detecting failed logins
            failed_login_attempts[ip] += 1

# Configurable threshold for suspicious activity
failed_login_threshold = 10

# Safely retrieve the most accessed endpoint
if endpoint_counter:
    most_accessed_endpoint, max_access_count = endpoint_counter.most_common(1)[0]
else:
    most_accessed_endpoint, max_access_count = "No endpoints found", 0

# Sorting results
sorted_ips = ip_counter.most_common()
suspicious_ips = [(ip, count) for ip, count in failed_login_attempts.items() if count > failed_login_threshold]

# Writing results to CSV
with open(output_csv_path, "w", newline="") as csv_file:
    writer = csv.writer(csv_file)

    # Requests per IP
    writer.writerow(["Requests per IP"])
    writer.writerow(["IP Address", "Request Count"])
    writer.writerows(sorted_ips)
    writer.writerow([])

    # Most accessed endpoint
    writer.writerow(["Most Accessed Endpoint"])
    writer.writerow(["Endpoint", "Access Count"])
    writer.writerow([most_accessed_endpoint, max_access_count])
    writer.writerow([])

    # Suspicious activity
    writer.writerow(["Suspicious Activity"])
    writer.writerow(["IP Address", "Failed Login Count"])
    writer.writerows(suspicious_ips)

# Displaying results
print("Analysis Completed. Results saved to 'log_analysis_results.csv'")
print("\nRequests per IP:")
for ip, count in sorted_ips:
    print(f"{ip:20} {count}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint} (Accessed {max_access_count} times)")

if suspicious_ips:
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips:
        print(f"{ip:20} {count}")
else:
    print("\nNo suspicious activity detected.")
