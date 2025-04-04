import os
import time
import re 
from collections import defaultdict

ATTEMPT_THRESHOLD = 5
TIME_WINDOW = 60

failded_attempt = defaultdict(list)

FAILED_LOGIN_ATTEMPT = [
    re.compile(r"Failed password for .* from (\d{1,3}(?:\.\d{1,3}){3})"),
    re.compile(r"Invalid user .* from (\d{1,3}(?:\.d{1,3}){3})"),
    re.compile(r"authentication failure; .* rhost=(\d{1,3}(?:\.\d{1,3}){3})"),
    re.compile(r"error: PM: Authentication failure for .* from (\d{1,3}(?:\.d{1,3}){3})"),
]

def monitor_file(file_path):
    """Monitors a file for a specific keyword."""
    with open(file_path, 'r') as file:
        file.seek(0, os.SEEK_SET)

        while True:
            line = file.readline()
            if not line:
                time.sleep(1)
                continue
            # if keyword in line:
            #     print(f"Found keyword '{keyword}' in file: {line.strip()}")
            for pattern in FAILED_LOGIN_ATTEMPT:
                match = pattern.search(line)
                if match:
                    ip = match.group(1)
                    handle_failed_attempt(ip)
                    detect_brute_force(ip)

def handle_failed_attempt(ip):
    """Logs a failed attempt for a given IP and cleans up old attempts."""
    current_time = time.time()
    failded_attempt[ip].append(current_time)

    failded_attempt[ip] = [t for t in failded_attempt[ip] if current_time - t <= TIME_WINDOW]

def detect_brute_force(ip):
    """Detects brute-force attempts based on the number of failed attempts within the time window."""
    if len(failded_attempt[ip] >= ATTEMPT_THRESHOLD):
        print(f"Brute-force attack detected from IP: {ip} (Failed attempts: {len(failded_attempt[ip])})")


if __name__ == "__main__":
    log_file = "/var/log/auth.log"
    # search_keyword = "CRON[36758]"
    monitor_file(log_file)