import re
from datetime import datetime

def parse_log_line(line):
    """
    Extracts structured data, converting the timestamp to a datetime object.
    """
    pattern = r'^(\w{3}\s+\d+\s\d{2}:\d{2}:\d{2})\s+[\w-]+\s+([\w\[\]\d]+):\s+(.*)$'
    match = re.match(pattern, line)
    
    if match:
        raw_ts = match.group(1)
        # Syslog doesn't have a year. We assume the current year.
        current_year = datetime.now().year
        dt_obj = datetime.strptime(f"{raw_ts} {current_year}", "%b %d %H:%M:%S %Y")
        
        return {
            "timestamp": dt_obj,
            "process": match.group(2),
            "message": match.group(3),
            "raw_timestamp": raw_ts
        }
    return None

def extract_ip(message):
    """Helper to pull an IP address from a message string."""
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    match = re.search(ip_pattern, message)
    return match.group(1) if match else "Unknown"

def extract_user(message):
    """Helper to pull a username from a message string."""
    # Common patterns: 'for root', 'for invalid user admin'
    if "invalid user" in message:
        match = re.search(r'invalid user (\w+)', message)
    else:
        match = re.search(r'for (\w+)', message)
    return match.group(1) if match else "Unknown"
