import re

def parse_log_line(line):
    """
    Extracts timestamp, process, and message from a standard syslog line.
    Example: May 11 10:00:01 server-01 sshd[123]: Message here
    """
    # Regex to match: Month Day Time Hostname Process[PID]: Message
    pattern = r'^(\w{3}\s+\d+\s\d{2}:\d{2}:\d{2})\s+[\w-]+\s+([\w\[\]\d]+):\s+(.*)$'
    match = re.match(pattern, line)
    
    if match:
        return {
            "timestamp": match.group(1),
            "process": match.group(2),
            "message": match.group(3)
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
