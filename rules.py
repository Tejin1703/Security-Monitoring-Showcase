from detections.parser import extract_ip, extract_user
from datetime import datetime

# Global state to track brute force attempts (In a real SOC, this might be a database or Redis)
# Format: { ip: [timestamp1, timestamp2, ...] }
failed_attempts_cache = {}

def check_failed_login(parsed_line):
    """Detects a single failed login attempt."""
    msg = parsed_line['message']
    if "Failed password" in msg:
        return {
            "type": "FAILED_LOGIN",
            "severity": "LOW",
            "user": extract_user(msg),
            "ip": extract_ip(msg),
            "timestamp": parsed_line['timestamp']
        }
    return None

def check_invalid_user(parsed_line):
    """Detects attempts to login as a non-existent user."""
    msg = parsed_line['message']
    if "invalid user" in msg:
        return {
            "type": "INVALID_USER",
            "severity": "MEDIUM",
            "user": extract_user(msg),
            "ip": extract_ip(msg),
            "timestamp": parsed_line['timestamp']
        }
    return None

def check_brute_force(parsed_line, threshold=5):
    """
    Detects brute force: 5+ failures from same IP.
    Note: In this simple version, we're tracking occurrences.
    """
    msg = parsed_line['message']
    if "Failed password" in msg:
        ip = extract_ip(msg)
        if ip not in failed_attempts_cache:
            failed_attempts_cache[ip] = []
        
        failed_attempts_cache[ip].append(parsed_line['timestamp'])
        
        if len(failed_attempts_cache[ip]) >= threshold:
            return {
                "type": "BRUTE_FORCE_ATTACK",
                "severity": "HIGH",
                "ip": ip,
                "attempts": len(failed_attempts_cache[ip]),
                "timestamp": parsed_line['timestamp'],
                "message": f"Suspicious activity: {len(failed_attempts_cache[ip])} failed attempts from {ip}"
            }
    return None

def check_sudo_abuse(parsed_line):
    """Detects repeated sudo commands which might indicate privilege escalation attempts."""
    if "sudo" in parsed_line['process']:
        return {
            "type": "SUDO_USAGE",
            "severity": "INFO",
            "message": parsed_line['message'],
            "timestamp": parsed_line['timestamp']
        }
    return None
