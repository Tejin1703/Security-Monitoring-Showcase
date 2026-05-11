from detections.parser import extract_ip, extract_user
from datetime import datetime

# Global state
# { ip: [datetime1, datetime2, ...] }
failed_attempts_cache = {}
# { ip: last_alert_time } - To prevent alert spamming (Noise Reduction)
alert_sent_cache = {}

def check_failed_login(parsed_line):
    """Detects a single failed login attempt."""
    msg = parsed_line['message']
    if "Failed password" in msg:
        return {
            "type": "FAILED_LOGIN",
            "severity": "LOW",
            "user": extract_user(msg),
            "ip": extract_ip(msg),
            "timestamp": parsed_line['raw_timestamp']
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
            "timestamp": parsed_line['raw_timestamp']
        }
    return None

def check_brute_force(parsed_line, threshold=5, window_seconds=60):
    """
    Detects 5+ failures from same IP within a 60s window.
    Implements 'Noise Reduction' by grouping attempts into a single alert per window.
    """
    msg = parsed_line['message']
    if "Failed password" in msg:
        ip = extract_ip(msg)
        ts = parsed_line['timestamp']
        
        if ip not in failed_attempts_cache:
            failed_attempts_cache[ip] = []
        
        failed_attempts_cache[ip].append(ts)
        
        # FILTER: Only keep attempts within the sliding window
        recent_attempts = [t for t in failed_attempts_cache[ip] if (ts - t).total_seconds() <= window_seconds]
        failed_attempts_cache[ip] = recent_attempts
        
        if len(recent_attempts) >= threshold:
            # Noise Reduction Check
            last_alert = alert_sent_cache.get(ip)
            if not last_alert or (ts - last_alert).total_seconds() > window_seconds:
                alert_sent_cache[ip] = ts
                return {
                    "type": "BRUTE_FORCE_ATTACK",
                    "severity": "HIGH",
                    "ip": ip,
                    "attempts": len(recent_attempts),
                    "timestamp": parsed_line['raw_timestamp'],
                    "message": f"Suspicious activity: {len(recent_attempts)} failed attempts from {ip} in {window_seconds}s window."
                }
    return None

def check_sudo_abuse(parsed_line):
    """
    Detects sensitive command usage.
    Ignores standard sudo usage to reduce False Positives.
    """
    msg = parsed_line['message']
    # List of 'High Risk' commands
    sensitive_cmds = ["/etc/shadow", "chmod", "chown", "passwd", "rm -rf /", "visudo"]
    
    if "sudo" in parsed_line['process']:
        # Check if the command contains any sensitive keywords
        is_sensitive = any(cmd in msg for cmd in sensitive_cmds)
        
        if is_sensitive:
            return {
                "type": "SUDO_ABUSE_SENSITIVE",
                "severity": "CRITICAL",
                "message": f"CRITICAL: User executing high-risk command: {msg}",
                "timestamp": parsed_line['raw_timestamp']
            }
    return None
