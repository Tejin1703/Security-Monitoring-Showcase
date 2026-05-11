import json
import os
from detections.parser import parse_log_line
from detections.rules import (
    check_failed_login, 
    check_invalid_user, 
    check_brute_force, 
    check_sudo_abuse
)

LOG_FILE = "logs/mock_auth.log"
REPORT_FILE = "output/incident_report.json"

def run_soc():
    print("🚀 Mini SOC System Starting...")
    alerts = []
    
    if not os.path.exists(LOG_FILE):
        print(f"❌ Error: {LOG_FILE} not found. Run mock_log_gen.py first.")
        return

    with open(LOG_FILE, "r") as f:
        for line in f:
            parsed = parse_log_line(line)
            if not parsed:
                continue
            
            # Run our detection suite
            # 1. Check for Brute Force (High Priority)
            brute_alert = check_brute_force(parsed)
            if brute_alert:
                alerts.append(brute_alert)
                print(f"🚨 ALERT [HIGH]: Brute Force detected from {brute_alert['ip']}")
                continue # If it's brute force, we already know it's a failed login

            # 2. Check for Invalid User
            invalid_alert = check_invalid_user(parsed)
            if invalid_alert:
                alerts.append(invalid_alert)
                print(f"⚠️  ALERT [MED]: Invalid user login attempt: {invalid_alert['user']}")

            # 3. Check for Sudo Abuse
            sudo_alert = check_sudo_abuse(parsed)
            if sudo_alert:
                alerts.append(sudo_alert)
                print(f"🔍 INFO: Sudo usage detected at {sudo_alert['timestamp']}")

            # 4. Check for general failed login
            failed_alert = check_failed_login(parsed)
            if failed_alert:
                alerts.append(failed_alert)

    # Phase 6: Report Generation
    generate_report(alerts)

def generate_report(alerts):
    print(f"\n--- Analysis Complete ---")
    print(f"Total Alerts Generated: {len(alerts)}")
    
    report = {
        "report_info": {
            "generated_at": "2026-05-11", # In a real script, use datetime.now()
            "source_file": LOG_FILE,
            "total_alerts": len(alerts)
        },
        "alerts": alerts
    }
    
    os.makedirs(os.path.dirname(REPORT_FILE), exist_ok=True)
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=4)
    
    print(f"📄 Incident report saved to: {REPORT_FILE}")

if __name__ == "__main__":
    run_soc()
