# 🛡️ Mini SOC: Security Monitoring & Incident Detection

A lightweight, modular Security Operations Center (SOC) tool built in Python. This project simulates a log-based detection system that monitors Linux authentication logs (`/var/log/auth.log`) to identify and alert on suspicious activity.

## 🚀 Key Features
- **Brute Force Detection**: Identifies IPs with 5+ failed login attempts within a short window.
- **Invalid User Monitoring**: Flags attempts to login with usernames that do not exist on the system.
- **Sudo Abuse Detection**: Monitors for repeated or suspicious `sudo` command usage.
- **Structured Reporting**: Generates machine-readable JSON incident reports for further analysis.
- **Modular Architecture**: Easy to add new detection rules (regex-based).

## 📁 Project Structure
- `main.py`: The core engine that orchestrates log parsing and detection.
- `detections/`:
  - `parser.py`: Extracts IP, User, and Timestamp from raw syslog strings.
  - `rules.py`: Contains logic for security alerts (Brute Force, Sudo, etc.).
- `logs/`: Directory for input logs (includes a mock generator for testing).
- `output/`: Where the `incident_report.json` is generated.

## 🛠️ How to Run
1. **Setup Environment**: Ensure you have Python 3 installed.
2. **Generate Test Data**: 
   ```bash
   python3 mock_log_gen.py
   ```
3. **Run Detection Engine**:
   ```bash
   python3 main.py
   ```
4. **Review Findings**:
   Check `output/incident_report.json` for a summary of detected threats.

## 📊 Example Incident Report
```json
{
    "type": "BRUTE_FORCE_ATTACK",
    "severity": "HIGH",
    "ip": "185.220.101.10",
    "attempts": 7,
    "timestamp": "May 11 03:11:52",
    "message": "Suspicious activity: 7 failed attempts from 185.220.101.10"
}
```

## 🛡️ Future Enhancements
- [ ] **Live Tail**: Real-time monitoring of `/var/log/auth.log` using `tail -f` logic.
- [ ] **Email Alerts**: Integration with SMTP to send instant notifications.
- [ ] **Visual Dashboard**: A simple web UI to visualize attack patterns over time.
