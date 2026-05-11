import datetime
import random
import os

def generate_mock_logs(filename="logs/mock_auth.log"):
    ips = ["192.168.1.10", "10.0.0.5", "172.16.0.2", "45.56.78.90", "123.123.123.123"]
    users = ["root", "admin", "guest", "testuser", "dbadmin"]
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    start_time = datetime.datetime.now() - datetime.timedelta(minutes=10)
    
    with open(filename, "w") as f:
        # 1. Normal successful logins
        for _ in range(5):
            timestamp = (start_time + datetime.timedelta(seconds=random.randint(1, 100))).strftime("%b %d %H:%M:%S")
            f.write(f"{timestamp} server-01 sshd[100]: Accepted password for {random.choice(users)} from {random.choice(ips)} port 22 ssh2\n")
        
        # 2. Failed login attempts (Singletons)
        for _ in range(3):
            timestamp = (start_time + datetime.timedelta(seconds=random.randint(101, 200))).strftime("%b %d %H:%M:%S")
            f.write(f"{timestamp} server-01 sshd[101]: Failed password for {random.choice(users)} from {random.choice(ips)} port 22 ssh2\n")

        # 3. Brute Force Attack (5+ attempts in a short time from one IP)
        attacker_ip = "185.220.101.10"
        for i in range(7):
            timestamp = (start_time + datetime.timedelta(seconds=300 + i)).strftime("%b %d %H:%M:%S")
            f.write(f"{timestamp} server-01 sshd[102]: Failed password for root from {attacker_ip} port 22 ssh2\n")
            
        # 4. Invalid User Login Attempt
        timestamp = (start_time + datetime.timedelta(seconds=400)).strftime("%b %d %H:%M:%S")
        f.write(f"{timestamp} server-01 sshd[103]: Failed password for invalid user malicious_actor from 192.168.1.99 port 22 ssh2\n")
        
        # 5. Sudo Usage
        user = "testuser"
        # 5a. Normal sudo (Should be ignored by new rule)
        timestamp = (start_time + datetime.timedelta(seconds=500)).strftime("%b %d %H:%M:%S")
        f.write(f"{timestamp} server-01 sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/ls /var/www\n")
        
        # 5b. Sudo Abuse (Sensitive command - Should be flagged)
        timestamp = (start_time + datetime.timedelta(seconds=510)).strftime("%b %d %H:%M:%S")
        f.write(f"{timestamp} server-01 sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow\n")

    print(f"✅ Mock log file created at: {filename}")

if __name__ == "__main__":
    generate_mock_logs()
