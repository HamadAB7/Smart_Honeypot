import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from datetime import datetime
import os
from termcolor import colored  
import re
from datetime import datetime

def normalize_logs(log_lines):
    normalized_entries = []

    for line in log_lines:
        line = line.strip()

        # 1. Match format: Telnet credentials
        if "Credentials entered from" in line:
            match = re.search(r'(\d+\.\d+\.\d+\.\d+).*Username:\s*(\S+),\s*Password:\s*(\S+)', line)
            if match:
                ip, username, password = match.groups()
                normalized_entries.append([ip, username, password, datetime.now()])
                continue

        # 2. Match format: HTTP login attempt
        if "Login attempt from" in line:
            match = re.search(r'Login attempt from (\d+\.\d+\.\d+\.\d+) - Username: (\S+), Password: (\S+)', line)
            if match:
                ip, username, password = match.groups()
                normalized_entries.append([ip, username, password, datetime.now()])
                continue

        # 3. Match format: FTP login
        if "Username:" in line and "Password:" in line and "IP:" in line:
            match = re.search(r'IP: (\d+\.\d+\.\d+\.\d+), Username: (\S+), Password: (\S+)', line)
            if match:
                ip, username, password = match.groups()
                normalized_entries.append([ip, username, password, datetime.now()])
                continue

        # 4. Match format: Simple comma-separated creds (like creds_audits.log)
        if re.match(r'\d+\.\d+\.\d+\.\d+,', line):
            try:
                parts = line.split(", ")
                ip = parts[0]
                username = parts[1] if len(parts) > 1 else "N/A"
                password = parts[2] if len(parts) > 2 else "N/A"
                normalized_entries.append([ip, username, password, datetime.now()])
                continue
            except Exception:
                continue

        # 5. SSH/telnet/command logs: extract "command as password" to flag suspicious commands
        if "Command" in line and "executed by" in line:
            match = re.search(r"Command\s+.*?(\S+)'?\s+executed by (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                command, ip = match.groups()
                normalized_entries.append([ip, "-", command, datetime.now()])
                continue

        # 6. DNS queries (IP, domain as username, record type as password)
        if "Query:" in line and "Type:" in line:
            match = re.search(r'IP: (\d+\.\d+\.\d+\.\d+), Query: ([\w\.-]+), Type: (\w+)', line)
            if match:
                ip, domain, query_type = match.groups()
                normalized_entries.append([ip, domain, query_type, datetime.now()])
                continue

    return normalized_entries

def load_all_logs(log_dir, log_files):
    all_entries = []

    for log_file in log_files:
        file_path = os.path.join(log_dir, log_file)
        if not os.path.exists(file_path):
            continue
        with open(file_path, 'r') as file:
            lines = file.readlines()
            normalized = normalize_logs(lines)
            all_entries.extend(normalized)

    return pd.DataFrame(all_entries, columns=["ip_address", "username", "password", "timestamp"])

# Known default credentials (expanded list)
default_creds = [
    ("admin", "admin"),
    ("root", "toor"),
    ("user", "123456"),
    ("admin", "123456"),
    ("test", "test"),
    ("guest", "guest"),
    ("root", "root"),
    ("admin", "password"),
    ("support", "support"),
    ("ftp", "ftp"),
    ("administrator", "admin"),
    ("pi", "raspberry")
]

# Function to preprocess logs
def preprocess_logs(df):
    le = LabelEncoder()
    df['ip_encoded'] = le.fit_transform(df['ip_address'])
    return df[['ip_encoded']]

# Detect anomalies using Isolation Forest
def detect_anomalies_with_ai(df):
    preprocessed_data = preprocess_logs(df)
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(preprocessed_data)
    df['anomaly'] = model.predict(preprocessed_data)
    return df

# Add behavior-based risk indicators
def enrich_with_behavior(df):
    df['attempts'] = df.groupby('ip_address')['ip_address'].transform('count')
    df['unique_usernames'] = df.groupby('ip_address')['username'].transform('nunique')
    df['unique_passwords'] = df.groupby('ip_address')['password'].transform('nunique')
    df['is_default_cred'] = df.apply(lambda x: (x['username'], x['password']) in default_creds, axis=1)
    return df

def assign_risk_score(df):
    def score(row):
        risk = 0
        risk += row['attempts'] * 1
        risk += row['unique_usernames'] * 2
        risk += row['unique_passwords'] * 1
        if row['is_default_cred']:
            risk += 5
        if row['anomaly'] == -1:
            risk += 3
        return risk

    def severity_level(score):
        if score >= 15:
            return "CRITICAL"
        elif score >= 10:
            return "HIGH"
        elif score >= 5:
            return "MEDIUM"
        else:
            return "LOW"

    df['risk_score'] = df.apply(score, axis=1)
    df['severity'] = df['risk_score'].apply(severity_level)
    return df

def generate_recommendations(df):
    high_risk = df[df['risk_score'] >= 10]
    unique_ips = high_risk.drop_duplicates(subset='ip_address')
    recommendations = []
    for _, row in unique_ips.iterrows():
        msg = f"[{row['severity']}] IP {row['ip_address']} made {row['attempts']} attempts, "
        msg += f"used {row['unique_usernames']} usernames and {row['unique_passwords']} passwords."
        if row['is_default_cred']:
            msg += " Used default credentials."
        msg += f" Risk Score: {row['risk_score']} — Recommend immediate review or block."
        color = {
        "LOW": "green",
        "MEDIUM": "yellow",
        "HIGH": "magenta",
        "CRITICAL": "red"
        }[row["severity"]]
        recommendations.append(colored(msg, color))
    return recommendations

def log_behavioral_events(df):
    with open("log_files/ai_behavioral.log", "a") as log:
        for _, row in df.iterrows():
            msg = f"{datetime.now()} - IP: {row['ip_address']} - Severity: {row['severity']} - Risk Score: {row['risk_score']}"
            log.write(msg + "\n")

def update_blocklist(df):
    high_risk_ips = df[df['severity'].isin(["CRITICAL", "HIGH"])]["ip_address"].unique()
    with open("log_files/block_list.txt", "w") as f:
        for ip in high_risk_ips:
            f.write(ip + "\n")

def run_analysis():
    log_dir = "log_files"
    log_files = [
        "cmd_audits.log",
        "creds_audits.log",
        "dns_honeypot.log",
        "ftp_honeypot.log",
        "http_audit.log",
        "telnet_honeypot.log"
    ]

    logs_df = load_all_logs(log_dir, log_files)

    logs_df = detect_anomalies_with_ai(logs_df)
    logs_df = enrich_with_behavior(logs_df)
    logs_df = assign_risk_score(logs_df)

    top_anomalies = logs_df[logs_df['risk_score'] >= 10]

    print("Top Risky IPs Detected:")
    print(top_anomalies[['ip_address', 'username', 'password', 'attempts',
                         'unique_usernames', 'unique_passwords', 'is_default_cred', 'risk_score', 'severity']])

    print("\nRecommended Actions:")
    for rec in generate_recommendations(top_anomalies):
        print(rec)

    log_behavioral_events(top_anomalies)
    update_blocklist(top_anomalies)

    top_anomalies.to_csv("log_files/high_risk_anomalies.csv", index=False)

#if __name__ == "__main__":
#    run_analysis() 