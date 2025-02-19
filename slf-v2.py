import os
import subprocess
import sqlite3
import scapy.all as scapy
import pandas as pd
import joblib
import time
import requests

# Load or initialize machine learning model
MODEL_PATH = "slf/firewall_model.pkl"
DATABASE_PATH = "slf/threats.db"

# Initialize database if it doesn’t exist
def init_database():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS threats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT,
                        port INTEGER,
                        protocol TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

# Capture packets and log threats
def capture_packets():
    print("[+] Capturing Network Packets...")
    packets = scapy.sniff(count=100)
    
    threats = []
    for packet in packets:
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            protocol = packet[scapy.IP].proto
            port = packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else 0
            threats.append((ip_src, port, protocol))
    
    return threats

# Save detected threats to database
def save_threats(threats):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    for ip, port, protocol in threats:
        cursor.execute("INSERT INTO threats (ip, port, protocol) VALUES (?, ?, ?)", (ip, port, protocol))
    conn.commit()
    conn.close()

# Retrain ML model with new threats
def retrain_model():
    print("[+] Retraining ML Model with New Data...")
    conn = sqlite3.connect(DATABASE_PATH)
    df = pd.read_sql_query("SELECT ip, port, protocol FROM threats", conn)
    conn.close()

    if df.empty:
        print("[!] No new threats found, skipping retraining.")
        return

    # Simple ML model (Random Forest)
    from sklearn.ensemble import RandomForestClassifier
    model = RandomForestClassifier()
    
    X = df.drop(columns=["ip"])  # Features (port, protocol)
    y = df["ip"].apply(lambda x: 1)  # Labels (1 = threat)

    model.fit(X, y)
    joblib.dump(model, MODEL_PATH)
    print("[+] Model retrained and updated!")

# Update firewall rules dynamically
def update_firewall():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT ip FROM threats")
    blocked_ips = [row[0] for row in cursor.fetchall()]
    conn.close()

    for ip in blocked_ips:
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        print(f"[+] Blocked IP: {ip}")

# Fetch and apply threat intelligence feeds
def threat_intelligence():
    print("[+] Fetching Threat Intelligence Feeds...")
    try:
        response = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.csv")
        lines = response.text.split("\n")[9:]  # Skip headers

        for line in lines:
            if line.strip():
                ip = line.split(",")[1]
                os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
                print(f"[+] Auto-blocked threat IP: {ip}")
    except Exception as e:
        print(f"[!] Failed to fetch threat feeds: {e}")

# Main function
def main():
    print("[+] Running Self-Learning Firewall...")

    # Step 1: Install dependencies if needed
    if not os.path.exists("myenv"):
        print("[+] Running install.sh to set up environment...")
        subprocess.run(["sudo", "sh", "install.sh"], check=True)

    # Step 2: Initialize Database
    init_database()

    # Step 3: Capture packets & log threats
    threats = capture_packets()
    if threats:
        save_threats(threats)
        retrain_model()
        update_firewall()

    # Step 4: Fetch Threat Feeds
    threat_intelligence()

    print("[+] Self-Learning Firewall Execution Completed.")

if __name__ == "__main__":
    main()
