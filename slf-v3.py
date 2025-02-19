import os
import time
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

# 🚀 GLOBAL VARIABLES
SUSPICIOUS_PORTS = [23, 445, 3389]  # Telnet, SMB, RDP
firewall_rules = {}
firewall_logs = pd.DataFrame(columns=["IP", "Port", "Action"])
model = None  # Placeholder for AI Model


# 🔥 PART 1: FIREWALL ENGINE (Packet Capturing & Filtering)
def firewall_engine(packet):
    """Basic firewall logic to analyze traffic."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else "Unknown")

        # Check AI for anomalies
        is_malicious = ai_detect_anomaly(src_ip, dst_port)

        # Final firewall decision
        if is_malicious or dst_port in SUSPICIOUS_PORTS:
            decision = "Blocked"
            block_ip(src_ip)  # Auto-block malicious IP
        else:
            decision = "Allowed"

        update_firewall_rules(src_ip, dst_port, decision)  # Update logs
        print(f"[{time.strftime('%H:%M:%S')}] {src_ip} → Port {dst_port} → {decision}")


# 🔥 PART 2: SELF-LEARNING MODULE (Adaptive Rule Updates)
def update_firewall_rules(ip, port, decision):
    """Updates firewall rules based on past logs."""
    global firewall_logs
    firewall_logs = firewall_logs.append({"IP": ip, "Port": port, "Action": decision}, ignore_index=True)

    # Auto-block IPs if found malicious multiple times
    blocked_ips = firewall_logs[firewall_logs["Action"] == "Blocked"]["IP"].value_counts()
    for blocked_ip, count in blocked_ips.items():
        if count > 3:
            print(f"⚠️ Auto-blocking {blocked_ip} due to repeated malicious activity")
            firewall_rules[blocked_ip] = "Blocked"
            block_ip(blocked_ip)


# 🔥 PART 3: AI-BASED ANOMALY DETECTION (Using ML)
def train_ai_model():
    """Trains AI model for anomaly detection."""
    global model

    # Simulated dataset (replace with actual logs)
    data = {
        "IP": ["192.168.1.1", "203.0.113.5", "192.168.1.2", "45.67.89.10", "203.0.113.5"],
        "Port": [80, 23, 443, 445, 3389],
        "Bytes_Transferred": [300, 5000, 250, 9000, 12000],
        "Is_Malicious": [0, 1, 0, 1, 1]  # 1 = Malicious, 0 = Safe
    }

    df = pd.DataFrame(data)
    df["IP"] = df["IP"].astype("category").cat.codes  # Encode IPs

    X = df[["IP", "Port", "Bytes_Transferred"]]
    y = df["Is_Malicious"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier()
    model.fit(X_train, y_train)
    print("✅ AI Model Trained Successfully!")


def ai_detect_anomaly(ip, port):
    """Predicts if a network request is malicious using AI."""
    if model is None:
        return False  # No model, no detection

    new_traffic = pd.DataFrame({"IP": [1], "Port": [port], "Bytes_Transferred": [5000]})
    prediction = model.predict(new_traffic)
    return prediction[0] == 1  # 1 means malicious


# 🔥 PART 4: IPTABLES INTEGRATION (Auto-Blocking Malicious IPs)
def block_ip(ip):
    """Blocks an IP using iptables."""
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    print(f"🚨 Blocked IP: {ip}")


# 🚀 MAIN FUNCTION
if __name__ == "__main__":
    train_ai_model()  # Train AI before running firewall
    print("🚀 AI Firewall is now running...")
    sniff(prn=firewall_engine, count=10)  # Capture 10 packets
