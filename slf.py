import scapy.all as scapy
import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
#Y29kZSBieSBqZWpvIAo=
# Load or train ML model
MODEL_FILE = "firewall_ml_model.pkl"

def train_or_load_model():
    if os.path.exists(MODEL_FILE):
        print("[+] Loading Pre-trained Model...")
        return joblib.load(MODEL_FILE)
    
    print("[+] Training New Model...")
    # Simulated training data
    data = np.array([
        [100, 6, 1],  # Normal traffic
        [1500, 17, 0],  # Malicious (UDP Flood)
        [200, 6, 1],  # Normal traffic
        [5000, 17, 0],  # Malicious (High packet size, UDP)
        [50, 6, 1]   # Normal traffic
    ])
    labels = np.array([0, 1, 0, 1, 0])  # 0 = Normal, 1 = Malicious

    scaler = StandardScaler()
    X = scaler.fit_transform(data[:, :-1])
    
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X, labels)
    
    joblib.dump(model, MODEL_FILE)
    print("[+] Model Training Complete.")
    
    return model
#Y29kZSBieSBqZWpvIAo=
# Capture packets and extract features
def capture_packets(packet_count=100):
    print("[+] Capturing Network Packets...")
    packets = scapy.sniff(count=packet_count)
    extracted_data = []
    ip_sources = []

    for packet in packets:
        if packet.haslayer(scapy.IP):
            extracted_data.append([
                len(packet),  # Packet size
                packet[scapy.IP].proto  # Protocol (TCP=6, UDP=17, ICMP=1)
            ])
            ip_sources.append(packet[scapy.IP].src)  # Store source IP

    df = pd.DataFrame(extracted_data, columns=['Length', 'Protocol'])
    return df, ip_sources
#Y29kZSBieSBqZWpvIAo=
# Detect anomalies using ML model
def detect_anomalies(model, df):
    print("[+] Detecting Anomalies...")
    scaler = StandardScaler()
    df_scaled = scaler.fit_transform(df)
    predictions = model.predict(df_scaled)
    return predictions

# Block malicious IPs using iptables
def block_ip(ip):
    print(f"[!] Blocking Malicious IP: {ip}")
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
#Y29kZSBieSBqZWpvIAo=
# Main function
def main():
    model = train_or_load_model()
    
    df, ip_sources = capture_packets()
    predictions = detect_anomalies(model, df)

    for ip, is_malicious in zip(ip_sources, predictions):
        if is_malicious == 1:
            block_ip(ip)

    print("[+] Firewall Execution Completed.")

if __name__ == "__main__":
    main()

#Y29kZSBieSBqZWpvIAo=

