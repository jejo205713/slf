import scapy.all as scapy
import pandas as pd
import tensorflow as tf
import joblib
import os
from flask import Flask, request
import netifaces as ni
import psutil

# Load AI Model
try:
    model = joblib.load("ai_firewall_model.pkl")
    print("\u2714 AI Model Loaded Successfully!")
except Exception as e:
    print("\u274C Error Loading AI Model:", e)
    model = None

# Global DataFrame for Firewall Logs
firewall_logs = pd.DataFrame(columns=["IP", "Port", "Action"])

def update_firewall_rules(ip, port, decision):
    """Updates firewall logs dynamically."""
    global firewall_logs
    new_entry = pd.DataFrame({"IP": [ip], "Port": [port], "Action": [decision]})
    firewall_logs = pd.concat([firewall_logs, new_entry], ignore_index=True)

def ai_detect_anomaly(ip, port):
    """Predicts if an IP is malicious using AI."""
    if model is None:
        return False  # No model loaded

    try:
        encoded_ip = pd.Series([ip]).astype("category").cat.codes[0]
        new_traffic = pd.DataFrame({"IP": [encoded_ip], "Port": [port], "Bytes_Transferred": [5000]})
        
        # Ensure AI model expects the correct features
        if hasattr(model, "feature_names_in_"):
            missing_features = set(model.feature_names_in_) - set(new_traffic.columns)
            for feature in missing_features:
                new_traffic[feature] = 0  # Add missing features with default values
        
        prediction = model.predict(new_traffic)
        return prediction[0] == 1  # Return True if it's an attack

    except Exception as e:
        print("\u274C AI Prediction Error:", e)
        return False

def block_ip(ip):
    """Blocks an IP using iptables."""
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    print(f"\u26D4 Blocked IP: {ip}")

def firewall_engine(packet):
    """Processes packets to detect and mitigate threats."""
    try:
        if scapy.IP in packet:  # Ensure packet contains an IP layer
            ip = packet[scapy.IP].src
            port = packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else "Unknown"

            if ai_detect_anomaly(ip, port):
                block_ip(ip)
                update_firewall_rules(ip, port, "Blocked")
            else:
                update_firewall_rules(ip, port, "Allowed")

        else:
            print("\u274C Packet processing error: No IP layer found!")
            packet.show()  # Debugging: Show packet details

    except Exception as e:
        print("\u274C Packet processing error:", e)

def capture_packets():
    """Captures network packets."""
    try:
        scapy.sniff(prn=firewall_engine, store=False, filter="ip", count=10)
    except Exception as e:
        print("\u274C Scapy Sniffing Error:", e)

def start_firewall():
    """Starts the AI firewall."""
    print("\U0001F6E1 AI Firewall is now running...")
    capture_packets()

if __name__ == "__main__":
    start_firewall()
