import joblib
import pandas as pd
from scapy.all import sniff
import os

# Load AI Model
model_path = "ai_firewall_model.pkl"

if os.path.exists(model_path):
    model = joblib.load(model_path)
    print("✅ AI Model Loaded Successfully!")
    
    # Step 3: Verify model feature names
    if hasattr(model, "feature_names_in_"):
        print("🔍 Model expected features:", model.feature_names_in_)
    else:
        print("⚠️ Model has no feature_names_in_ attribute!")
else:
    print("❌ AI Model Not Found!")
    model = None

# AI Prediction Function (Step 2 Included)
def ai_detect_anomaly(ip, port):
    """Predicts if an IP is malicious using AI."""
    if model is None:
        return False  # No model loaded

    try:
        # Encode IP as categorical value
        encoded_ip = pd.Series([ip]).astype("category").cat.codes[0]
        new_traffic = pd.DataFrame({"IP": [encoded_ip], "Port": [port], "Bytes_Transferred": [5000]})

        # Ensure model feature order is correct
        if hasattr(model, "feature_names_in_"):
            required_features = model.feature_names_in_
        else:
            required_features = new_traffic.columns  # Default to input DataFrame columns

        # Match feature order
        new_traffic = new_traffic.reindex(columns=required_features, fill_value=0)

        prediction = model.predict(new_traffic)
        return prediction[0] == 1  # Return True if it's an attack

    except Exception as e:
        print("\u274C AI Prediction Error:", e)
        return False

# Function to process packets
def process_packet(packet):
    try:
        src_ip = packet[0][1].src
        dst_port = packet[0][2].dport if packet.haslayer("TCP") or packet.haslayer("UDP") else None

        if dst_port:
            is_attack = ai_detect_anomaly(src_ip, dst_port)
            if is_attack:
                print(f"🚨 DDoS Attack Detected from {src_ip} on port {dst_port}!")
                # Add mitigation logic here (e.g., block IP)

    except Exception as e:
        print("⚠️ Packet Processing Error:", e)

# Start Packet Sniffing
if __name__ == "__main__":
    print("🔥 AI Firewall is now running...")
    sniff(prn=process_packet, store=0)
