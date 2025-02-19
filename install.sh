#!/bin/bash

# SLF Setup Script By JEJO
echo "[+] Updating system and installing required packages..."
sudo apt update && sudo apt install python3 python3-venv python3-pip -y
#Y29kZSBieSBqZWpvIAo=
# Create Virtual Environment
echo "[+] Creating virtual environment..."
cd ~/hack/self-Learning-firewall || { echo "Error: Directory not found!"; exit 1; }
python3 -m venv myenv
#Y29kZSBieSBqZWpvIAo=
# Activate Virtual Environment
echo "[+] Activating virtual environment..."
source myenv/bin/activate
#Y29kZSBieSBqZWpvIAo=
# Upgrade pip
echo "[+] Upgrading pip..."
pip install --upgrade pip
#Y29kZSBieSBqZWpvIAo=
# Install required dependencies
echo "[+] Installing dependencies..."
pip install scapy joblib numpy pandas scikit-learn tensorflow flask requests matplotlib netifaces psutil
#Y29kZSBieSBqZWpvIAo=
# Set permissions for Scapy (required for packet sniffing)
echo "[+] Granting raw socket permissions to Python..."
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
#Y29kZSBieSBqZWpvIAo=
# Verify installation
echo "[+] Verifying installation..."
python3 -c "import scapy; import joblib; import sklearn; import flask; print('All dependencies installed successfully!')"
#Y29kZSBieSBqZWpvIAo=
echo "[+] Setup complete! Use 'source myenv/bin/activate' to activate the virtual environment."
