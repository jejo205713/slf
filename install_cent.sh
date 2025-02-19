
#!/bin/bash

echo "[+] Updating system and installing required packages..."
sudo yum update -y
sudo yum install -y python3 python3-pip

echo "[+] Creating virtual environment..."
python3 -m venv myenv

echo "[+] Activating virtual environment..."
source myenv/bin/activate

echo "[+] Upgrading pip..."
pip install --upgrade pip

echo "[+] Installing required dependencies..."
pip install scapy joblib numpy pandas scikit-learn tensorflow flask requests matplotlib netifaces psutil

echo "[+] Setting raw socket permissions for Python (required for Scapy)..."
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

echo "[+] Verifying installation..."
python3 -c "import scapy; import joblib; import sklearn; import flask; print('All dependencies installed successfully')"

echo "[+] Setup complete! Use 'source myenv/bin/activate' to activate the virtual environment."
