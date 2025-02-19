#!/bin/bash

echo "Updating package lists..."
sudo yum update -y

echo "Installing Python and required development tools..."
sudo yum install -y python3 python3-devel python3-pip

echo "Installing dependencies..."
pip3 install --upgrade pip
pip3 install scapy joblib numpy pandas scikit-learn tensorflow flask requests matplotlib netifaces psutil

echo "Checking installation..."
python3 -c "import scapy; import joblib; import numpy; import pandas; import sklearn; import tensorflow; import flask; import requests; import matplotlib; import netifaces; import psutil; print('✅ All dependencies installed successfully!')"

echo "Installation complete."
