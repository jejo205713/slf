import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Generate Sample Data
data = {
    "IP": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],  # Encoded IP addresses
    "Port": [80, 443, 22, 53, 8080, 3306, 21, 23, 25, 3389],  # Common ports
    "Bytes_Transferred": [500, 1500, 2000, 50, 7000, 9000, 600, 100, 4000, 10000],  # Traffic size
    "Is_Attack": [0, 0, 1, 0, 1, 1, 0, 0, 1, 1]  # 1 = attack, 0 = normal traffic
}

df = pd.DataFrame(data)

# Split Data
X = df.drop(columns=["Is_Attack"])  # Features
y = df["Is_Attack"]  # Target

# Train Model
model = RandomForestClassifier(n_estimators=10, random_state=42)
model.fit(X, y)

# Save Model
joblib.dump(model, "ai_firewall_model.pkl")
print("✅ AI Firewall Model Trained and Saved Successfully!")
