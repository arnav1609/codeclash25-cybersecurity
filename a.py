import subprocess
import time
import numpy as np
import logging
import pandas as pd
from flask import Flask, render_template, jsonify, request
import random
import threading
import plotly.graph_objs as go
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from stable_baselines3 import PPO  
from sklearn.linear_model import LinearRegression
from sklearn.cluster import KMeans
import sys
import os

# Fix NumPy compatibility issue
if not hasattr(np, "bool8"):
    np.bool8 = np.bool_

# Load dataset
dataset_path = "cleaned_numeric_IoT_dataset.csv"
df = pd.read_csv(dataset_path, dtype=str, low_memory=False)
df.columns = df.columns.str.strip()

# Target column
target_col = "label"
df[target_col] = df[target_col].astype(str)  
label_encoder = LabelEncoder()
df[target_col] = label_encoder.fit_transform(df[target_col])

# Convert all feature columns to numeric
df = df.apply(pd.to_numeric, errors='coerce').fillna(0)
X = df.drop(columns=[target_col])
y = df[target_col]

# Train AI model for risk scoring
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)
print("✅ AI Risk Scoring Model Trained!")

# Train Reinforcement Learning Model for Firewall Updates
firewall_model = PPO("MlpPolicy", "CartPole-v1", verbose=1)
print("✅ Reinforcement Learning Model Initialized!")

# Flask App
app = Flask(__name__)
logs, intrusion_data = [], []
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Define log_message function
def log_message(level, message):
    """Logs a message and stores it in the logs list."""
    log_entry = {"level": level, "message": message, "time": time.strftime("%Y-%m-%d %H:%M:%S")}
    logs.append(log_entry)
    logging.log(getattr(logging, level.upper(), logging.INFO), message)

# Secure Rollback Mechanism
def secure_firmware_rollback():
    log_message("critical", "🚨 Secure Firmware Rollback Triggered! Restoring previous stable state...")
    try:
        subprocess.Popen(["./restore_firmware.sh"])  
    except Exception as e:
        log_message("error", f"Firmware rollback failed: {e}")

    log_message("info", "Restarting intrusion monitoring and plotting...")
    start_intrusion_monitoring()  
    start_plotting_thread()  

def plot_intrusion_levels():
    """Continuously updates intrusion level visualization."""
    while True:
        time.sleep(5)  
        if intrusion_data:
            intrusion_levels = [entry["intrusion_level"] for entry in intrusion_data[-20:]]
            times = [time.strftime("%H:%M:%S", time.localtime(entry["time"])) for entry in intrusion_data[-20:]]

            fig = go.Figure()
            fig.add_trace(go.Scatter(x=times, y=intrusion_levels, mode="lines+markers", name="Intrusion Level"))
            print("🔄 Updating intrusion level plot...")  
@app.route("/predict_next_attack")
def predict_next_attack():
    attack_types = ["IoT Botnet", "Ransomware", "DDoS", "Malware", "Brute Force", "SQL Injection"]
    predicted_attack = random.choice(attack_types)
    predicted_severity = random.randint(30, 100)  # Simulate severity level

    return jsonify({
        "attack_type": predicted_attack,
        "severity": predicted_severity
    })            

# Function to start plotting in a separate thread
def start_plotting_thread():
    threading.Thread(target=plot_intrusion_levels, daemon=True).start()

# Containerized OS Recovery
def restart_security_container():
    log_message("critical", "🔄 Restarting security container due to high-severity threat...")
    subprocess.run(["docker", "restart", "security_container"], check=True)

# Function to Simulate Attacks
def detect_intrusion():
    base_level = 50
    while True:
        time.sleep(random.uniform(1, 3))
        change = np.random.randint(-10, 10)  
        base_level = max(0, min(100, base_level + change))
        
        attack_types = ["IoT Botnet", "Ransomware", "DDoS", "Malware", "Brute Force", "SQL Injection"]
        attack_type = random.choice(attack_types)
        severity = np.random.randint(1, 100)
        threat_type = "Low" if severity < 30 else "Medium" if severity < 60 else "High" if severity < 85 else "Critical"
        firewall_action = "Allow" if severity < 30 else "Monitor" if severity < 60 else "Rate Limit" if severity < 85 else "Block IP"

        latitude = round(random.uniform(-90, 90), 4)
        longitude = round(random.uniform(-180, 180), 4)

        intrusion_data.append({
            "time": time.time(),
            "intrusion_level": base_level,
            "attack_type": attack_type,
            "threat_type": threat_type,
            "severity": severity,
            "firewall_rule": firewall_action,
            "latitude": latitude,
            "longitude": longitude
        })

        log_message("warning", f"{attack_type} detected! Severity: {severity} ({threat_type}) - Firewall: {firewall_action} - Location: ({latitude}, {longitude})")

        if severity >= 85:
            secure_firmware_rollback()
            restart_security_container()

# Flask Routes
@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/logs")
def get_logs():
    return jsonify(logs[-10:])

@app.route("/intrusion_data")
def get_intrusion_data():
    return jsonify(intrusion_data[-20:])

@app.route("/critical_alerts")
def get_critical_alerts():
    critical_logs = [log for log in logs if "critical" in log["level"]]
    return jsonify(critical_logs[-5:])

@app.route("/attack_locations")
def get_attack_locations():
    locations = [
        {
            "latitude": entry.get("latitude", 0),  # Ensure default values
            "longitude": entry.get("longitude", 0),
            "attack_type": entry.get("attack_type", "Unknown"),
            "severity": entry.get("severity", 0)
        }
        for entry in intrusion_data[-20:] if "latitude" in entry and "longitude" in entry
    ]
    return jsonify(locations)
@app.route("/trigger_recovery", methods=["POST"])
def trigger_recovery():
    try:
        # Restart Flask by relaunching the script
        python = sys.executable  # Get Python executable path
        os.execl(python, python, *sys.argv)  # Restart the app

        return jsonify({"status": "success", "message": "Flask app is restarting!"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Recovery failed: {str(e)}"}), 500



# Start intrusion monitoring thread
def start_intrusion_monitoring():
    threading.Thread(target=detect_intrusion, daemon=True).start()

if __name__ == "__main__":
    start_intrusion_monitoring()
    start_plotting_thread()
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
