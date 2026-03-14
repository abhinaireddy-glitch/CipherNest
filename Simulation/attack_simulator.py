"""
simulation/attack_simulator.py
Generates synthetic network log data including normal traffic and attack patterns.
"""

import pandas as pd
import numpy as np
import random
import os
from datetime import datetime, timedelta

random.seed(42)
np.random.seed(42)

NORMAL_IPS = [f"192.168.1.{i}" for i in range(1, 20)]
ATTACK_IPS = ["10.0.0.99", "172.16.0.5", "45.33.32.156", "192.241.235.82", "198.20.70.114"]
PORTS = [80, 443, 22, 3306, 8080, 53, 21, 25]
PROTOCOLS = ["TCP", "UDP", "ICMP"]
STATUS_CODES = [200, 301, 403, 404, 500]

def generate_normal_event(timestamp):
    return {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": random.choice(NORMAL_IPS),
        "dst_ip": f"10.0.0.{random.randint(1, 5)}",
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice(PORTS),
        "protocol": random.choice(PROTOCOLS),
        "bytes_sent": random.randint(100, 5000),
        "packets": random.randint(1, 20),
        "duration": round(random.uniform(0.1, 5.0), 3),
        "status_code": random.choice(STATUS_CODES),
        "label": "normal"
    }

def generate_portscan_event(timestamp):
    attacker = random.choice(ATTACK_IPS)
    return {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": attacker,
        "dst_ip": f"10.0.0.{random.randint(1, 5)}",
        "src_port": random.randint(1024, 65535),
        "dst_port": random.randint(1, 1024),   # scanning low ports
        "protocol": "TCP",
        "bytes_sent": random.randint(40, 80),   # tiny packets
        "packets": random.randint(1, 3),
        "duration": round(random.uniform(0.001, 0.05), 4),  # very fast
        "status_code": 403,
        "label": "port_scan"
    }

def generate_ddos_event(timestamp):
    attacker = random.choice(ATTACK_IPS)
    return {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": attacker,
        "dst_ip": "10.0.0.1",
        "src_port": random.randint(1024, 65535),
        "dst_port": 80,
        "protocol": random.choice(["TCP", "UDP"]),
        "bytes_sent": random.randint(50000, 200000),  # huge traffic
        "packets": random.randint(1000, 5000),
        "duration": round(random.uniform(0.001, 0.1), 4),
        "status_code": 500,
        "label": "ddos"
    }

def generate_bruteforce_event(timestamp):
    attacker = random.choice(ATTACK_IPS)
    return {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": attacker,
        "dst_ip": f"10.0.0.{random.randint(1, 5)}",
        "src_port": random.randint(1024, 65535),
        "dst_port": 22,   # SSH brute force
        "protocol": "TCP",
        "bytes_sent": random.randint(200, 500),
        "packets": random.randint(5, 15),
        "duration": round(random.uniform(0.5, 2.0), 3),
        "status_code": 403,
        "label": "brute_force"
    }

def generate_logs(n_events=500):
    logs = []
    start_time = datetime.now() - timedelta(hours=2)

    for i in range(n_events):
        timestamp = start_time + timedelta(seconds=i * 10)
        roll = random.random()

        if roll < 0.70:
            logs.append(generate_normal_event(timestamp))
        elif roll < 0.82:
            logs.append(generate_portscan_event(timestamp))
        elif roll < 0.91:
            logs.append(generate_ddos_event(timestamp))
        else:
            logs.append(generate_bruteforce_event(timestamp))

    df = pd.DataFrame(logs)
    os.makedirs("data", exist_ok=True)
    df.to_csv("data/sample_logs.csv", index=False)
    print(f"[AttackSimulator] Generated {len(df)} log events → data/sample_logs.csv")
    print(df["label"].value_counts().to_string())
    return df

if __name__ == "__main__":
    generate_logs()
