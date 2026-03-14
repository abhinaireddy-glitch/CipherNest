"""
agents/network_monitor.py

Stage 1 — Network Monitor Agent
INPUT  : data/sampled_30k_dataset.csv  (raw 30k flow records, 79 columns)
OUTPUT : pandas DataFrame with cleaned + enriched columns
         → passed directly into LogAnalyzerAgent.analyze(df)

New columns added here:
  - Fwd_Bwd_Packet_Ratio  : forward/backward packet asymmetry
  - Bytes_Per_Packet       : total bytes / total packets
  - Is_Short_Flow          : 1 if Flow Duration < 1000 microseconds
  - Is_High_Volume         : 1 if Flow Bytes/s in top 5%
  - Is_Attack_Port         : 1 if Destination Port is a commonly attacked port
"""

import pandas as pd
import numpy as np
import os


class NetworkMonitorAgent:
    def __init__(self, log_path="data/sampled_30k_dataset.csv"):
        self.log_path = log_path

    # ── Step 1: Load ──────────────────────────────────────────────────────────
    def load_logs(self):
        if not os.path.exists(self.log_path):
            raise FileNotFoundError(
                f"[NetworkMonitor] File not found: {self.log_path}\n"
                "Make sure sampled_30k_dataset.csv is inside the data/ folder."
            )
        df = pd.read_csv(self.log_path)
        print(f"[NetworkMonitor] Loaded {len(df)} rows, {len(df.columns)} columns.")
        return df

    # ── Step 2: Clean ─────────────────────────────────────────────────────────
    def clean(self, df):
        # Fill the 6 nulls in 'Flow Bytes/s' with 0
        df["Flow Bytes/s"] = df["Flow Bytes/s"].fillna(0)
        # Replace inf values that appear in flow-based datasets
        df.replace([np.inf, -np.inf], 0, inplace=True)
        print(f"[NetworkMonitor] Cleaned — nulls filled, inf values replaced.")
        return df

    # ── Step 3: Enrich with derived features ─────────────────────────────────
    def enrich(self, df):
        # Asymmetry between forward and backward packets (scans are very one-sided)
        df["Fwd_Bwd_Packet_Ratio"] = df["Total Fwd Packets"] / (
            df["Total Backward Packets"] + 1
        )

        # Average bytes per packet
        total_packets = df["Total Fwd Packets"] + df["Total Backward Packets"]
        total_bytes   = df["Total Length of Fwd Packets"] + df["Total Length of Bwd Packets"]
        df["Bytes_Per_Packet"] = total_bytes / (total_packets + 1)

        # Very short flow duration = likely probe or scan (in microseconds)
        df["Is_Short_Flow"] = (df["Flow Duration"] < 1000).astype(int)

        # Unusually high bandwidth = possible DDoS or exfil
        threshold = df["Flow Bytes/s"].quantile(0.95)
        df["Is_High_Volume"] = (df["Flow Bytes/s"] > threshold).astype(int)

        # Common attack target ports
        attack_ports = {80, 443, 22, 21, 3306, 8080, 23, 25}
        df["Is_Attack_Port"] = df["Destination Port"].isin(attack_ports).astype(int)

        print(f"[NetworkMonitor] Enriched — 5 derived features added. "
              f"Total columns: {len(df.columns)}")
        return df

    # ── Main entry ────────────────────────────────────────────────────────────
    def run(self):
        df = self.load_logs()
        df = self.clean(df)
        df = self.enrich(df)
        return df  # → LogAnalyzerAgent.analyze(df)
