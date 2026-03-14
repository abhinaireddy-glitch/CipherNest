"""
agents/responder.py

Stage 5 — Response Agent
INPUT  : DataFrame from OrchestratorAgent.run(df)
         (has all cols + attack_type + severity)
OUTPUT : 
  - Same DataFrame + response_action column
  - data/processed_logs.csv       ← full pipeline output for React dashboard
  - data/blocked_ips.json         ← list of blocked destination ports (no real IPs in dataset)
  - data/response_actions.json    ← audit log of every action taken
  - data/threat_summary.json      ← summary stats for dashboard KPI cards
"""

import pandas as pd
import json
import os
from datetime import datetime


# Ports blocked when a threat is detected targeting them
BLOCKED_PORTS = set()
ACTIONS_LOG   = []


class ResponderAgent:
    def __init__(self, output_dir="data"):
        self.output_dir   = output_dir
        self.blocked_ports = set()
        self.actions_log   = []
        os.makedirs(output_dir, exist_ok=True)

    def _take_action(self, row):
        severity = row["severity"]
        attack   = row["attack_type"]
        port     = int(row["Destination Port"])

        if severity == "CRITICAL":
            if port not in self.blocked_ports:
                self.blocked_ports.add(port)
                self.actions_log.append({
                    "timestamp"  : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "action"     : "BLOCK_PORT",
                    "target_port": port,
                    "attack_type": attack,
                    "severity"   : severity,
                })
            return "BLOCKED"

        elif severity == "HIGH":
            self.actions_log.append({
                "timestamp"  : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action"     : "ALERT_HIGH",
                "target_port": port,
                "attack_type": attack,
                "severity"   : severity,
            })
            return "ALERTED"

        elif severity == "MEDIUM":
            return "FLAGGED"

        return "NONE"

    def respond(self, df):
        df = df.copy()
        df["response_action"] = "NONE"

        threat_df = df[df["attack_type"] != "normal"]
        print(f"[Responder] Processing {len(threat_df)} threats...")

        for idx, row in threat_df.iterrows():
            action = self._take_action(row)
            df.at[idx, "response_action"] = action

        print(f"[Responder] Blocked ports : {sorted(self.blocked_ports)}")
        print(f"[Responder] Total actions  : {len(self.actions_log)}")
        return df

    def save_outputs(self, df):
        # 1. Full processed log (used by React dashboard /api/logs)
        logs_path = os.path.join(self.output_dir, "processed_logs.csv")
        df.to_csv(logs_path, index=False)
        print(f"[Responder] Saved → {logs_path}")

        # 2. Blocked ports (used by React dashboard /api/blocked)
        blocked_path = os.path.join(self.output_dir, "blocked_ports.json")
        with open(blocked_path, "w") as f:
            json.dump(sorted(list(self.blocked_ports)), f, indent=2)
        print(f"[Responder] Saved → {blocked_path}")

        # 3. Response actions audit log
        actions_path = os.path.join(self.output_dir, "response_actions.json")
        with open(actions_path, "w") as f:
            json.dump(self.actions_log, f, indent=2)
        print(f"[Responder] Saved → {actions_path}")

        # 4. Summary stats for dashboard KPI cards (/api/stats)
        attack_counts = df["attack_type"].value_counts().to_dict()
        severity_counts = df["severity"].value_counts().to_dict()
        summary = {
            "total_flows"     : int(len(df)),
            "total_threats"   : int((df["attack_type"] != "normal").sum()),
            "total_anomalies" : int(df["anomaly"].sum()),
            "blocked_ports"   : sorted(list(self.blocked_ports)),
            "attack_breakdown": attack_counts,
            "severity_breakdown": severity_counts,
            "response_actions": len(self.actions_log),
            "generated_at"    : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        summary_path = os.path.join(self.output_dir, "threat_summary.json")
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"[Responder] Saved → {summary_path}")

        return summary

    def run(self, df):
        df      = self.respond(df)
        summary = self.save_outputs(df)
        return df, summary
