"""
agents/log_analyzer.py

Stage 2 — Log Analyzer Agent
INPUT  : DataFrame from NetworkMonitorAgent.run()
         (has all original 79 cols + 5 enriched cols + Label col)
OUTPUT : Same DataFrame with 2 new columns added:
           - suspicious      : bool  — True if any heuristic rule fired
           - suspicion_reason: str   — semicolon-separated list of triggered rules
         → passed directly into ThreatDetectorAgent.run(df)

Rules are based on real network flow behavior:
  Rule 1 — Very high packet rate       → possible DDoS
  Rule 2 — Very short flow duration    → port scan / probe
  Rule 3 — High fwd/bwd asymmetry      → one-sided attack traffic
  Rule 4 — High volume + short flow    → flood attack
  Rule 5 — SYN flag with no ACK        → SYN scan or SYN flood
  Rule 6 — Many PSH flags              → web attack pattern (XSS/SQLi/BruteForce)
  Rule 7 — Zero backward packets       → unanswered probes (scan)
"""

import pandas as pd


class LogAnalyzerAgent:

    # Tuned thresholds based on dataset distribution
    HIGH_PACKET_RATE_THRESHOLD  = 10000   # Flow Packets/s
    SHORT_FLOW_THRESHOLD        = 1000    # Flow Duration (microseconds)
    HIGH_ASYMMETRY_THRESHOLD    = 10      # Fwd_Bwd_Packet_Ratio
    HIGH_VOLUME_FLOW_THRESHOLD  = 50000   # Flow Bytes/s
    PSH_FLAG_THRESHOLD          = 3       # PSH Flag Count

    def analyze(self, df):
        df = df.copy()
        df["suspicious"]       = False
        df["suspicion_reason"] = ""

        # Rule 1: Very high packet rate → DDoS / flood
        mask1 = df["Flow Packets/s"] > self.HIGH_PACKET_RATE_THRESHOLD
        df.loc[mask1, "suspicious"]        = True
        df.loc[mask1, "suspicion_reason"] += "high_packet_rate;"

        # Rule 2: Very short flow → port scan / probe
        mask2 = df["Is_Short_Flow"] == 1
        df.loc[mask2, "suspicious"]        = True
        df.loc[mask2, "suspicion_reason"] += "short_flow_probe;"

        # Rule 3: High forward/backward asymmetry → one-sided attack
        mask3 = df["Fwd_Bwd_Packet_Ratio"] > self.HIGH_ASYMMETRY_THRESHOLD
        df.loc[mask3, "suspicious"]        = True
        df.loc[mask3, "suspicion_reason"] += "high_fwd_bwd_asymmetry;"

        # Rule 4: High volume + short duration → flood attack
        mask4 = (df["Is_High_Volume"] == 1) & (df["Is_Short_Flow"] == 1)
        df.loc[mask4, "suspicious"]        = True
        df.loc[mask4, "suspicion_reason"] += "high_volume_short_flow;"

        # Rule 5: SYN flag present but ACK is 0 → SYN scan or flood
        mask5 = (df["SYN Flag Count"] > 0) & (df["ACK Flag Count"] == 0)
        df.loc[mask5, "suspicious"]        = True
        df.loc[mask5, "suspicion_reason"] += "syn_no_ack;"

        # Rule 6: Many PSH flags → web attack (XSS, SQLi, BruteForce send many pushes)
        mask6 = df["PSH Flag Count"] > self.PSH_FLAG_THRESHOLD
        df.loc[mask6, "suspicious"]        = True
        df.loc[mask6, "suspicion_reason"] += "high_psh_flags;"

        # Rule 7: No backward packets at all → unanswered probes
        mask7 = df["Total Backward Packets"] == 0
        df.loc[mask7, "suspicious"]        = True
        df.loc[mask7, "suspicion_reason"] += "no_backward_packets;"

        suspicious_count = df["suspicious"].sum()
        print(f"[LogAnalyzer] {suspicious_count} suspicious flows detected out of {len(df)} total.")
        return df  # → ThreatDetectorAgent.run(df)
