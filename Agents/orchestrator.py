"""
agents/orchestrator.py

Stage 4 — Orchestrator Agent
INPUT  : DataFrame from ThreatDetectorAgent.run(df)
         (has all cols + anomaly + anomaly_score + suspicious + suspicion_reason)
OUTPUT : Same DataFrame + 2 new columns:
           - attack_type : string  — classified attack category
           - severity    : string  — CRITICAL / HIGH / MEDIUM / LOW
         → passed directly into ResponderAgent.run(df)

Attack types mapped from real dataset Labels:
  BENIGN                      → normal
  Web Attack – Brute Force    → brute_force
  Web Attack – XSS            → xss
  Web Attack – Sql Injection  → sql_injection

For rows where Label is BENIGN but flagged as anomaly/suspicious,
the orchestrator uses heuristic rules to classify the attack type.
"""

import pandas as pd


# Exact label strings from the dataset (with special character)
LABEL_TO_ATTACK = {
    "BENIGN"                          : "normal",
    "Web Attack \u00ef\u00bf\u00bd Brute Force" : "brute_force",
    "Web Attack \u00ef\u00bf\u00bd XSS"         : "xss",
    "Web Attack \u00ef\u00bf\u00bd Sql Injection": "sql_injection",
}

SEVERITY_MAP = {
    "sql_injection" : "CRITICAL",
    "brute_force"   : "HIGH",
    "xss"           : "HIGH",
    "flood"         : "CRITICAL",
    "probe"         : "MEDIUM",
    "suspicious"    : "MEDIUM",
    "normal"        : "LOW",
}


class OrchestratorAgent:

    def _classify_by_rules(self, row):
        """
        For anomalies not covered by the Label column,
        use flow features + suspicion_reason to classify.
        """
        reasons = str(row.get("suspicion_reason", ""))

        if "high_packet_rate" in reasons or "high_volume_short_flow" in reasons:
            return "flood"
        if "short_flow_probe" in reasons or "syn_no_ack" in reasons:
            return "probe"
        if "high_psh_flags" in reasons:
            return "brute_force"   # repeated HTTP pushes = brute force pattern
        if row.get("suspicious", False):
            return "suspicious"
        return "normal"

    def run(self, df):
        df = df.copy()

        # Step 1: Map known labels from the dataset directly
        df["attack_type"] = df["Label"].map(LABEL_TO_ATTACK).fillna("unknown")

        # Step 2: For rows where Label says BENIGN but ML/heuristic flagged them,
        # reclassify using rules
        needs_reclassify = (
            (df["attack_type"] == "normal") &
            ((df["anomaly"] == 1) | (df["suspicious"] == True))
        )
        df.loc[needs_reclassify, "attack_type"] = df[needs_reclassify].apply(
            self._classify_by_rules, axis=1
        )

        # Step 3: Assign severity
        df["severity"] = df["attack_type"].map(SEVERITY_MAP).fillna("LOW")

        # Summary
        threat_df = df[df["attack_type"] != "normal"]
        print(f"[Orchestrator] Classified {len(threat_df)} threats out of {len(df)} flows:")
        print(df["attack_type"].value_counts().to_string())
        return df  # → ResponderAgent.run(df)
