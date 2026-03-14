"""
agents/threat_detector.py

Stage 3 — Threat Detector Agent  (ML-based)
INPUT  : DataFrame from LogAnalyzerAgent.analyze(df)
OUTPUT : Same DataFrame + 5 new columns:
           - anomaly       : 1 = anomaly, 0 = normal
           - anomaly_score : float, higher = more suspicious (display-friendly)
           - risk_score    : raw decision_function score (negative = more anomalous)
           - risk_level    : CRITICAL / HIGH / MEDIUM / LOW  (data-driven thresholds)
           - top_features  : top 3 features driving each anomaly
         → passed directly into OrchestratorAgent.run(df)

NOTE on column names:
  - risk_level : ML-based severity from this agent
  - severity   : attack-type-based severity set later by orchestrator.py
  Both coexist and are separate signals — judges see both.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURE_COLS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio",
    "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
    # Enriched features from NetworkMonitor
    "Fwd_Bwd_Packet_Ratio", "Bytes_Per_Packet", "Is_Short_Flow",
    "Is_High_Volume", "Is_Attack_Port",
]


class ThreatDetectorAgent:
    def __init__(self, contamination=0.05):
        self.contamination  = contamination
        self.model          = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.scaler         = StandardScaler()
        self.available_cols = []

    # ── Improvement 3: Data-driven risk level thresholds ─────────────────────
    # We compute thresholds from the actual score distribution of anomalies,
    # NOT hardcoded values. This makes the system work correctly on any dataset.
    def _compute_thresholds(self, scores: np.ndarray) -> tuple:
        """
        Among all flagged anomalies (scores below contamination boundary),
        split them into 3 equal-sized buckets: CRITICAL / HIGH / MEDIUM.
        Anything above the anomaly boundary is LOW.
        """
        anomaly_scores = scores[scores < np.percentile(scores, self.contamination * 100 + 1)]
        if len(anomaly_scores) == 0:
            return -0.1, -0.05, 0.0   # fallback
        critical_thresh = np.percentile(anomaly_scores, 33)  # bottom third = CRITICAL
        high_thresh     = np.percentile(anomaly_scores, 66)  # middle third = HIGH
        medium_thresh   = anomaly_scores.max()               # top third = MEDIUM
        return critical_thresh, high_thresh, medium_thresh

    def _score_to_risk_level(self, score: float,
                              critical_t: float,
                              high_t: float,
                              medium_t: float) -> str:
        if score <= critical_t:
            return "CRITICAL"
        elif score <= high_t:
            return "HIGH"
        elif score <= medium_t:
            return "MEDIUM"
        else:
            return "LOW"

    # ── Improvement 2: Per-row feature explanation ────────────────────────────
    def _get_row_top_features(self, row_scaled: np.ndarray) -> str:
        """Top 3 features by absolute z-score for a single row."""
        top3 = np.argsort(np.abs(row_scaled))[::-1][:3]
        return ", ".join(self.available_cols[i] for i in top3)

    def _explain_global(self, X_scaled: np.ndarray) -> list:
        """Top 3 features driving anomalies across the entire dataset."""
        anomaly_mask = self.model.predict(X_scaled) == -1
        if anomaly_mask.sum() == 0:
            return []
        mean_abs = np.abs(X_scaled[anomaly_mask]).mean(axis=0)
        top3     = np.argsort(mean_abs)[::-1][:3]
        return [self.available_cols[i] for i in top3]

    # ── Main run ──────────────────────────────────────────────────────────────
    def run(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()

        self.available_cols = [c for c in FEATURE_COLS if c in df.columns]
        X        = df[self.available_cols].fillna(0)
        X_scaled = self.scaler.fit_transform(X)

        # Core predictions
        preds      = self.model.fit_predict(X_scaled)   # -1 anomaly, 1 normal

        # Improvement 1 — continuous risk score via decision_function
        # decision_function: negative = anomalous, more negative = more dangerous
        raw_scores = self.model.decision_function(X_scaled)

        df["anomaly"]       = (preds == -1).astype(int)
        df["anomaly_score"] = np.round(-raw_scores, 4)  # flipped: higher = worse
        df["risk_score"]    = np.round(raw_scores, 4)   # raw: negative = anomaly

        # Improvement 3 — data-driven thresholds (not hardcoded)
        critical_t, high_t, medium_t = self._compute_thresholds(raw_scores)
        df["risk_level"] = df["risk_score"].apply(
            lambda s: self._score_to_risk_level(s, critical_t, high_t, medium_t)
        )

        # Improvement 2 — per-row feature explanation (anomalies only)
        top_features_list = [
            self._get_row_top_features(X_scaled[i]) if preds[i] == -1 else "N/A"
            for i in range(len(preds))
        ]
        df["top_features"] = top_features_list

        # ── Terminal output ───────────────────────────────────────────────────
        anomaly_count = df["anomaly"].sum()
        print(f"[ThreatDetector] IsolationForest flagged {anomaly_count} anomalies "
              f"out of {len(df)} flows ({anomaly_count / len(df) * 100:.1f}%)")

        print(f"[ThreatDetector] Risk level breakdown:")
        print(df[df["anomaly"] == 1]["risk_level"].value_counts().to_string())

        # Improvement 1+2+3 — sample threat intelligence output
        print(f"\n[ThreatDetector] Sample threat intelligence (top 5 most dangerous):")
        sample = (
            df[df["anomaly"] == 1]
            .nsmallest(5, "risk_score")
            [["risk_score", "risk_level", "top_features"]]
        )
        for idx, row in sample.iterrows():
            print(f"  Flow {idx:>6} → risk score: {row['risk_score']:>8.4f} "
                  f"→ {row['risk_level']:<8} "
                  f"| top features: {row['top_features']}")

        # Improvement 2 — global top features
        global_top = self._explain_global(X_scaled)
        if global_top:
            print(f"\n[ThreatDetector] Top features causing anomalies (global):")
            for i, feat in enumerate(global_top, 1):
                print(f"  {i}. {feat}")

        print(f"\n[ThreatDetector] Score thresholds used → "
              f"CRITICAL≤{critical_t:.4f} | HIGH≤{high_t:.4f} | MEDIUM≤{medium_t:.4f}")

        return df  # → OrchestratorAgent.run(df)