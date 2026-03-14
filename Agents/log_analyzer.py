import json
from collections import defaultdict, Counter, deque
from datetime import datetime, timedelta
import pandas as pd

class LogAnalysisAgent:
    def __init__(self):
        """
        Initialize the real-time log analysis agent
        """
        self.alerts = []
        # Track repeated suspicious activity for trend analysis
        self.recent_alerts = deque(maxlen=1000)

    def add_alert(self, alert):
        """Receive a new alert from the Network Monitoring Agent"""
        self.alerts.append(alert)
        self.recent_alerts.append(alert)
        print(f"[LogAnalysis] New alert recorded: {alert['alert_type']} from {alert.get('source_ip')}")
        # Optional: update summaries in real-time
        self.display_summary_live(alert)

    def filter_alerts(self, **criteria):
        """Filter alerts based on arbitrary criteria"""
        filtered = self.alerts
        for key, value in criteria.items():
            if value is not None:
                filtered = [a for a in filtered if a.get(key) == value]
        return filtered

    def summarize_alerts(self):
        """Return summary statistics"""
        summary = defaultdict(dict)
        summary["alerts_by_type"] = dict(Counter(a["alert_type"] for a in self.alerts))
        summary["alerts_by_severity"] = dict(Counter(a["severity"] for a in self.alerts))
        summary["top_source_ips"] = Counter(a["source_ip"] for a in self.alerts if a.get("source_ip")).most_common(10)
        summary["top_destination_ips"] = Counter(a["destination_ip"] for a in self.alerts if a.get("destination_ip")).most_common(10)
        summary["top_ports"] = Counter(a["port"] for a in self.alerts if a.get("port")).most_common(10)
        return summary

    def display_summary(self):
        """Display full summary"""
        summary = self.summarize_alerts()
        print("\n--- ALERT SUMMARY ---")
        print("Alerts by Type:", summary["alerts_by_type"])
        print("Alerts by Severity:", summary["alerts_by_severity"])
        print("Top Source IPs:", summary["top_source_ips"])
        print("Top Destination IPs:", summary["top_destination_ips"])
        print("Top Ports:", summary["top_ports"])

    def display_summary_live(self, alert):
        """Display incremental summary for incoming alert"""
        print(f"[INFO] {alert['timestamp']} | {alert['alert_type']} | {alert.get('source_ip')} -> {alert.get('destination_ip')}")

    def generate_csv_report(self, filename="network_alert_summary.csv"):
        """Export all alerts to CSV"""
        if not self.alerts:
            print("[INFO] No alerts to export.")
            return
        df = pd.DataFrame(self.alerts)
        df.to_csv(filename, index=False)
        print(f"[INFO] CSV report generated: {filename}")
