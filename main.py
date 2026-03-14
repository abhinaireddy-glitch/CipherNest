"""
main.py — CipherNest Pipeline Entry Point

Full flow:
  sampled_30k_dataset.csv
       ↓
  [1] NetworkMonitorAgent   — loads, cleans, enriches
       ↓ DataFrame (84 cols)
  [2] LogAnalyzerAgent      — heuristic rules → suspicious + suspicion_reason
       ↓ DataFrame (86 cols)
  [3] ThreatDetectorAgent   — IsolationForest ML → anomaly + anomaly_score
       ↓ DataFrame (88 cols)
  [4] OrchestratorAgent     — classifies attack_type + severity
       ↓ DataFrame (90 cols)
  [5] ResponderAgent        — takes action, saves all output files
       ↓
  data/processed_logs.csv
  data/blocked_ports.json
  data/response_actions.json
  data/threat_summary.json
"""

import sys
sys.stdout.reconfigure(encoding="utf-8")





from agents.network_monitor import NetworkMonitorAgent
from agents.log_analyzer    import LogAnalyzerAgent
from agents.threat_detector import ThreatDetectorAgent
from agents.orchestrator    import OrchestratorAgent
from agents.responder       import ResponderAgent

BANNER = """
╔══════════════════════════════════════════════════════════╗
║         CipherNest — AI Cybersecurity Defense SOC        ║
║      Multi-Agent Threat Detection & Response System      ║
╚══════════════════════════════════════════════════════════╝
"""

def run_pipeline():
    print(BANNER)

    print("━" * 58)
    print(" STAGE 1 │ Network Monitor Agent")
    print("━" * 58)
    monitor = NetworkMonitorAgent(log_path="data/sampled_30k_dataset.csv")
    df = monitor.run()

    print("\n" + "━" * 58)
    print(" STAGE 2 │ Log Analyzer Agent")
    print("━" * 58)
    df = LogAnalyzerAgent().analyze(df)

    print("\n" + "━" * 58)
    print(" STAGE 3 │ Threat Detector Agent  [IsolationForest ML]")
    print("━" * 58)
    df = ThreatDetectorAgent(contamination=0.05).run(df)

    print("\n" + "━" * 58)
    print(" STAGE 4 │ Orchestrator Agent")
    print("━" * 58)
    df = OrchestratorAgent().run(df)

    print("\n" + "━" * 58)
    print(" STAGE 5 │ Response Agent")
    print("━" * 58)
    df, summary = ResponderAgent(output_dir="data").run(df)

    print("\n" + "═" * 58)
    print("  PIPELINE COMPLETE")
    print("═" * 58)
    print(f"  Total Flows Processed : {summary['total_flows']}")
    print(f"  Threats Detected      : {summary['total_threats']}")
    print(f"  ML Anomalies          : {summary['total_anomalies']}")
    print(f"  Ports Blocked         : {summary['blocked_ports']}")
    print(f"  Response Actions      : {summary['response_actions']}")
    print("\n  Attack Breakdown:")
    for k, v in summary["attack_breakdown"].items():
        print(f"    {k:<20} {v}")
    print("\n  Output files ready in data/")
    print("  Start API: uvicorn api:app --reload --port 8000")
    print("═" * 58)


if __name__ == "__main__":
    run_pipeline()
