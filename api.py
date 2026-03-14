"""
api.py — FastAPI bridge between Python agents and React dashboard

Run with: uvicorn api:app --reload --port 8000

Endpoints your teammate can call from React:
  GET  /api/stats          → KPI summary (total flows, threats, blocked ports)
  GET  /api/logs           → full processed_logs.csv as JSON
  GET  /api/threats        → only rows where attack_type != normal
  GET  /api/blocked        → list of blocked ports
  GET  /api/actions        → response actions audit log
  GET  /api/attack-counts  → {attack_type: count} for charts
  POST /api/run-pipeline   → re-runs the full agent pipeline
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import json
import os
import subprocess

app = FastAPI(title="CipherNest API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # React dev server on any port
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_DIR = "data"

def read_json(filename):
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)

def read_csv(filename):
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        return None
    return pd.read_csv(path)


@app.get("/api/stats")
def get_stats():
    data = read_json("threat_summary.json")
    if data is None:
        return {"error": "Run python main.py first"}
    return data


@app.get("/api/logs")
def get_logs(limit: int = 500):
    df = read_csv("processed_logs.csv")
    if df is None:
        return {"error": "Run python main.py first"}
    df = df.fillna(0)
    return df.tail(limit).to_dict(orient="records")


@app.get("/api/threats")
def get_threats():
    df = read_csv("processed_logs.csv")
    if df is None:
        return {"error": "Run python main.py first"}
    threats = df[df["attack_type"] != "normal"].fillna(0)
    return threats.to_dict(orient="records")


@app.get("/api/blocked")
def get_blocked():
    data = read_json("blocked_ports.json")
    return data or []


@app.get("/api/actions")
def get_actions():
    data = read_json("response_actions.json")
    return data or []


@app.get("/api/attack-counts")
def get_attack_counts():
    df = read_csv("processed_logs.csv")
    if df is None:
        return {"error": "Run python main.py first"}
    counts = df["attack_type"].value_counts().to_dict()
    severity = df["severity"].value_counts().to_dict()
    return {"attack_types": counts, "severity_levels": severity}


@app.post("/api/run-pipeline")
def run_pipeline():
    try:
        result = subprocess.run(
            ["python", "main.py"],
            capture_output=True, text=True, timeout=120
        )
        return {
            "status" : "success" if result.returncode == 0 else "error",
            "output" : result.stdout,
            "errors" : result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "output": "Pipeline took too long"}
