from simulation.attack_simulator import simulate_attack
from agents.network_monitor import monitor_logs
from agents.log_analyzer import analyze_logs
from agents.threat_detector import detect_threats
from agents.orchestrator import orchestrate
from agents.responder import respond

simulate_attack()

data = monitor_logs()

data = analyze_logs(data)

data = detect_threats(data)

threats = orchestrate(data)

respond(threats)