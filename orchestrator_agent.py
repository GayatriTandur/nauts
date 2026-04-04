import pandas as pd
from ingestion_agent import ingest_logs
from memory_agent import load_memory, save_memory
from investigation_agent import investigate_threat

def classify_event(event):
    event = str(event).lower()
    if any(w in event for w in ["unauthorized", "malware", "ransomware"]):
        return {"type": "System Breach", "severity": "Critical", "score": 95}
    elif any(w in event for w in ["failed", "login", "brute"]):
        return {"type": "Auth Attack", "severity": "High", "score": 80}
    elif any(w in event for w in ["delete", "usb", "access"]):
        return {"type": "Policy Violation", "severity": "Medium", "score": 60}
    else:
        return {"type": "Anomaly", "severity": "Low", "score": 30}

def run_soc_pipeline(log_file, memory_file):
    df = ingest_logs(log_file)
    memory = load_memory(memory_file)
    results = []

    for _, row in df.iterrows():
        cls = classify_event(row.get("event", ""))
        threat = {
            "type": cls["type"],
            "user": row.get("user", "Unknown"),
            "ip": row.get("ip", "0.0.0.0"),
            "event": row.get("event", "Unknown"),
            "severity": cls["severity"],
            "risk_score": cls["score"],
            "timestamp": str(row.get("timestamp", "N/A"))
        }

        # Agent Investigation
        investigation = investigate_threat(threat)
        # Prepare the remediation plan
        response = f"Isolate IP {threat['ip']} and quarantine user {threat['user']}."

        results.append({"threat": threat, "investigation": investigation, "response": response})

    save_memory(memory_file, memory + [r["threat"] for r in results])
    return df, results





