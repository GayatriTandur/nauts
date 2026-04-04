import json
import os


def load_memory(memory_file):
    """
    Memory Agent
    Loads stored incidents from JSON.
    """
    if os.path.exists(memory_file):
        try:
            with open(memory_file, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def store_incident(threat, investigation, response, memory_file):
    """
    Stores incident if not already present.
    """

    memory = load_memory(memory_file)

    incident = {
        "type": threat.get("type", "Unknown"),
        "user": threat.get("user", "Unknown"),
        "ip": threat.get("ip", "Unknown"),
        "severity": threat.get("severity", "Low"),
        "confidence": threat.get("confidence", 0),
        "risk_score": threat.get("risk_score", 0),
        "event": threat.get("event", "Unknown"),
        "timestamp": threat.get("timestamp", "Unknown"),
        "summary": investigation.get("summary", "No summary available"),
        "priority": investigation.get("priority", "P4 - Low"),
        "immediate_action": investigation.get("immediate_action", "Manual review required"),
        "recommended_action": investigation.get("recommended_action", []),
        "response": response
    }

    if incident not in memory:
        memory.append(incident)

    with open(memory_file, "w") as f:
        json.dump(memory, f, indent=4)


def save_memory(memory_file, data):
    """
    Saves the memory data to JSON file.
    """
    try:
        with open(memory_file, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error saving memory: {e}")
        
        