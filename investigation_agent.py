import json

try:
    from openai import OpenAI
    client = OpenAI()
    OPENAI_AVAILABLE = True
except Exception:
    OPENAI_AVAILABLE = False


def local_fallback_analysis(threat):
    """
    Local rule-based fallback if OpenAI is unavailable.
    This ensures the project still works during demo/submission.
    """
    severity = threat.get("severity", "Low")
    threat_type = threat.get("type", "Unknown Threat")
    user = threat.get("user", "Unknown")
    ip = threat.get("ip", "Unknown")
    event = threat.get("event", "Unknown")

    if severity == "Critical":
        return {
            "summary": f"{threat_type} detected from user {user} at IP {ip}. This is a critical security threat requiring immediate containment.",
            "priority": "P1 - Immediate",
            "immediate_action": "Isolate the affected system and block suspicious IP immediately.",
            "recommended_action": [
                "Block the suspicious IP address",
                "Disable or lock the affected user account",
                "Isolate impacted machine or endpoint",
                "Perform malware/forensic investigation",
                "Escalate incident to security team immediately"
            ]
        }

    elif severity == "High":
        return {
            "summary": f"{threat_type} detected for user {user} from IP {ip}. This activity may indicate an authentication or phishing-related attack.",
            "priority": "P2 - High",
            "immediate_action": "Review account activity and temporarily secure the user account.",
            "recommended_action": [
                "Force password reset for the user",
                "Review recent login attempts and access history",
                "Check if MFA is enabled",
                "Block suspicious IP if repeated behavior is found",
                "Monitor the account for unusual behavior"
            ]
        }

    elif severity == "Medium":
        return {
            "summary": f"{threat_type} involving event '{event}' was detected for user {user}. This may indicate suspicious file or system activity.",
            "priority": "P3 - Medium",
            "immediate_action": "Review the affected file or system activity.",
            "recommended_action": [
                "Inspect affected files or deleted resources",
                "Review endpoint activity for anomalies",
                "Check whether sensitive files were accessed",
                "Verify whether removable devices were used",
                "Continue monitoring for escalation"
            ]
        }

    else:
        return {
            "summary": f"{threat_type} detected from user {user} at IP {ip}. The event appears low-risk but should still be monitored.",
            "priority": "P4 - Low",
            "immediate_action": "Monitor the event and review for repeated suspicious behavior.",
            "recommended_action": [
                "Review the suspicious log entry",
                "Monitor similar future events",
                "Check whether the event matches normal behavior",
                "Keep this activity in incident history",
                "Escalate only if repeated or correlated with other alerts"
            ]
        }


def investigate_threat(threat):
    """
    Investigation Agent
    Uses OpenAI (if available) to analyze a detected threat and generate:
    - summary
    - priority
    - immediate action
    - step-by-step action plan

    Falls back to local analysis if OpenAI is unavailable.
    """

    if not OPENAI_AVAILABLE:
        return local_fallback_analysis(threat)

    system_prompt = """
    You are an expert SOC (Security Operations Center) Investigation and Response Agent.

    Analyze the given cyber threat and return ONLY valid JSON in this exact format:

    {
        "summary": "brief explanation of the threat",
        "priority": "P1 - Immediate / P2 - High / P3 - Medium / P4 - Low",
        "immediate_action": "what should be done first right now",
        "recommended_action": [
            "step 1",
            "step 2",
            "step 3",
            "step 4"
        ]
    }

    Rules:
    - Critical threats must usually be P1 - Immediate
    - High threats must usually be P2 - High
    - Medium threats must usually be P3 - Medium
    - Low threats must usually be P4 - Low
    - Give practical cybersecurity response actions
    - Keep summary concise and professional
    - Return only valid JSON
    """

    user_prompt = f"""
    Analyze this detected cyber threat:

    {json.dumps(threat, indent=2)}

    Return only valid JSON.
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"}
        )

        result = response.choices[0].message.content
        parsed = json.loads(result)
        return parsed

    except Exception:
        return local_fallback_analysis(threat)
    
    
