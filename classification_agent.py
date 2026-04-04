def classify_threat(threat):
    """
    Classification Agent
    Converts risk score into severity.
    """

    score = threat.get("risk_score", 50)

    if score >= 90:
        severity = "Critical"
        confidence = 95
    elif score >= 75:
        severity = "High"
        confidence = 88
    elif score >= 55:
        severity = "Medium"
        confidence = 75
    else:
        severity = "Low"
        confidence = 60

    threat["severity"] = severity
    threat["confidence"] = confidence

    return threat
