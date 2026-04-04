import pandas as pd

def detect_patterns(df):
    """
    Detection Agent
    Detects suspicious behavior patterns in a generalized way.
    No hardcoded usernames or fixed IPs.
    """

    threats = []

    # ----------------------------
    # 1. Brute Force Attack
    # Rule: >= 5 failed logins by same user from same IP
    # ----------------------------
    failed = df[df["event"] == "LOGIN_FAILED"]
    grouped_failed = failed.groupby(["ip", "user"]).size().reset_index(name="count")

    for _, row in grouped_failed.iterrows():
        if row["count"] >= 5:
            threats.append({
                "type": "Brute Force Attack",
                "user": row["user"],
                "ip": row["ip"],
                "risk_score": min(95, 50 + row["count"] * 5),
                "reason": f"{row['count']} failed login attempts from same IP"
            })

    # ----------------------------
    # 2. Port Scanning
    # Rule: >= 3 PORT_SCAN events from same IP
    # ----------------------------
    scans = df[df["event"] == "PORT_SCAN"]
    grouped_scan = scans.groupby("ip").size().reset_index(name="count")

    for _, row in grouped_scan.iterrows():
        if row["count"] >= 3:
            threats.append({
                "type": "Port Scanning",
                "user": "Unknown",
                "ip": row["ip"],
                "risk_score": min(85, 40 + row["count"] * 10),
                "reason": f"{row['count']} suspicious port scan events"
            })

    # ----------------------------
    # 3. Malware Detection
    # Rule: any MALWARE_DETECTED event
    # ----------------------------
    malware = df[df["event"] == "MALWARE_DETECTED"]
    for _, row in malware.iterrows():
        threats.append({
            "type": "Malware Activity",
            "user": row["user"],
            "ip": row["ip"],
            "risk_score": 98,
            "reason": "Malware event detected in logs"
        })

    # ----------------------------
    # 4. Data Exfiltration
    # Rule: >= 4 DATA_DOWNLOAD events by same user/IP
    # ----------------------------
    downloads = df[df["event"] == "DATA_DOWNLOAD"]
    grouped_dl = downloads.groupby(["ip", "user"]).size().reset_index(name="count")

    for _, row in grouped_dl.iterrows():
        if row["count"] >= 4:
            threats.append({
                "type": "Possible Data Exfiltration",
                "user": row["user"],
                "ip": row["ip"],
                "risk_score": min(95, 55 + row["count"] * 8),
                "reason": f"{row['count']} suspicious download events"
            })

    # ----------------------------
    # 5. DDoS-like Activity
    # Rule: >= 20 REQUEST events from same IP
    # ----------------------------
    requests = df[df["event"] == "REQUEST"]
    grouped_req = requests.groupby("ip").size().reset_index(name="count")

    for _, row in grouped_req.iterrows():
        if row["count"] >= 20:
            threats.append({
                "type": "DDoS-like Activity",
                "user": "Unknown",
                "ip": row["ip"],
                "risk_score": min(99, 60 + row["count"]),
                "reason": f"{row['count']} rapid requests from same IP"
            })

    # ----------------------------
    # 6. Privilege Escalation
    # Rule: any PRIVILEGE_CHANGE event
    # ----------------------------
    privilege = df[df["event"] == "PRIVILEGE_CHANGE"]
    for _, row in privilege.iterrows():
        threats.append({
            "type": "Privilege Escalation Attempt",
            "user": row["user"],
            "ip": row["ip"],
            "risk_score": 96,
            "reason": "Privilege change event detected"
        })

    # ----------------------------
    # 7. Suspicious File Deletion
    # Rule: >= 3 FILE_DELETION events by same user/IP
    # ----------------------------
    deletion = df[df["event"] == "FILE_DELETION"]
    grouped_del = deletion.groupby(["ip", "user"]).size().reset_index(name="count")

    for _, row in grouped_del.iterrows():
        if row["count"] >= 3:
            threats.append({
                "type": "Suspicious File Deletion",
                "user": row["user"],
                "ip": row["ip"],
                "risk_score": min(92, 50 + row["count"] * 10),
                "reason": f"{row['count']} rapid file deletion events"
            })

    # ----------------------------
    # 8. External Device Usage
    # Rule: any USB_CONNECTED event
    # ----------------------------
    usb = df[df["event"] == "USB_CONNECTED"]
    for _, row in usb.iterrows():
        threats.append({
            "type": "External Device Usage",
            "user": row["user"],
            "ip": row["ip"],
            "risk_score": 45,
            "reason": "USB device connection detected"
        })

    # ----------------------------
    # 9. Suspicious Late-Night Login
    # Rule: LOGIN_SUCCESS between 11 PM and 4 AM
    # ----------------------------
    success = df[df["event"] == "LOGIN_SUCCESS"]
    for _, row in success.iterrows():
        hour = row["timestamp"].hour
        if hour >= 23 or hour <= 4:
            threats.append({
                "type": "Suspicious Late Night Login",
                "user": row["user"],
                "ip": row["ip"],
                "risk_score": 65,
                "reason": f"Successful login at unusual hour: {row['timestamp']}"
            })

    # ----------------------------
    # 10. Excessive File Access
    # Rule: >= 5 FILE_ACCESS events by same user/IP
    # ----------------------------
    access = df[df["event"] == "FILE_ACCESS"]
    grouped_access = access.groupby(["ip", "user"]).size().reset_index(name="count")

    for _, row in grouped_access.iterrows():
        if row["count"] >= 5:
            threats.append({
                "type": "Excessive File Access",
                "user": row["user"],
                "ip": row["ip"],
                "risk_score": min(85, 40 + row["count"] * 8),
                "reason": f"{row['count']} file access events in short period"
            })

    # ----------------------------
    # 11. Unknown Suspicious Activity
    # Rule: any unrecognized event
    # ----------------------------
    known_events = [
        "LOGIN_FAILED", "LOGIN_SUCCESS", "PORT_SCAN", "MALWARE_DETECTED",
        "DATA_DOWNLOAD", "REQUEST", "PRIVILEGE_CHANGE",
        "FILE_DELETION", "USB_CONNECTED", "FILE_ACCESS"
    ]

    unknown = df[~df["event"].isin(known_events)]
    for _, row in unknown.iterrows():
        threats.append({
            "type": "Unknown Suspicious Activity",
            "user": row["user"],
            "ip": row["ip"],
            "risk_score": 50,
            "reason": f"Unknown event detected: {row['event']}"
        })

    return threats