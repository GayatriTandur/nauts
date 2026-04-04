def execute_response(threat):
    """
    Response Agent
    Simulates automated incident response.
    """

    severity = threat["severity"]

    if severity == "Critical":
        return (
            f"Critical response executed: blocked IP {threat['ip']}, "
            f"alerted security admin, and isolated affected endpoint."
        )

    elif severity == "High":
        return (
            f"High response executed: blocked IP {threat['ip']} "
            f"and flagged user {threat['user']} for urgent review."
        )

    elif severity == "Medium":
        return (
            f"Medium response executed: activity from IP {threat['ip']} "
            f"marked for close monitoring."
        )

    else:
        return (
            f"Low response executed: event from IP {threat['ip']} "
            f"logged for analyst review."
        )
    