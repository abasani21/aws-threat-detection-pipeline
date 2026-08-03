import json


def detect_secret_access(events):
    """
    Converts CloudTrail GetSecretValue events into security findings.
    """

    findings = []

    for event in events:
        cloudtrail_event = json.loads(event["CloudTrailEvent"])

        finding = {
            "severity": "HIGH",
            "title": "Secrets Manager secret accessed",
            "username": event.get("Username", "Unknown"),
            "event_time": str(event.get("EventTime", "Unknown")),
            "source_ip": cloudtrail_event.get("sourceIPAddress", "Unknown"),
            "secret_id": cloudtrail_event.get(
                "requestParameters", {}
            ).get("secretId", "Unknown"),
            "recommendation": "Verify that this secret access was authorized."
        }

        findings.append(finding)

    return findings