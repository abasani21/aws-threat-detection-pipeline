import json

from config import APPROVED_SECRET_USERS


def detect_secret_access(events):
    """
    Converts CloudTrail GetSecretValue events into contextual security findings.
    """

    findings = []

    for event in events:
        cloudtrail_event = json.loads(event["CloudTrailEvent"])

        username = event.get("Username", "Unknown")
        identity_type = cloudtrail_event.get("userIdentity", {}).get(
            "type", "Unknown"
        )
        source_ip = cloudtrail_event.get("sourceIPAddress", "Unknown")
        secret_id = cloudtrail_event.get(
            "requestParameters", {}
        ).get("secretId", "Unknown")

        if identity_type == "Root":
            severity = "HIGH"
            reason = "The AWS root identity accessed a secret."
        elif username not in APPROVED_SECRET_USERS:
            severity = "MEDIUM"
            reason = "An unapproved IAM user accessed a secret."
        else:
            severity = "LOW"
            reason = "An approved IAM user accessed a secret."

        finding = {
            "severity": severity,
            "title": "Secrets Manager secret accessed",
            "reason": reason,
            "username": username,
            "identity_type": identity_type,
            "event_time": str(event.get("EventTime", "Unknown")),
            "source_ip": source_ip,
            "secret_id": secret_id,
            "recommendation": (
                "Confirm that the secret access was expected and review "
                "the identity's permissions."
            ),
        }

        findings.append(finding)

    return findings