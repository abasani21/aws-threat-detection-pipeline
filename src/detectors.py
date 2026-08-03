import json

from datetime import datetime, timezone

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

def detect_risky_access_keys(access_keys, max_age_days=90):
    """
    Flags old, inactive, or never-used IAM access keys.
    """

    findings = []
    now = datetime.now(timezone.utc)

    for key in access_keys:
        create_date = key["create_date"]
        age_days = (now - create_date).days
        last_used = key["last_used_date"]

        if key["status"] == "Inactive":
            severity = "MEDIUM"
            reason = "The access key is inactive but still exists."
        elif last_used is None:
            severity = "HIGH"
            reason = "The access key has never been used."
        elif age_days >= max_age_days:
            severity = "MEDIUM"
            reason = f"The access key is {age_days} days old."
        else:
            severity = "LOW"
            reason = "The access key is active and below the age threshold."

        findings.append(
            {
                "severity": severity,
                "title": "IAM access key review",
                "username": key["username"],
                "access_key_id": key["access_key_id"],
                "status": key["status"],
                "age_days": age_days,
                "last_used": str(last_used) if last_used else "Never",
                "reason": reason,
                "recommendation": (
                    "Remove unused keys and rotate keys that exceed "
                    f"{max_age_days} days."
                ),
            }
        )

    return findings