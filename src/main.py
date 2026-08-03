from datetime import datetime

from aws_client import (
    list_s3_buckets,
    list_iam_users,
    list_secrets,
    list_secret_access_events,
    list_iam_access_keys,
    send_sns_alert,
)

from detectors import (
    detect_secret_access,
    detect_risky_access_keys,
)

from config import SNS_TOPIC_ARN


def main():
    print("=" * 60)
    print("AWS Threat Detection Pipeline")
    print("=" * 60)

    if not SNS_TOPIC_ARN:
        raise ValueError(
            "SNS_TOPIC_ARN environment variable is not configured."
        )

    # -----------------------------
    # S3 Buckets
    # -----------------------------
    buckets = list_s3_buckets()

    if not buckets:
        print("\nNo S3 buckets found.")
    else:
        print("\nS3 Buckets:")
        for bucket in buckets:
            print(f"- {bucket}")

    # -----------------------------
    # IAM Users
    # -----------------------------
    users = list_iam_users()

    if not users:
        print("\nNo IAM users found.")
    else:
        print("\nIAM Users:")
        for user in users:
            print(f"- {user}")

    # -----------------------------
    # Secrets Manager
    # -----------------------------
    secrets = list_secrets()

    if not secrets:
        print("\nNo Secrets Manager secrets found.")
    else:
        print("\nSecrets Manager Secrets:")
        for secret in secrets:
            print(f"- {secret}")

    # -----------------------------
    # Secret Access Detection
    # -----------------------------
    events = list_secret_access_events()
    findings = detect_secret_access(events)

    print("\nSecurity Findings:")

    if not findings:
        print("No secret access events found.")
    else:
        for finding in findings:
            print("\n" + "-" * 50)
            print(f"Severity: {finding['severity']}")
            print(f"Finding: {finding['title']}")
            print(f"User: {finding['username']}")

            secret_name = finding["secret_id"].split(":")[-1]
            print(f"Secret: {secret_name}")

            print(f"Source IP: {finding['source_ip']}")
            print(f"Time: {finding['event_time']}")
            print(f"Reason: {finding['reason']}")
            print(f"Recommendation: {finding['recommendation']}")
            print(f"Identity Type: {finding['identity_type']}")

    # -----------------------------
    # IAM Access Key Detection
    # -----------------------------
    access_keys = list_iam_access_keys()
    access_key_findings = detect_risky_access_keys(access_keys)

    print("\nIAM Access Key Findings:")

    if not access_key_findings:
        print("No IAM access keys found.")
    else:
        for finding in access_key_findings:

            masked_key = (
                finding["access_key_id"][:4]
                + "*" * 12
                + finding["access_key_id"][-4:]
            )

            print("\n" + "-" * 50)
            print(f"Severity: {finding['severity']}")
            print(f"Finding: {finding['title']}")
            print(f"User: {finding['username']}")
            print(f"Access Key: {masked_key}")
            print(f"Status: {finding['status']}")
            print(f"Age: {finding['age_days']} days")
            print(f"Last Used: {finding['last_used']}")
            print(f"Reason: {finding['reason']}")
            print(f"Recommendation: {finding['recommendation']}")

    # -----------------------------
    # SNS Alerts
    # -----------------------------
    alertable_findings = [
        finding
        for finding in findings + access_key_findings
        if finding["severity"] in {"MEDIUM", "HIGH", "CRITICAL"}
    ]

    if alertable_findings:

        highest_severity = alertable_findings[0]["severity"]

        message_lines = [
            "=" * 60,
            "AWS THREAT DETECTION PIPELINE",
            "=" * 60,
            "",
            "SECURITY ALERT",
            "",
            f"Severity: {highest_severity}",
            "",
        ]

        for finding in alertable_findings:

            message_lines.extend([
                "-" * 60,
                f"Finding: {finding['title']}",
                f"User: {finding.get('username', 'Unknown')}",
            ])

            if "access_key_id" in finding:
                masked_key = (
                    finding["access_key_id"][:4]
                    + "*" * 12
                    + finding["access_key_id"][-4:]
                )
                message_lines.append(f"Access Key: {masked_key}")

            if "secret_id" in finding:
                secret_name = finding["secret_id"].split(":")[-1]
                message_lines.append(f"Secret: {secret_name}")

            message_lines.extend([
                f"Reason: {finding['reason']}",
                f"Recommendation: {finding['recommendation']}",
                "",
            ])

        message_lines.extend([
            "=" * 60,
            "PIPELINE SUMMARY",
            "=" * 60,
            f"Secrets Findings: {len(findings)}",
            f"IAM Access Key Findings: {len(access_key_findings)}",
            f"Alertable Findings: {len(alertable_findings)}",
            "",
            f"Generated: {datetime.now()}",
        ])

        message = "\n".join(message_lines)

        message_id = send_sns_alert(
            SNS_TOPIC_ARN,
            f"[{highest_severity}] AWS Threat Detection - {alertable_findings[0]['title']}",
            message,
        )

        print("\nSNS alert sent successfully.")
        print(f"Message ID: {message_id}")

    else:
        print("\nNo MEDIUM or higher findings. SNS alert not sent.")

    # -----------------------------
    # Pipeline Summary
    # -----------------------------
    print("\n" + "=" * 60)
    print("Pipeline Summary")
    print("=" * 60)
    print(f"Secrets Findings:      {len(findings)}")
    print(f"IAM Key Findings:      {len(access_key_findings)}")
    print(f"Alertable Findings:    {len(alertable_findings)}")
    print("=" * 60)

    return {
        "secrets_findings": len(findings),
        "access_key_findings": len(access_key_findings),
        "alertable_findings": len(alertable_findings),
    }

def lambda_handler(event, context):
    summary = main()

    return {
        "statusCode": 200,
        "body": summary,
    }


if __name__ == "__main__":
    main()