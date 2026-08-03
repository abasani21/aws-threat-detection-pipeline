from aws_client import (
    list_s3_buckets,
    list_iam_users,
    list_secrets,
    list_secret_access_events,
)

from detectors import detect_secret_access


def main():
    print("=" * 50)
    print("AWS Threat Detection Pipeline")
    print("=" * 50)

    buckets = list_s3_buckets()

    if not buckets:
        print("\nNo S3 buckets found.")
    else:
        print("\nS3 Buckets:")
        for bucket in buckets:
            print(f"- {bucket}")

    users = list_iam_users()

    if not users:
        print("\nNo IAM users found.")
    else:
        print("\nIAM Users:")
        for user in users:
            print(f"- {user}")

    secrets = list_secrets()

    if not secrets:
        print("\nNo Secrets Manager secrets found.")
    else:
        print("\nSecrets Manager Secrets:")
        for secret in secrets:
            print(f"- {secret}")

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
            print(f"Secret: {finding['secret_id']}")
            print(f"Source IP: {finding['source_ip']}")
            print(f"Time: {finding['event_time']}")
            print(f"Recommendation: {finding['recommendation']}")
            print(f"Reason: {finding['reason']}")
            print(f"Identity Type: {finding['identity_type']}")


if __name__ == "__main__":
    main()