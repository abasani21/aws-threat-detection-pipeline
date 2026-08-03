from aws_client import (
    list_s3_buckets,
    list_iam_users,
    list_secrets,
    list_secret_access_events,
    list_iam_access_keys,
)

from detectors import detect_secret_access, detect_risky_access_keys


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

            secret_name = finding["secret_id"].split(":")[-1]
            print(f"Secret: {secret_name}")

            print(f"Source IP: {finding['source_ip']}")
            print(f"Time: {finding['event_time']}")
            print(f"Reason: {finding['reason']}")
            print(f"Recommendation: {finding['recommendation']}")
            print(f"Identity Type: {finding['identity_type']}")

    # This section must align with the "if not findings" line,
    # not sit inside the "for finding" loop.
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


if __name__ == "__main__":
    main()