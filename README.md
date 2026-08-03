# AWS Threat Detection Pipeline

A serverless AWS security monitoring pipeline that automatically scans AWS resources for potential security risks, generates findings, and sends email alerts through Amazon SNS.

## Features

- Detects Secrets Manager access events using CloudTrail
- Detects IAM access keys older than 90 days
- Sends formatted email alerts through Amazon SNS
- Runs automatically every day using EventBridge Scheduler
- Can also be executed locally for testing
- Returns structured JSON when invoked through AWS Lambda

---

## AWS Services Used

- AWS Lambda
- Amazon EventBridge Scheduler
- Amazon SNS
- AWS IAM
- AWS CloudTrail
- AWS Secrets Manager
- Amazon S3
- Boto3 (Python SDK)

---

## Architecture

```
EventBridge Scheduler
        │
        ▼
AWS Lambda
        │
        ▼
Threat Detection Logic
        │
 ┌──────┴─────────┐
 │                │
 ▼                ▼
CloudTrail     IAM
Secrets        Access Keys
        │
        ▼
Security Findings
        │
        ▼
Amazon SNS
        │
        ▼
Email Notification
```

---

## Detection Rules

### Secrets Manager

Detects access to AWS Secrets Manager secrets using CloudTrail events.

Outputs:

- User
- Secret accessed
- Source IP
- Timestamp
- Recommendation

---

### IAM Access Keys

Detects:

- Access keys older than 90 days

Outputs:

- IAM User
- Key Age
- Last Used
- Recommendation

---

## Example SNS Alert

```
AWS THREAT DETECTION PIPELINE

SECURITY ALERT

Severity: MEDIUM

Finding: IAM access key review

User: akhil

Reason:
Access key is older than 90 days.

Recommendation:
Rotate or delete the access key.
```

---

## Local Execution

```bash
python src/main.py
```

---

## AWS Deployment

- Upload project to AWS Lambda
- Configure environment variables
- Attach IAM execution role
- Configure EventBridge Scheduler
- Configure Amazon SNS topic
- Deploy

---

## Future Improvements

- GuardDuty integration
- Security Hub integration
- Slack notifications
- AWS Config compliance checks
- Multi-account scanning
- HTML email formatting
- CloudWatch dashboard
- Finding persistence using DynamoDB

---

## Author

Akhil Basani

Virginia Tech
Cybersecurity Management & Analytics