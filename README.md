# AWS Threat Detection Pipeline

A serverless AWS security monitoring pipeline that scans AWS resources for potential risks, classifies findings by severity, and sends automated email alerts through Amazon SNS.

## Overview

This project uses AWS Lambda and EventBridge Scheduler to run a daily security scan across selected AWS services.

The pipeline currently:

- inventories S3 buckets, IAM users, and Secrets Manager secrets
- analyzes CloudTrail `GetSecretValue` events
- reviews IAM access-key age and usage
- classifies findings as LOW, MEDIUM, HIGH, or CRITICAL
- sends SNS email notifications for MEDIUM-or-higher findings
- returns a structured summary from AWS Lambda

## Architecture

```text
EventBridge Scheduler
        |
        v
AWS Lambda
        |
        +-----------------------------+
        |              |              |
        v              v              v
       IAM        CloudTrail     Secrets Manager
        |              |              |
        +--------------+--------------+
                       |
                       v
               Detection Engine
                       |
                       v
                  Amazon SNS
                       |
                       v
                  Email Alert
```

## AWS Services

- AWS Lambda
- Amazon EventBridge Scheduler
- Amazon SNS
- AWS Identity and Access Management
- AWS CloudTrail
- AWS Secrets Manager
- Amazon S3
- Amazon CloudWatch Logs

## Detection Rules

### Secrets Manager access

The pipeline queries CloudTrail for `GetSecretValue` events and records:

- actor
- identity type
- secret identifier
- source IP address
- event time
- severity
- remediation recommendation

Approved IAM users produce LOW findings. Unapproved users or root access receive higher severity.

### IAM access-key review

The pipeline reviews each IAM user's access keys and records:

- masked access-key ID
- status
- age
- last-used time
- severity
- remediation recommendation

Active keys older than 90 days are treated as alertable findings.

## Example Lambda Response

```json
{
  "statusCode": 200,
  "body": {
    "secrets_findings": 2,
    "access_key_findings": 2,
    "alertable_findings": 1
  }
}
```

## Example SNS Alert

```text
[MEDIUM] AWS Threat Detection - IAM access key review

Finding: IAM access key review
User: akhil
Access Key: AKIA************SBUE
Reason: The access key is 205 days old.
Recommendation: Remove unused keys and rotate keys that exceed 90 days.
```

## Project Structure

```text
aws-threat-detection-pipeline/
├── src/
│   ├── aws_client.py
│   ├── config.py
│   ├── detectors.py
│   ├── main.py
│   └── reporter.py
├── docs/
├── reports/
├── screenshots/
├── tests/
├── requirements.txt
├── .gitignore
└── README.md
```

## Local Setup

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Configure the SNS topic ARN:

```bash
export SNS_TOPIC_ARN="YOUR_SNS_TOPIC_ARN"
export APPROVED_SECRET_USERS="your-iam-username"
```

Run locally:

```bash
python3 src/main.py
```

## Lambda Configuration

Handler:

```text
main.lambda_handler
```

Environment variables:

```text
SNS_TOPIC_ARN
APPROVED_SECRET_USERS
```

The Lambda execution role requires permission to:

- list S3 buckets
- list IAM users and access keys
- retrieve access-key last-used data
- list Secrets Manager secrets
- query CloudTrail events
- publish to the SNS topic
- write logs to CloudWatch

## Scheduling

EventBridge Scheduler invokes the Lambda function every day at 9:00 AM in the `America/New_York` time zone.

## Security Notes

- AWS credentials are not stored in the repository.
- Access-key IDs are masked in output.
- Lambda uses an IAM execution role rather than hardcoded credentials.
- Deployment ZIP files and virtual environments are excluded from Git.

## Future Improvements

- add public S3 bucket and security-group exposure checks
- persist findings in DynamoDB
- integrate AWS Security Hub or GuardDuty
- add Slack or Microsoft Teams notifications
- manage infrastructure with AWS SAM, CDK, or Terraform
- add automated unit and integration tests
- prevent duplicate alerts by tracking previously reported findings

## Author

Akhil Basani  
Virginia Tech