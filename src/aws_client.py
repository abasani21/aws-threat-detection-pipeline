import boto3

def list_s3_buckets():
    """
    Connects to AWS and returns all S3 bucket names.
    """

    s3 = boto3.client("s3")

    response = s3.list_buckets()

    buckets = [bucket["Name"] for bucket in response["Buckets"]]

    return buckets

def list_iam_users():
    """
    Returns all IAM user names.
    """

    iam = boto3.client("iam")

    response = iam.list_users()

    users = [user["UserName"] for user in response["Users"]]

    return users

def list_secrets():
    """
    Returns all AWS Secrets Manager secret names.
    """

    secrets_client = boto3.client("secretsmanager")

    response = secrets_client.list_secrets()

    secrets = [secret["Name"] for secret in response.get("SecretList", [])]

    return secrets

def list_secret_access_events():
    """
    Returns CloudTrail GetSecretValue events.
    """

    cloudtrail = boto3.client("cloudtrail")

    response = cloudtrail.lookup_events(
        LookupAttributes=[
            {
                "AttributeKey": "EventName",
                "AttributeValue": "GetSecretValue"
            }
        ],
        MaxResults=10
    )

    return response["Events"]

def list_iam_access_keys():
    """
    Returns access-key details for every IAM user.
    """

    iam = boto3.client("iam")
    key_details = []

    users_response = iam.list_users()

    for user in users_response["Users"]:
        username = user["UserName"]

        keys_response = iam.list_access_keys(UserName=username)

        for key in keys_response["AccessKeyMetadata"]:
            last_used_response = iam.get_access_key_last_used(
                AccessKeyId=key["AccessKeyId"]
            )

            last_used = last_used_response["AccessKeyLastUsed"].get(
                "LastUsedDate"
            )

            key_details.append(
                {
                    "username": username,
                    "access_key_id": key["AccessKeyId"],
                    "status": key["Status"],
                    "create_date": key["CreateDate"],
                    "last_used_date": last_used,
                }
            )

    return key_details

def send_sns_alert(topic_arn, subject, message):
    """
    Publishes an alert message to an SNS topic.
    """

    sns = boto3.client("sns")

    response = sns.publish(
        TopicArn=topic_arn,
        Subject=subject,
        Message=message,
    )

    return response["MessageId"]