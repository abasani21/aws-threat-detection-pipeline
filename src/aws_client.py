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