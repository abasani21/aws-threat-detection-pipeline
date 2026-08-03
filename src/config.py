import os


APPROVED_SECRET_USERS = {
    user.strip()
    for user in os.getenv("APPROVED_SECRET_USERS", "").split(",")
    if user.strip()
}

SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN", "")