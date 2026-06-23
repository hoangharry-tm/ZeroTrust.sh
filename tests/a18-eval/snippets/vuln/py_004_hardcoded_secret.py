import boto3
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
def upload(bucket, key, data):
    s3 = boto3.client("s3", aws_secret_access_key=AWS_SECRET_KEY)
    s3.put_object(Bucket=bucket, Key=key, Body=data)
