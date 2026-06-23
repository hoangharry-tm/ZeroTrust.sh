import os, boto3
def upload(bucket: str, key: str, data: bytes) -> None:
    s3 = boto3.client(
        "s3",
        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
    )
    s3.put_object(Bucket=bucket, Key=key, Body=data)
