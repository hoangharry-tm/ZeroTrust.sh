# PY-007 V1/B,C: hardcoded credentials in connection string and dict
# Realistic AI-generated data pipeline config — multiple credential leaks
import pymongo
import redis
from sqlalchemy import create_engine


# VULN B: connection string with embedded password
DATABASE_URL = "postgresql://app_user:Pr0duct10nP@ssw0rd@db.prod.internal:5432/analytics"

# VULN B: MongoDB with credentials
MONGO_URL = "mongodb://admin:SuperSecretMongo123@mongo.prod.internal:27017/events"

# VULN B: Redis with password
REDIS_URL = "redis://:RedisPasswordForProd!@redis.prod.internal:6379/0"

# VULN C: credential dict
DB_CONFIG = {
    "host": "mysql.prod.internal",
    "port": 3306,
    "user": "pipeline_user",
    "password": "MySQLPassw0rd4Pipeline",  # VULN: dict credential
    "database": "etl_staging",
}

SMTP_CONFIG = {
    "host": "smtp.mailgun.org",
    "port": 587,
    "user": "postmaster@mg.example.com",
    "secret": "mailgun-smtp-password-abcdef123456",  # VULN: dict credential
}


def get_analytics_engine():
    return create_engine(DATABASE_URL)


def get_mongo_client():
    return pymongo.MongoClient(MONGO_URL)


def get_redis_client():
    return redis.from_url(REDIS_URL)
