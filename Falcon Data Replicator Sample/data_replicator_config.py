# AWS security credentials
AWS_KEY = ""

AWS_SECRET = ""

# URL of SQS queue.
QUEUE_URL = ""

# Root directory to download files from S3 to.
OUTPUT_PATH = ""

# Time in seconds before a message is added back to the SQS queue if not deleted.  Ensure this is large enough for you
# to safely finish processing any downloaded files.
VISIBILITY_TIMEOUT = 300

# name of the aws region
REGION_NAME = ""
