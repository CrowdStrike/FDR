#  _____     _                   ____        _          ____            _ _           _
# |  ___|_ _| | ___ ___  _ __   |  _ \  __ _| |_ __ _  |  _ \ ___ _ __ | (_) ___ __ _| |_ ___  _ __
# | |_ / _` | |/ __/ _ \| '_ \  | | | |/ _` | __/ _` | | |_) / _ \ '_ \| | |/ __/ _` | __/ _ \| '__|
# |  _| (_| | | (_| (_) | | | | | |_| | (_| | || (_| | |  _ <  __/ |_) | | | (_| (_| | || (_) | |
# |_|  \__,_|_|\___\___/|_| |_| |____/ \__,_|\__\__,_| |_| \_\___| .__/|_|_|\___\__,_|\__\___/|_|
#                                                                |_|
###################################################################################################
# NOTE: See Falcon Data Replicator instructions for details on how to use this application.       #
###################################################################################################
#
import json
import os
import sys
import time
import pathlib
import signal
import configparser
import argparse

# This solution is dependant upon the AWS boto3 Python library
try:
    import boto3
except ImportError as err:
    print(err)
    print('The AWS boto3 library is required to run Falcon Data Replicator.\nPlease execute "pip3 install boto3"')


# This method is used as an exit handler. When a cancel or interrupt is received, this method forces
# FDR to finish processing the file it is working on before exiting.
def clean_exit(signal, frame):
    global EXIT
    EXIT = True
    return


parser = argparse.ArgumentParser("Falcon Data Replicator")
parser.add_argument("-f", "--config_file", dest="config_file", help="Path to the configuration file", required=False)
args = parser.parse_args()
if not args.config_file:
    config_file = "../falcon_data_replicator.ini"
else:
    config_file = args.config_file


# GLOBALS
config = configparser.ConfigParser()
config.read(config_file)
# We cannot read our source parameters, exit the routine
if "Source Data" not in config:
    print("Unable to load configuration file parameters. Routine halted.")
    sys.exit(1)

# AWS Client ID - Provided by CrowdStrike
AWS_KEY = config["Source Data"]["AWS_KEY"]
# AWS Client Secret - Provided by CrowdStrike
AWS_SECRET = config["Source Data"]["AWS_SECRET"]
# AWS SQS queue URL - Provided by CrowdStrike
QUEUE_URL = config["Source Data"]["QUEUE_URL"]
# Local file output location
OUTPUT_PATH = config["Source Data"]["OUTPUT_PATH"]
# Timeout before messages are returned to the queue
VISIBILITY_TIMEOUT = int(config["Source Data"]["VISIBILITY_TIMEOUT"])
# AWS Region name for our source S3 bucket
REGION_NAME = config["Source Data"]["REGION_NAME"]
TARGET_REGION_NAME = None  # Defaults to no upload
TARGET_BUCKET_NAME = None  # Defaults to no upload
REMOVE_LOCAL_FILE = False  # Defaults to keeping files locally
try:
    if "Destination Data" in config:
        # If it's not present, we don't need it
        if config["Destination Data"]["TARGET_BUCKET"]:
            # The name of our target S3 bucket
            TARGET_BUCKET_NAME = config["Destination Data"]["TARGET_BUCKET"]
except AttributeError:
    pass
try:
    if "Destination Data" in config:
        # If it's not present, we don't need it
        if config["Destination Data"]["TARGET_REGION"]:
            # The AWS region name our target S3 bucket resides in
            TARGET_REGION_NAME = config["Destination Data"]["TARGET_REGION"]
except AttributeError:
    pass
try:
    if "Destination Data" in config:
        # If it's not present, we don't need it
        if config["Destination Data"]["REMOVE_LOCAL_FILE"]:
            # Should we remove local files after we upload them?
            remove = config["Destination Data"]["REMOVE_LOCAL_FILE"]
            if remove.lower() in "true,yes":
                REMOVE_LOCAL_FILE = True
            else:
                REMOVE_LOCAL_FILE = False
except AttributeError:
    pass
# Default our run flag to on
EXIT = False

# Enable our graceful exit handler to allow uploads and artifact cleanup to complete
signal.signal(signal.SIGINT, clean_exit)
# Connect to our CrowdStrike provided SQS queue
sqs = boto3.resource('sqs', region_name=REGION_NAME, aws_access_key_id=AWS_KEY, aws_secret_access_key=AWS_SECRET)
# Connect to our CrowdStrike provided S3 bucket
s3 = boto3.client('s3', region_name=REGION_NAME, aws_access_key_id=AWS_KEY, aws_secret_access_key=AWS_SECRET)
# If we are doing S3 uploads
if TARGET_BUCKET_NAME and TARGET_REGION_NAME:
    # Connect to our target S3 bucket
    s3_target = boto3.client('s3', region_name=TARGET_REGION_NAME)  # Leveraging the existing client configuration to connect
# Create our queue object for handling message traffic
queue = sqs.Queue(url=QUEUE_URL)


def handle_file(path, key):
    """If configured, upload this file to our target bucket and remove it."""
    # If we've defined a target bucket
    if TARGET_BUCKET_NAME:
        # Open our local file (binary)
        with open(path, 'rb') as data:
            # Perform the upload to the same key in our target bucket
            s3_target.upload_fileobj(data, TARGET_BUCKET_NAME, key)
        print('Uploaded file to path %s' % key)
        # Only perform this step if configured to do so
        if REMOVE_LOCAL_FILE:
            # Remove the file from the local file system
            os.remove(path)
            print(f"Removed {path}")
            # Remove the temporary folder from the local file system
            os.rmdir(os.path.dirname(path))
            print(f"Removed {os.path.dirname(path)}")
            pure = pathlib.PurePath(path)
            # Remove the parent temporary folders if they exist
            os.rmdir(pure.parent.parent)
            print(f"Removed {pure.parent.parent}")
            if OUTPUT_PATH not in pure.parent.parent.parent.name:
                os.rmdir(pure.parent.parent.parent)
                print(f"Removed {pure.parent.parent.parent}")
    # We're done
    return True


def download_message_files(msg):
    """Downloads the files from s3 referenced in msg and places them in OUTPUT_PATH.

    download_message_files function will iterate through every file listed at msg['filePaths'],
    move it to a local path with name "{OUTPUT_PATH}/{s3_path}",
    and then call handle_file(path).
    """
    # Construct output path for this message's files
    msg_output_path = os.path.join(OUTPUT_PATH, msg['pathPrefix'])
    # Ensure directory exists at output path
    if not os.path.exists(msg_output_path):
        # Create it if it doesn't
        os.makedirs(msg_output_path)
    # For every file in our message
    for s3_file in msg['files']:
        # Retrieve the bucket path for this file
        s3_path = s3_file['path']
        # Create a local path name for our destination file based off of the S3 path
        local_path = os.path.join(OUTPUT_PATH, s3_path)
        # Open our local file for binary write
        with open(local_path, 'wb') as data:
            # Download the file from S3 into our opened local file
            s3.download_fileobj(msg['bucket'], s3_path, data)
        print('Downloaded file to path %s' % local_path)
        # Handle S3 upload if configured
        handle_file(local_path, s3_path)


def consume_data_replicator():
    """Consume from data replicator and track number of messages/files/bytes downloaded."""
    # Delay between message iterations
    sleep_time = 1
    # Tracking details
    msg_cnt = 0
    file_cnt = 0
    byte_cnt = 0

    # Continuously poll the queue for new messages.
    while not EXIT:
        # Receive messages from queue if any exist
        # (NOTE: receive_messages() only receives a few messages at a time, it does NOT exhaust the queue)
        for msg in queue.receive_messages(VisibilityTimeout=VISIBILITY_TIMEOUT):
            # Increment our message counter
            msg_cnt += 1
            # Grab the actual message body
            body = json.loads(msg.body)
            # Download the file to our local file system and potentially upload it to S3
            download_message_files(body)
            # Increment our file count by using the fileCount value in our message
            file_cnt += body['fileCount']
            # Increment our byte count by using the totalSize value in our message
            byte_cnt += body['totalSize']
            # Remove our message from the queue, if this is not performed in VISIBILITY_TIMEOUT seconds
            # this message will be restored to the queue for follow-up processing
            msg.delete()
            # Sleep until our next message iteration
            time.sleep(sleep_time)

        print("Messages consumed: %i\tFile count: %i\tByte count: %i" % (msg_cnt, file_cnt, byte_cnt))
    # We've requested an exit
    if EXIT:
        print("Routine exit requested.")


# Start our main routine
if __name__ == '__main__':
    consume_data_replicator()


#                     .
#      Your data      |  _____________________________________________________     ___
#          is here!   | |    _____                  ________      _ __        |  __
#            \ _______| |   / ___/______ _    _____/ / __/ /_____(_) /_____   |      ___
#             / _____ | |  / /__/ __/ _ \ |/|/ / _  /\ \/ __/ __/ /  '_/ -_)  |
#            / /(__) || |  \___/_/  \___/__,__/\_,_/___/\__/_/ /_/_/\_\\__/   |  ___
#   ________/ / |OO| || |                                                     |
#  | Hemi    |-------|| |                     --= FALCON DATA REPLICATOR >>   | ___
# (|         |     -.|| |_______________________                              |    ____
#  |  ____   \       ||_________||____________  |             ____      ____  |
# /| / __ \   |______||     / __ \   / __ \   | |            / __ \    / __ \ |\       ___
# \|| /  \ |_______________| /  \ |_| /  \ |__| |___________| /  \ |__| /  \|_|/
#    | () |                 | () |   | () |                  | () |    | () |     ____
#     \__/                   \__/     \__/                    \__/      \__/
