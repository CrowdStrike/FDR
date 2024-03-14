"""Falcon Data Replicator - Local File System / AWS S3 connector"""
#  _____     _                   ____        _          ____            _ _           _
# |  ___|_ _| | ___ ___  _ __   |  _ \  __ _| |_ __ _  |  _ \ ___ _ __ | (_) ___ __ _| |_ ___  _ __
# | |_ / _` | |/ __/ _ \| '_ \  | | | |/ _` | __/ _` | | |_) / _ \ '_ \| | |/ __/ _` | __/ _ \| '__|
# |  _| (_| | | (_| (_) | | | | | |_| | (_| | || (_| | |  _ <  __/ |_) | | | (_| (_| | || (_) | |
# |_|  \__,_|_|\___\___/|_| |_| |____/ \__,_|\__\__,_| |_| \_\___| .__/|_|_|\___\__,_|\__\___/|_|
#                                                                |_|
# Local File System / AWS S3 connector
#
###################################################################################################
# NOTE: See https://github.com/CrowdStrike/FDR for details on how to use this application.        #
###################################################################################################
#
import json
import io
import os
import sys
import time
import pathlib
import signal as sig
import configparser
import argparse
import logging
from logging.handlers import RotatingFileHandler
from functools import partial

# This solution is dependant upon the AWS boto3 Python library
try:
    import boto3
except ImportError as err:
    print(err)
    print('The AWS boto3 library is required to run Falcon Data Replicator.\nPlease execute "pip3 install boto3"')
    sys.exit(1)


# Class to hold our connector config and to track our running status
class FDRConnector:  # pylint: disable=R0902
    """The FDRConnector class contains the details of this connection and tracks the status of our process."""
    def __init__(self, config: configparser.ConfigParser):
        """Initialize our status class"""
        self.set_exit(False)
        # We cannot read our source parameters, exit the routine
        if "Source Data" not in config:
            print("Unable to load configuration file parameters. Routine halted.")
            sys.exit(1)

        # AWS Client ID - Provided by CrowdStrike
        self.aws_key = config["Source Data"]["AWS_KEY"]
        # AWS Client Secret - Provided by CrowdStrike
        self.aws_secret = config["Source Data"]["AWS_SECRET"]
        # AWS SQS queue URL - Provided by CrowdStrike
        self.queue_url = config["Source Data"]["QUEUE_URL"]
        # Local file output location
        self.output_path = config["Source Data"]["OUTPUT_PATH"]
        # Timeout before messages are returned to the queue
        self.visibility_timeout = int(config["Source Data"]["VISIBILITY_TIMEOUT"])
        # Message delay
        self.message_delay = int(config["Source Data"]["MESSAGE_DELAY"])
        # Queue delay
        self.queue_delay = int(config["Source Data"]["QUEUE_DELAY"])
        # Log File
        self.log_file = config["Source Data"]["LOG_FILE"]
        # AWS Region name for our source S3 bucket
        self.region_name = config["Source Data"]["REGION_NAME"]
        self.in_memory_transfer_only = False  # Defaults to writing to the local file system
        self.target_region_name = None  # Defaults to no upload
        self.target_bucket_name = None  # Defaults to no upload
        self.remove_local_file = False  # Defaults to keeping files locally
        try:
            # Fail on these in order.  If REMOVE_LOCAL_FILE, or IN_MEMORY_TRANSFER_ONLY
            # fail, processing will still continue.
            if "Destination Data" in config:
                # If it's not present, we don't need it
                if config["Destination Data"]["TARGET_BUCKET"]:
                    # The name of our target S3 bucket
                    self.target_bucket_name = config["Destination Data"]["TARGET_BUCKET"]

                if config["Destination Data"]["TARGET_REGION"]:
                    # The AWS region name our target S3 bucket resides in
                    self.target_region_name = config["Destination Data"]["TARGET_REGION"]

                if config["Destination Data"]["REMOVE_LOCAL_FILE"]:
                    # Should we remove local files after we upload them?
                    remove = config["Destination Data"]["REMOVE_LOCAL_FILE"]
                    if remove.lower() in "true,yes".split(","):  # pylint: disable=R1703
                        self.remove_local_file = True
                    else:
                        self.remove_local_file = False

                if config["Destination Data"]["IN_MEMORY_TRANSFER_ONLY"]:
                    # Transfer to S3 without using the local file system?
                    mem_trans = config["Destination Data"]["IN_MEMORY_TRANSFER_ONLY"]
                    if mem_trans.lower() in "true,yes".split(","):  # pylint: disable=R1703
                        self.in_memory_transfer_only = True
                    else:
                        self.in_memory_transfer_only = False

        except KeyError:
            pass

    @property
    def exiting(self):
        """Returns the value of the exiting property"""
        return self.exiting

    @classmethod
    def set_exit(cls, val):
        """Sets the value of the exiting property"""
        cls.exiting = val
        return True


# This method is used as an exit handler. When a quit, cancel or interrupt is received,
# this method forces FDR to finish processing the file it is working on before exiting.
def clean_exit(stat, signal, frame):  # pylint: disable=W0613
    """Graceful exit handler for SIGINT, SIGQUIT and SIGTERM"""
    stat.set_exit(True)
    return True


def handle_file(path, key, file_object=None):
    """If configured, upload this file to our target bucket and remove it."""
    # If we've defined a target bucket
    if FDR.target_bucket_name:
        if not file_object:
            # Open our local file (binary)
            with open(path, 'rb') as data:
                # Perform the upload to the same key in our target bucket
                s3_target.upload_fileobj(data, FDR.target_bucket_name, key)
            logger.info('Uploaded file to path %s', key)
            # Only perform this step if configured to do so
            if FDR.remove_local_file:
                # Remove the file from the local file system
                os.remove(path)
                logger.info("Removed %s", path)
                # Remove the temporary folder from the local file system
                os.rmdir(os.path.dirname(path))
                logger.info("Removed %s", os.path.dirname(path))
                pure = pathlib.PurePath(path)
                # Remove the parent temporary folders if they exist
                os.rmdir(pure.parent.parent)
                logger.info("Removed %s", pure.parent.parent)
                if FDR.output_path not in pure.parent.parent.parent.name:
                    os.rmdir(pure.parent.parent.parent)
                    logger.info("Removed %s", pure.parent.parent.parent)
        else:
            s3_target.upload_fileobj(file_object, FDR.target_bucket_name, key)
            logger.info('Uploaded file to path %s', key)
    # We're done
    return True


def download_message_files(msg):
    """Downloads the files from s3 referenced in msg and places them in output_path.

    download_message_files function will iterate through every file listed at msg['filePaths'],
    move it to our output_path, and then call handle_file.
    """
    # Construct output path for this message's files
    msg_output_path = os.path.realpath(os.path.join(FDR.output_path, msg["pathPrefix"]))
    # Only write files to the specified output_path
    if os.path.commonpath([FDR.output_path, msg_output_path]) != FDR.output_path:
        logger.info(
            f"Skipping {msg_output_path} to prevent writes outside of output path: {FDR.output_path}"
        )
        return
    # Ensure directory exists at output path
    if not os.path.exists(msg_output_path):
        # Create it if it doesn't
        os.makedirs(msg_output_path)
    # For every file in our message
    for s3_file in msg['files']:
        # Retrieve the bucket path for this file
        s3_path = s3_file['path']
        if not FDR.in_memory_transfer_only:
            # Create a local path name for our destination file based off of the S3 path
            local_path = os.path.realpath(os.path.join(FDR.output_path, s3_path))
            # Only write files to the specified output_path
            if os.path.commonpath([FDR.output_path, local_path]) != FDR.output_path:
                logger.info(
                    f"Skipping {local_path} to prevent writes outside of output path: {FDR.output_path}"
                )
                continue
            # Open our local file for binary write
            with open(local_path, 'wb') as data:
                # Download the file from S3 into our opened local file
                s3.download_fileobj(msg['bucket'], s3_path, data)
            logger.info('Downloaded file to path %s', local_path)
            # Handle S3 upload if configured
            handle_file(local_path, s3_path, None)
        else:
            logger.info('Downloading file to memory')
            s3t = boto3.resource("s3",
                                 region_name=FDR.region_name,
                                 aws_access_key_id=FDR.aws_key,
                                 aws_secret_access_key=FDR.aws_secret
                                 )
            bkt = s3t.Bucket(msg['bucket'])
            obj = bkt.Object(s3_path)
            stream = io.BytesIO()
            obj.download_fileobj(stream)
            # Seek to the beginning of the stream before passing it to the upload handler
            stream.seek(0)
            handle_file(None, s3_path, stream)


def consume_data_replicator():
    """Consume from data replicator and track number of messages/files/bytes downloaded."""
    # Tracking details
    msg_cnt = 0
    file_cnt = 0
    byte_cnt = 0

    # Continuously poll the queue for new messages.
    while not FDR.exiting:
        received = False
        # Receive messages from queue if any exist
        # (NOTE: receive_messages() only receives a few messages at a time, it does NOT exhaust the queue)
        for msg in queue.receive_messages(VisibilityTimeout=FDR.visibility_timeout):
            received = True
            # Increment our message counter
            msg_cnt += 1
            logger.info("Processing message %i [%s]", msg_cnt, msg.message_id)
            # Grab the actual message body
            body = json.loads(msg.body)
            # Download the file to our local file system and potentially upload it to S3
            download_message_files(body)
            # Increment our file count by using the fileCount value in our message
            file_cnt += body['fileCount']
            # Increment our byte count by using the totalSize value in our message
            byte_cnt += body['totalSize']
            logger.info("Removing message %i [%s] from queue", msg_cnt, msg.message_id)
            # Remove our message from the queue, if this is not performed in visibility_timeout seconds
            # this message will be restored to the queue for follow-up processing
            msg.delete()
            # Sleep until our next message iteration
            time.sleep(FDR.message_delay)

        logger.info("Messages consumed: %i\tFile count: %i\tByte count: %i", msg_cnt, file_cnt, byte_cnt)
        if not received:
            logger.info("No messages received, sleeping for %i seconds", FDR.queue_delay)
            time.sleep(FDR.queue_delay)

    # We've requested an exit
    if FDR.exiting:
        # Clean exit
        logger.warning("Routine exit requested")
        sys.exit(0)
    else:
        # Something untoward has occurred
        logger.error("Unexpected exit occurred")
        sys.exit(1)


# Start our main routine
if __name__ == '__main__':
    # Configure our accepted command line parameters
    parser = argparse.ArgumentParser("Falcon Data Replicator")
    parser.add_argument("-f", "--config_file", dest="config_file", help="Path to the configuration file", required=False)
    # Parse any parameters passed at runtime
    args = parser.parse_args()
    # If we were not provided a configuration file name
    if not args.config_file:
        # Use the default name / location provided in our repo
        CONFIG_FILE = "../falcon_data_replicator.ini"
    else:
        # Use the configuration file provided at runtime
        CONFIG_FILE = args.config_file
    # Read in our configuration parameters
    configuration = configparser.ConfigParser()
    configuration.read(CONFIG_FILE)
    # Create our connector
    FDR = FDRConnector(configuration)
    # Setup our root logger
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    # Create our FDR logger
    logger = logging.getLogger("FDR Connector")
    # Rotate log file handler
    RFH = RotatingFileHandler(FDR.log_file, maxBytes=20971520, backupCount=5)
    # Log file output format
    F_FORMAT = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
    # Set the log file output level to INFO
    RFH.setLevel(logging.INFO)
    # Add our log file formatter to the log file handler
    RFH.setFormatter(F_FORMAT)
    # Add our log file handler to our logger
    logger.addHandler(RFH)
    # Log our pre-startup event
    logger.info(" _____ ____  ____        _")
    logger.info("|  ___|  _ \\|  _ \\      (.\\")
    logger.info("| |_  | | | | |_) |     |/(\\")
    logger.info("|  _| | |_| |  _ <       \\(\\\\")
    logger.info("|_|   |____/|_| \\_\\      \"^\"`\\")
    logger.info("Process starting up")
    # Enable our graceful exit handler to allow uploads and artifact
    # cleanup to complete for SIGINT, SIGTERM and SIGQUIT signals.
    sig.signal(sig.SIGINT, partial(clean_exit, FDR))
    sig.signal(sig.SIGTERM, partial(clean_exit, FDR))
    sig.signal(sig.SIGQUIT, partial(clean_exit, FDR))
    # Connect to our CrowdStrike provided SQS queue
    sqs = boto3.resource('sqs',
                         region_name=FDR.region_name,
                         aws_access_key_id=FDR.aws_key,
                         aws_secret_access_key=FDR.aws_secret
                         )
    # Connect to our CrowdStrike provided S3 bucket
    s3 = boto3.client('s3',
                      region_name=FDR.region_name,
                      aws_access_key_id=FDR.aws_key,
                      aws_secret_access_key=FDR.aws_secret
                      )
    # If we are doing S3 uploads
    if FDR.target_bucket_name and FDR.target_region_name:
        logger.info("Upload to AWS S3 enabled")
        # Connect to our target S3 bucket, uses the existing client configuration to connect (Not the CS provided ones)
        s3_target = boto3.client('s3', region_name=FDR.target_region_name)
    # Create our queue object for handling message traffic
    queue = sqs.Queue(url=FDR.queue_url)
    logger.info("Startup complete")
    # Start consuming the replicator feed
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
