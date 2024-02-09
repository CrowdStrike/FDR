r"""Falcon Data Replicator - Local File System / AWS S3 connector

 _____     _                   ____        _          ____            _ _           _
|  ___|_ _| | ___ ___  _ __   |  _ \  __ _| |_ __ _  |  _ \ ___ _ __ | (_) ___ __ _| |_ ___  _ __
| |_ / _` | |/ __/ _ \| '_ \  | | | |/ _` | __/ _` | | |_) / _ \ '_ \| | |/ __/ _` | __/ _ \| '__|
|  _| (_| | | (_| (_) | | | | | |_| | (_| | || (_| | |  _ <  __/ |_) | | | (_| (_| | || (_) | |
|_|  \__,_|_|\___\___/|_| |_| |____/ \__,_|\__\__,_| |_| \_\___| .__/|_|_|\___\__,_|\__\___/|_|
                                                               |_|

                      .
       Your data      |  _____________________________________________________     ___
           is here!   | |    _____                  ________      _ __        |  __
             \ _______| |   / ___/______ _    _____/ / __/ /_____(_) /_____   |      ___
              / _____ | |  / /__/ __/ _ \ |/|/ / _  /\ \/ __/ __/ /  '_/ -_)  |
             / /(__) || |  \___/_/  \___/__,__/\_,_/___/\__/_/ /_/_/\_\\__/   |  ___
    ________/ / |OO| || |                                                     |
   | Hemi    |-------|| |                     --= FALCON DATA REPLICATOR >>   | ___
  (|         |     -.|| |_______________________                              |    ____
   |  ____   \       ||_________||____________  |             ____      ____  |
  /| / __ \   |______||     / __ \   / __ \   | |            / __ \    / __ \ |\       ___
  \|| /  \ |_______________| /  \ |_| /  \ |__| |___________| /  \ |__| /  \|_|/
     | () |                 | () |   | () |                  | () |    | () |     ____
      \__/                   \__/     \__/                    \__/      \__/


                        Local File System / AWS S3 connector

NOTE: See https://github.com/CrowdStrike/FDR for details on how to use this application.
"""
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
from concurrent.futures import ThreadPoolExecutor
from threading import main_thread
from ocsf import transform_fdr_data_to_ocsf_data, upload_parquet_files_to_s3
from fdr.fdrconnector import FDRConnector

# This solution is dependant upon the AWS boto3 Python library
try:
    import boto3
except ImportError as err:
    print(err)
    raise SystemExit("The AWS boto3 library is required to run Falcon "
                     "Data Replicator.\nPlease execute 'pip3 install boto3'"
                     ) from err

try:
    from aws_assume_role_lib import assume_role
except ImportError as err:
    print(err)
    raise SystemExit("The aws-assume-role-lib library is required to run Falcon "
                     "Data Replicator.\nPlease execute 'pip3 install aws-assume-role-lib'"
                     ) from err
# Global FDR
FDR = None


# This method is used as an exit handler. When a quit, cancel or interrupt is received,
# this method forces FDR to finish processing the file it is working on before exiting.
def clean_exit(stat, signal, frame):  # pylint: disable=W0613
    """Graceful exit handler for SIGINT, SIGQUIT and SIGTERM"""
    stat.set_exit(True)
    return True


def do_keyed_delete(file_target: str, log: logging.Logger):
    """Remove temporary folder artifacts."""
    os.remove(file_target)
    os.rmdir(os.path.dirname(file_target))
    pure = pathlib.PurePath(file_target)
    # Remove the parent temporary folders if they exist
    try:
        os.rmdir(pure.parent.parent)
    except OSError:
        log.debug(f"Skipping deletion of {pure.parent.parent} as not empty.")
    else:
        log.debug("Removed %s", pure.parent.parent)
    if FDR.output_path not in pure.parent.parent.parent.name:
        try:
            os.rmdir(pure.parent.parent.parent)
        except OSError:
            log.debug(
                f"Skipping deletion of {pure.parent.parent.parent} as not empty.")
        else:
            log.debug("Removed %s", pure.parent.parent.parent)


def handle_file(path, key, target_bkt, file_object=None, log_util: logging.Logger = None):
    """Process the file. If configured, upload this file to our target bucket and remove it."""
    total_events_in_file = 0
    transform_time = 0
    upload_time = 0
    # If we've defined a target bucket
    if FDR.target_bucket_name:
        if not file_object:
            if FDR.do_ocsf:
                # Send the gzip'd file to be transformed and write it as parquet file
                start_transform_time = time.time()
                total_events_in_file = transform_fdr_data_to_ocsf_data(
                    FDR, path, log_util)
                transform_time = time.time() - start_transform_time
                # upload the file that meets the criteria
                start_upload_time = time.time()
                upload_parquet_files_to_s3(FDR, target_bkt, log_util)
                upload_time = time.time() - start_upload_time
            else:
                start_upload_time = time.time()
                # Open our local file (binary)
                with open(path, 'rb') as data:
                    # Perform the upload to the same key in our target bucket
                    target_bkt.upload_fileobj(
                        data, FDR.target_bucket_name, key)
                log_util.info('Uploaded file to path %s', key)
                upload_time = time.time() - start_upload_time
            # Only perform this step if configured to do so
            if FDR.remove_local_file:
                # Remove the file from the local file system
                do_keyed_delete(path, log_util)

        else:
            if FDR.do_ocsf:
                # OCSF conversion using IN Memory data from s3 source
                start_transform_time = time.time()
                total_events_in_file = transform_fdr_data_to_ocsf_data(
                    FDR, file_object, log_util)
                transform_time = time.time() - start_transform_time
                # upload the file that meets the criteria
                start_upload_time = time.time()
                upload_parquet_files_to_s3(FDR, target_bkt, log_util)
                upload_time = time.time() - start_upload_time
            else:
                start_upload_time = time.time()
                target_bkt.upload_fileobj(
                    file_object, FDR.target_bucket_name, key)
                log_util.info('Uploaded file to path %s', key)
                upload_time = time.time() - start_upload_time
            if os.path.exists(f"{FDR.output_path}/{key}"):
                # Something about our zip handling is leaving artifacts on the drive
                do_keyed_delete(f"{FDR.output_path}/{key}", log_util)
    # We're done
    return {'done': True, 'total_events_per_input_file': total_events_in_file,
            'transform_time_per_input_file': transform_time,
            'upload_time_per_input_file': upload_time
            }


def download_message_files(msg, s3ta, s3or, log: logging.Logger):
    """Download the file specified in the SQS message and trigger file handling."""
    # Construct output path for this message's files
    msg_output_path = os.path.join(FDR.output_path, msg['pathPrefix'])
    # Only write files to the specified output_path
    if os.path.commonpath([FDR.output_path, msg_output_path]) != FDR.output_path:
        return
    # Ensure directory exists at output path
    if not os.path.exists(msg_output_path):
        # Create it if it doesn't
        os.makedirs(msg_output_path)
    total_event_count = 0
    total_download_time_sec = 0.0
    total_transform_time_sec = 0.0
    total_upload_time_sec = 0.0
    # For every file in our message
    for s3_file in msg['files']:
        # Retrieve the bucket path for this file
        s3_path = s3_file['path']
        total_download_time_per_input_file = 0
        if not FDR.in_memory_transfer_only:
            # Create a local path name for our destination file based off of the S3 path
            local_path = os.path.join(FDR.output_path, s3_path)
            # Only write files to the specified output_path
            if os.path.commonpath([FDR.output_path, local_path]) != FDR.output_path:
                continue
            if not os.path.exists(os.path.dirname(local_path)):
                # Handle fdr platform and time partitioned folders
                os.makedirs(os.path.dirname(local_path))
            start_download_time = time.time()
            # Open our local file for binary write
            with open(local_path, 'wb') as data:
                # Download the file from S3 into our opened local file
                s3or.download_fileobj(msg['bucket'], s3_path, data)
            log.debug('Downloaded file to path %s', local_path)
            total_download_time_per_input_file = time.time() - start_download_time
            # Handle S3 upload if configured
            result = handle_file(local_path, s3_path, s3ta, None, log)
        else:
            log.debug('Downloading file to memory')
            start_download_time = time.time()
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
            total_download_time_per_input_file = time.time() - start_download_time
            result = handle_file(None, s3_path, s3ta, stream, log)

        total_event_count += result['total_events_per_input_file']
        total_download_time_sec += total_download_time_per_input_file
        total_transform_time_sec += result['transform_time_per_input_file']
        total_upload_time_sec += result['upload_time_per_input_file']
        # pif is per_input_file
        log.debug(
            'total_events_pif=%i, '
            'total_download_time_pif=%f, '
            'total_transform_time_pif=%f, '
            'total_upload_time_pif=%f, '
            'filepath=%s',
            result['total_events_per_input_file'],
            total_download_time_per_input_file,
            result['transform_time_per_input_file'],
            result['upload_time_per_input_file'],
            s3_path)

    return {'total_event_count': total_event_count,
            'total_download_time_sec': total_download_time_sec,
            'total_transform_time_sec': total_transform_time_sec,
            'total_upload_time_sec': total_upload_time_sec}


def process_queue_message(msg, s3b, s3o, log_util: logging.Logger):
    """Process the message off of the queue and trigger the file download."""
    log_util.debug("Processing message [%s]", msg.message_id)
    # Grab the actual message body
    body = json.loads(msg.body)
    # Download the file to our local file system and potentially upload it to S3
    metrics = download_message_files(body, s3b, s3o, log_util)
    log_util.debug("Removing message [%s] from queue", msg.message_id)
    # Remove our message from the queue, if this is not performed in visibility_timeout seconds
    # this message will be restored to the queue for follow-up processing
    msg.delete()

    return body['fileCount'], body['totalSize'], True, metrics


def do_shutdown(log_util: logging.Logger, clean: bool = False):
    """Perform a graceful shutdown."""
    if clean:
        log_util.warning("Routine exit requested")
        sys.exit(0)
    else:
        log_util.warning("Unexpected error occurred")
        sys.exit(1)


def consume_data_replicator(s3_bkt, s3_cs_bkt, log: logging.Logger):
    """Consume from data replicator and track number of messages/files/bytes downloaded."""
    # Tracking details
    total_event_count = 0
    total_download_time_sec = 0.0
    total_transform_time_sec = 0.0
    total_upload_time_sec = 0.0
    total_time_sec = 0.0
    msg_cnt = 0
    file_cnt = 0
    byte_cnt = 0

    # Continuously poll the queue for new messages.
    while not FDR.exiting:
        received = False
        # Receive messages from queue if any exist and send each message to it's own thread for processing
        # (NOTE: receive_messages() only receives a few messages at a time, it does NOT exhaust the queue)
        #
        with ThreadPoolExecutor(FDR.max_threads, thread_name_prefix="thread") as executor:
            futures = {
                executor.submit(process_queue_message, msg,
                                s3_bkt, s3_cs_bkt, log)
                for msg in queue.receive_messages(VisibilityTimeout=FDR.visibility_timeout, MaxNumberOfMessages=10)
            }
            max_total_download_time_sec = 0.0
            max_total_transform_time_sec = 0.0
            max_total_upload_time_sec = 0.0
            max_total_time_sec = 0.0
            for fut in futures:
                msg_cnt += 1
                res = fut.result()
                file_cnt += res[0]
                byte_cnt += res[1]
                received = res[2]
                total_event_count += res[3]['total_event_count']
                if max_total_download_time_sec < res[3]['total_download_time_sec']:
                    max_total_download_time_sec = res[3]['total_download_time_sec']
                if max_total_transform_time_sec < res[3]['total_transform_time_sec']:
                    max_total_transform_time_sec = res[3]['total_transform_time_sec']
                if max_total_upload_time_sec < res[3]['total_upload_time_sec']:
                    max_total_upload_time_sec = res[3]['total_upload_time_sec']
                m_tot_time_sec = max_total_download_time_sec + \
                    max_total_transform_time_sec + max_total_upload_time_sec
                max_total_time_sec = max(max_total_time_sec, m_tot_time_sec)

        if not received:
            log.info("No messages received, sleeping for %i seconds",
                     FDR.queue_delay)
            for _ in range(0, FDR.queue_delay):
                time.sleep(1)
                if FDR.exiting:
                    do_shutdown(log, True)
        else:
            total_download_time_sec += max_total_download_time_sec
            total_transform_time_sec += max_total_transform_time_sec
            total_upload_time_sec += max_total_upload_time_sec
            total_time_sec += max_total_time_sec
            log.info(
                "Messages_consumed: %i\t"
                "File_count: %i\t"
                "total_event_count: %i\t"
                "total_time_sec: %f\t"
                "total_download_time_sec: %f\t"
                "total_transform_time_sec: %f\t"
                "total_upload_time_sec: %f\t"
                "Byte_count: %i",
                msg_cnt,
                file_cnt,
                total_event_count,
                total_time_sec,
                total_download_time_sec,
                total_transform_time_sec,
                total_upload_time_sec,
                byte_cnt)

    # We've requested an exit
    if FDR.exiting:
        # Clean exit
        do_shutdown(log, True)
    else:
        # Something untoward has occurred
        do_shutdown(log, False)


def setup_logging(connector: FDRConnector):
    """Configure logging."""
    # Set our parent thread name
    thread = main_thread()
    thread.name = "main"
    # Ask boto to keep his voice down
    logging.getLogger('boto').setLevel(logging.CRITICAL)
    logging.getLogger('boto3').setLevel(logging.CRITICAL)
    logging.getLogger('botocore').setLevel(logging.CRITICAL)
    logging.getLogger('s3transfer').setLevel(logging.CRITICAL)
    logging.getLogger('urllib3').setLevel(logging.CRITICAL)
    # Log level
    log_level = logging.INFO
    if FDR.log_level.upper() == "DEBUG":
        log_level = logging.DEBUG
    # Setup our root logger
    logging.basicConfig(
        level=log_level, format="%(asctime)-8s %(levelname)-8s %(name)s/%(threadName)-10s %(message)s")
    # Create our FDR logger
    log_util = logging.getLogger("FDR")
    # Rotate log file handler
    rfh = RotatingFileHandler(
        connector.log_file, maxBytes=20971520, backupCount=5)
    # Log file output format
    f_format = logging.Formatter(
        '%(asctime)s %(levelname)-8s %(name)s/%(threadName)-10s %(message)s')
    # Set the log file output level to INFO
    rfh.setLevel(logging.INFO)
    # Add our log file formatter to the log file handler
    rfh.setFormatter(f_format)
    # Add our log file handler to our logger
    log_util.addHandler(rfh)
    # Log our pre-startup event
    log_util.info(" _____ ____  ____        _")
    log_util.info("|  ___|  _ \\|  _ \\      (.\\")
    log_util.info("| |_  | | | | |_) |     |/(\\")
    log_util.info("|  _| | |_| |  _ <       \\(\\\\")
    log_util.info("|_|   |____/|_| \\_\\      \"^\"`\\")
    log_util.info("Process starting up with Thread Count=%i", FDR.max_threads)

    return log_util


def setup_signal_handlers(connector: FDRConnector):
    """Setup our graceful exit handlers."""
    sig.signal(sig.SIGINT, partial(clean_exit, connector))
    sig.signal(sig.SIGTERM, partial(clean_exit, connector))
    sig.signal(sig.SIGQUIT, partial(clean_exit, connector))


def get_crowdstrike_aws_objects(connector: FDRConnector):
    """Retrieve the CrowdStrike AWS objects storing our FDR data."""
    sqs = boto3.resource('sqs',
                         region_name=connector.region_name,
                         aws_access_key_id=connector.aws_key,
                         aws_secret_access_key=connector.aws_secret
                         )
    # Connect to our CrowdStrike provided S3 bucket
    s3bkt = boto3.client('s3',
                         region_name=connector.region_name,
                         aws_access_key_id=connector.aws_key,
                         aws_secret_access_key=connector.aws_secret
                         )

    # Create our queue object for handling message traffic
    sqs_queue = sqs.Queue(url=FDR.queue_url)

    return sqs_queue, s3bkt


# pylint: disable=R0913
def get_aws_client(resource_type, account_id, aws_region, role_name, session_name, external_id, role_path='/'):
    """
    This function Assumes role and returns a client

    Args:
        resource_type (string): Resource type to initialize (Ex: ec2, s3)
        account_id (string): Target account Id to assume role
        aws_region (string): AWS region to initialize service
        role_name (string): Role name to assume
        session_name (string): Assume role session name
        external_id (string): External Id to assume role
        role_path (string): Role Path, default = '/'

    Returns:
        serviceClient (botocore client): botocore resource client

    """
    try:
        # Make Role ARN
        if role_path == '/':
            role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
        else:
            role_arn = f'arn:aws:iam::{account_id}:role/{role_path.lstrip("/").rstrip("/")}/{role_name}'

        # Assume role
        session = boto3.Session(region_name=aws_region)
        assumed_role_session = assume_role(session, role_arn, RoleSessionName=session_name, ExternalId=external_id)
        return assumed_role_session.client(resource_type, region_name=aws_region)

    except Exception as error:
        print(f'Failed to assume the role for Account: {account_id}: {error}')
        raise


def get_s3_target(connector: FDRConnector, log_util: logging.Logger):
    """Retrieve details for any S3 bucket uploads."""
    returned = None
    if FDR.target_bucket_name and connector.target_region_name:
        log_util.info("Upload to AWS S3 enabled")

        # Connect to our target S3 bucket, uses the existing
        # client configuration to connect (Not the CS provided ones)
        if connector.do_ocsf:
            returned = get_aws_client('s3',
                                      connector.target_account_id,
                                      connector.target_region_name,
                                      connector.ocsf_role_name,
                                      "CrowdStrikeCustomSource",
                                      connector.ocsf_role_external_id
                                      )
        else:
            returned = boto3.client(
                's3', region_name=connector.target_region_name)

    return returned


def consume_arguments():
    """Consume any provided command line arguments."""
    # Configure our accepted command line parameters
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-f", "--config_file", dest="config_file", help="Path to the configuration file",
                        required=False)
    # Parse any parameters passed at runtime
    return parser.parse_args()


def initialize_connector(cmd_line: argparse.Namespace):
    """Initialize an instance of our FDRConnector class."""
    # If we were not provided a configuration file name
    if not cmd_line.config_file:
        # Use the default name / location provided in our repo
        config_file = "falcon_data_replicator.ini"
    else:
        # Use the configuration file provided at runtime
        config_file = cmd_line.config_file
    # Read in our configuration parameters
    configuration = configparser.ConfigParser()
    configuration.read(config_file)
    # Create our connector
    return FDRConnector(configuration)


# Start our main routine
if __name__ == '__main__':
    # Consume any provided command line arguments
    cmdline = consume_arguments()
    # Initialize our FDR connector
    FDR = initialize_connector(cmdline)
    # Setup logging
    logger = setup_logging(FDR)
    # Enable our graceful exit handler to allow uploads and artifact
    # cleanup to complete for SIGINT, SIGTERM and SIGQUIT signals.
    setup_signal_handlers(FDR)
    # Connect to our CrowdStrike provided SQS queue and S3 bucket
    queue, s3_cs = get_crowdstrike_aws_objects(FDR)
    # If we are doing S3 uploads
    s3_target = get_s3_target(FDR, logger)
    logger.info("Startup complete")
    # Start consuming the replicator feed
    consume_data_replicator(s3_target, s3_cs, logger)
