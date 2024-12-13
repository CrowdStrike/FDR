import data_replicator_config
import json
import os
import time

try:
    import boto3
except ImportError as err:
    print(err)
    print(
        'boto3 is required to run data_replicator_sample_consumer.  Please "pip install boto3"!'
    )

###################################################################################################
# NOTE: See Falcon Data Replicator instructions for details on how  to use this sample consumer.  #
###################################################################################################

AWS_KEY = data_replicator_config.AWS_KEY
AWS_SECRET = data_replicator_config.AWS_SECRET
QUEUE_URL = data_replicator_config.QUEUE_URL
OUTPUT_PATH = os.path.realpath(data_replicator_config.OUTPUT_PATH)
VISIBILITY_TIMEOUT = data_replicator_config.VISIBILITY_TIMEOUT
REGION_NAME = data_replicator_config.REGION_NAME

sqs = boto3.resource(
    "sqs",
    region_name=REGION_NAME,
    aws_access_key_id=AWS_KEY,
    aws_secret_access_key=AWS_SECRET,
)
s3 = boto3.client(
    "s3",
    region_name=REGION_NAME,
    aws_access_key_id=AWS_KEY,
    aws_secret_access_key=AWS_SECRET,
)
queue = sqs.Queue(url=QUEUE_URL)


def handle_file(path):
    """PUT CUSTOM LOGIC FOR HANDLING FILES HERE"""
    print("Downloaded file to path %s" % path)


def download_message_files(msg):
    """Downloads the files from s3 referenced in msg and places them in OUTPUT_PATH.

    download_message_files function will iterate through every file listed at msg['filePaths'],
    move it to a local path with name "{OUTPUT_PATH}/{s3_path}",
    and then call handle_file(path).
    """

    # Construct output path for this message's files
    msg_output_path = os.path.realpath(os.path.join(OUTPUT_PATH, msg["pathPrefix"]))
    # Only write files to the specified output_path
    if os.path.commonpath([OUTPUT_PATH, msg_output_path]) != OUTPUT_PATH:
        print(
            f"Skipping {msg_output_path} to prevent writes outside of output path: {OUTPUT_PATH}"
        )
        return

    # Ensure directory exists at output path
    if not os.path.exists(msg_output_path):
        os.makedirs(msg_output_path)

    for s3_file in msg["files"]:
        try:
            s3_path = s3_file["path"]
            local_path = os.path.realpath(os.path.join(OUTPUT_PATH, s3_path))
            # only write files to the specified output path
            if os.path.commonpath([OUTPUT_PATH, local_path]) != OUTPUT_PATH:
                print(
                    f"Skipping {local_path} to prevent writes outside of output path: {OUTPUT_PATH}"
                )
                continue

            # Handle FDR platform and time partitioned folders
            if not os.path.exists(os.path.dirname(local_path)):
                os.makedirs(os.path.dirname(local_path))

            # Copy one file from s3 to local
            s3.download_file(msg["bucket"], s3_path, local_path)
            # Do something with file
            handle_file(local_path)
        except Exception as e:
            print(f"Error downloading file {s3_file['path']}: {e}")
            print(
                "\nIf you're unsure how to handle this error, open an issue on Github: https://github.com/CrowdStrike/FDR/issues or contact support.\n"
            )
            exit(1)


def consume_data_replicator():
    """Consume from data replicator and track number of messages/files/bytes downloaded."""

    sleep_time = 1
    msg_cnt = 0
    file_cnt = 0
    byte_cnt = 0

    while True:  # We want to continuously poll the queue for new messages.
        # Receive messages from queue if any exist (NOTE: receive_messages() only receives a few messages at a
        # time, it does NOT exhaust the queue)
        for msg in queue.receive_messages(VisibilityTimeout=VISIBILITY_TIMEOUT):
            msg_cnt += 1
            body = json.loads(msg.body)  # grab the actual message body
            download_message_files(body)
            file_cnt += body["fileCount"]
            byte_cnt += body["totalSize"]
            # msg.delete() must be called or the message will be returned to the SQS queue after
            # VISIBILITY_TIMEOUT seconds
            msg.delete()
            time.sleep(sleep_time)

        print(
            "Messages consumed: %i\tFile count: %i\tByte count: %i"
            % (msg_cnt, file_cnt, byte_cnt)
        )


if __name__ == "__main__":
    consume_data_replicator()
