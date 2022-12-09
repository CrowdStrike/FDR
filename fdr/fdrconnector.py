import os
import sys
import configparser


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
        # Log setting
        self.log_level = config["Source Data"].get("LOG_LEVEL", "INFO")
        max_threads = config["Source Data"].get("MAX_THREADS", False)
        if not max_threads:
            self.max_threads = min(32, (os.cpu_count() or 1) * 4)
        else:
            self.max_threads = int(max_threads)
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
                    self.remove_local_file = False
                    if remove.lower() in "true,yes".split(","):  # pylint: disable=R1703
                        self.remove_local_file = True

                if config["Destination Data"]["IN_MEMORY_TRANSFER_ONLY"]:
                    # Transfer to S3 without using the local file system?
                    mem_trans = config["Destination Data"]["IN_MEMORY_TRANSFER_ONLY"]
                    self.in_memory_transfer_only = False
                    if mem_trans.lower() in "true,yes".split(","):  # pylint: disable=R1703
                        self.in_memory_transfer_only = True

                if config["Destination Data"]["DO_OCSF_CONVERSION"]:
                    ocsf_setting = config["Destination Data"].get("DO_OCSF_CONVERSION", "no")
                    self.do_ocsf = False
                    if ocsf_setting.lower() in "true,yes".split(","):
                        self.do_ocsf = True
                    if config["Destination Data"]["TARGET_ACCOUNT_ID"]:
                        # AWS Account ID
                        self.target_account_id = config["Destination Data"]["TARGET_ACCOUNT_ID"]

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
