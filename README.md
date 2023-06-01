![CrowdStrike Falcon](https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png)<br/>[![Twitter URL](https://img.shields.io/twitter/url?label=Follow%20%40CrowdStrike&style=social&url=https%3A%2F%2Ftwitter.com%2FCrowdStrike)](https://twitter.com/CrowdStrike)<br/>
# Falcon Data Replicator
[![Bandit](https://github.com/CrowdStrike/FDR/actions/workflows/bandit.yml/badge.svg)](https://github.com/CrowdStrike/FDR/actions/workflows/bandit.yml)
[![Flake8](https://github.com/CrowdStrike/FDR/actions/workflows/linting.yml/badge.svg)](https://github.com/CrowdStrike/FDR/actions/workflows/linting.yml)
[![Python Lint](https://github.com/CrowdStrike/FDR/actions/workflows/pylint.yml/badge.svg)](https://github.com/CrowdStrike/FDR/actions/workflows/pylint.yml)
[![CodeQL](https://github.com/CrowdStrike/FDR/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/CrowdStrike/FDR/actions/workflows/codeql-analysis.yml)

The Falcon Data Replicator replicates log data from your CrowdStrike environment to a stand-alone target. This target can be a location on the file system, 
or a cloud storage bucket.
> Currently AWS is the only cloud provider implemented.
## Requirements
+ Python 3.6+
+ boto3
+ CrowdStrike Falcon FDR credentials
+ CrowdStrike Falcon FDR SQS queue URL
## Stand-alone solution
+ [falcon_data_replicator.ini](https://github.com/CrowdStrike/FDR/blob/main/falcon_data_replicator.ini) - Configuration file
+ [standalone/falcon_data_replicator.py](https://github.com/CrowdStrike/FDR/blob/main/standalone/falcon_data_replicator.py) - Stand-alone solution application file
### Configuration
The `falcon_data_replicator.ini` file contains all of the parameters necessary to configure the
solution for replication to the local file system and / or a storage bucket in AWS S3. After 
retrieving the AWS credentials and SQS queue details from your Falcon console, edit this file
to reflect your environment.
#### Required parameters
The following parameters must be provided in order for the solution to operate.
+ `AWS_KEY` - AWS client ID provided to you by the CrowdStrike Falcon console
+ `AWS_SECRET` - AWS client secret provided to you by the CrowdStrike Falcon console
+ `QUEUE_URL` - AWS SQS queue URL provided to you by the CrowdStrike Falcon console
+ `OUTPUT_PATH` - File path where downloaded files will be stored, not used for in-memory transfers
+ `VISIBILITY_TIMEOUT` - Time in seconds before a message is returned back to the SQS queue
+ `REGION_NAME` - The name of the AWS region where your CrowdStrike SQS queue resides
+ `MESSAGE_DELAY` - The time in seconds to wait in between the processing of each message
+ `QUEUE_DELAY` - The time in seconds to wait before each check of the queue for more messages
+ `LOG_FILE` - The name and path of the the log file
#### Destination parameters
The following parameters configure our destination details. If not these parameters are not present,
upload to our bucket is skipped and the local files are retained after download.
+ `TARGET_BUCKET` - The name of the AWS bucket we will use for our target destination
+ `TARGET_REGION` - The name of the AWS region our target bucket resides within
+ `REMOVE_LOCAL_FILE` - Boolean representing whether or not to remove local files after they are uploaded
+ `IN_MEMORY_TRANSFER_ONLY` - Transfer the file from the source bucket to the destination bucket without storing the file on the local file system.
+ `DO_OCSF_CONVERSION` - Boolean representing whether or not to convert the events to the OCSF format
+ `TARGET_ACCOUNT_ID` - The AWS account ID of the target bucket
+ `OCSF_ROLE_NAME` - The name of the role to use when writing to the target bucket
+ `OCSF_ROLE_EXTERNAL_ID` - The external ID to use when assuming the role provided by OCSF_ROLE_NAME. Default: `CrowdStrikeCustomSource`
+ `OCSF_INGEST_LATENCY` - The maximum amount of time (in minutes) to buffer records before publishing. Min: 5 Max: 60 Default: 5
+ `OCSF_MAX_FILE_SIZE` - Maximum size of a file in MB before it is uploaded. Min: 1 Max: 200 Default: 200
 > Note: Security Lake performance is sensitive to the number of files that must be read for a query. Use `OCSF_MAX_FILE_SIZE` and `OCSF_INGEST_LATENCY` to tune performance for your use case.
### Running the solution
After updating the configuration file to reflect your environment specifics, you can run this solution using:
```bash
python3 falcon_data_replicator.py
```
If your configuration file is not present in the same directory as the application file, you can reference
this path using the _-f_ or _--config_file_ command line parameters.
```bash
python3 falcon_data_replicator.py -f some_path/falcon_data_replicator.ini
```
## Container-based
_Coming soon_

