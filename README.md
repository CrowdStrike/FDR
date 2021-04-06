# Falcon Data Replicator
The Falcon Data Replicator replicates log data from your CrowdStrike environment
to a stand-alone target. This target can be a location on the filesystem, or a 
cloud storage bucket.
> Currently AWS is the only cloud provider implemented.
## Requirements
+ Python 3.6+
+ boto3
+ CrowdStrike Falcon FDR credentials
+ CrowdStrike Falcon FDR SQS queue URL
## Stand-alone solution
+ `falcon_data_replicator.ini` - Configuration file
+ `standalone/falcon_data_replicator.py` - Stand-alone solution application file
### Configuration
The `falcon_data_replicator.ini` file contains all of the parameters necessary to configure the
solution for replication to the local file system and / or a storage bucket in AWS S3. After 
retreiving the AWS credentials and SQS queue details from your Falcon console, edit this file
to reflect your environment.
#### Required parameters
The following parameters must be provided in order for the solution to operate.
+ `AWS_KEY` - AWS client ID provided to you by the CrowdStrike Falcon console
+ `AWS_SECRET` - AWS client secret provided to you by the CrowdStrike Falcon console
+ `QUEUE_URL` - AWS SQS queue URL provided to you by the CrowdStrike Falcon console
+ `OUTPUT_PATH` - File path where downloaded files will be stored
+ `VISIBILITY_TIMEOUT` - Time in seconds before a message is returned back to the SQS queue
+ `REGION_NAME` - The name of the AWS region where your CrowdStrike SQS queue resides
+ `MESSAGE_DELAY` - The time in seconds to wait in between the processing of each message
+ `QUEUE_DELAY` - The time in seconds to wait before each check of the queue for more messages
#### Destination parameters
The following parameters configure our destination details. If not these parameters are not present,
upload to our bucket is skipped and the local files are retained after download.
+ `TARGET_BUCKET` - The name of the AWS bucket we will use for our target destination
+ `TARGET_REGION` - The name of the AWS region our target bucket resides within
+ `REMOVE_LOCAL_FILE` - Boolean representing whether or not to remove local files after they are uploaded
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

