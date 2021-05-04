# Assisted Log Enabler - Find resources that are not logging, and turn them on.
This script is for customers who do not have logging turned on for various services, and lack knowledge of best practices and/or how to turn them on.

With this script, logging is turned on automatically for the various AWS Services for a customer:
* VPC Flow Logs (Single Account and Multi-Account using Organizations)
* CloudTrail (Single Account Only)
* EKS Audit and Authenticator Logs (Single Account Only)
* S3 Access Logs (future release)

## Use Case
There are customers of AWS who sometimes do not have logging turned on. When no logs are available, the ability to assist customers with analysis becomes limited, to the point that performing analysis may not be possible. Additionally, there are customers who use AWS that may not have the full technical expertise of how to set up logging for the various AWS services.

Assisted Log Enabler (ALE) is designed to ease the customer burden of learning how to turn on logs in the middle of a security incident. ALE performs the work of creating an S3 bucket, checking the services to see if logging is turned on, and activating logging when it's found to be off. When this is performed, the customer can be assured that logging within their AWS environment is active, in order to investigate future (and possibly ongoing) security incidents.

## Diagram
The following is a simple diagram on how Assisted Log Enabler works in a single account, in order to turn on logging for customers.
![Alt text](diagrams/assisted_log_enabler.png)

## Prerequesites
### Permissions
The following permissions are needed within AWS IAM for Assisted Log Enabler to run:
```
"ec2:DescribeVpcs",
"ec2:DescribeFlowLogs",
"ec2:CreateFlowLogs",
"logs:CreateLogDelivery",
"s3:GetBucketPolicy",
"s3:PutBucketPolicy",
"s3:PutLifecycleConfiguration"
"s3:PutObject",
"s3:CreateBucket",
"cloudtrail:StartLogging",
"cloudtrail:CreateTrail",
"cloudtrail:DescribeTrails",
"eks:UpdateClusterConfig",
"eks:ListClusters"
```
Additionally, if running from within a AWS Lambda function, the function will need the AWSLambdaBasicExecutionRole in order to run successfully. Please refer to the following link for more details: https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html

### Workflow Details
The following are the details of what happens within the Assisted Log Enabler workflow:
* A bucket is created within the customer's account.
* A Lifecycle Policy is created for the bucket, with the following parameters:
   * Converts files to Glacier-tier storage after 90 days
   * Deletes files after 365 days
* VPCs are checked to see if flow logs are turned on or off
* For VPCs that do not have flow logs turned on, VPC Flow Logging is turned on, and sent to the bucket created
   * VPC Flow Logs version 2, 3, 4, and 5 fields are all enabled
* CloudTrail service is checked to see there is at least one CloudTrail configured
* If no trail is configured, one is created and configured to log to the bucket created


### Running the Code
The code in it's current form can be ran inside the following:
* AWS CloudShell (preferred)
* AWS Lambda

```
python3 assisted_log_enabler.py

 █████  ███████ ███████ ██ ███████ ████████ ███████ ██████  
██   ██ ██      ██      ██ ██         ██    ██      ██   ██ 
███████ ███████ ███████ ██ ███████    ██    █████   ██   ██ 
██   ██      ██      ██ ██      ██    ██    ██      ██   ██ 
██   ██ ███████ ███████ ██ ███████    ██    ███████ ██████  
                                                            
                                                            
                ██       ██████   ██████                   
                ██      ██    ██ ██                        
                ██      ██    ██ ██   ███                  
                ██      ██    ██ ██    ██                  
                ███████  ██████   ██████                    
                                                            
                                                            
███████ ███    ██  █████  ██████  ██      ███████ ██████    
██      ████   ██ ██   ██ ██   ██ ██      ██      ██   ██   
█████   ██ ██  ██ ███████ ██████  ██      █████   ██████    
██      ██  ██ ██ ██   ██ ██   ██ ██      ██      ██   ██   
███████ ██   ████ ██   ██ ██████  ███████ ███████ ██   ██ 
         Joshua "DozerCat" McKiddy - Team DragonCat - AWS
         Type -h for help.

No valid option selected. Please run with -h to display valid options.
```
* Options
```
python3 assisted_log_enabler.py -h
usage: assisted_log_enabler.py [-h] [--single_account] [--multi_account]

Assisted Log Enabler - Find resources that are not logging, and turn them on.

optional arguments:
  -h, --help        show this help message and exit
  --single_account  Run Assisted Log Enabler against a single AWS account.
  --multi_account   Run Assisted Log Enabler against a multi account AWS environment.
                    WARNING: You must have the associated CloudFormation
                    template deployed as a StackSet before running this
                    option.
```

### Current Restrictions
* Currently, only the VPC Flow Logs can be turned on by the multi-account version.
   * Looking to add multi-account CloudTrail check in the next update.
   * Looking to add multi-account & multi-region EKS audit and authenticator logs in the next update.


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.


## License

This project is licensed under the Apache-2.0 License.
