#// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#// SPDX-License-Identifier: Apache-2.0
# Assisted Log Enabler (ALE) - Find resources that are not logging, and turn them on.
# Joshua "DozerCat" McKiddy - Team DragonCat - AWS


import logging
import os
import json
import boto3
import time
import datetime
from botocore.exceptions import ClientError
from datetime import timezone


current_date = datetime.datetime.now(tz=timezone.utc)
current_date_string = str(current_date)
timestamp_date = datetime.datetime.now(tz=timezone.utc).strftime("%Y%m%d%H%M%S")
timestamp_date_string = str(timestamp_date)


sts = boto3.client('sts')
s3 = boto3.client('s3')
cloudtrail = boto3.client('cloudtrail')
region = os.environ['AWS_REGION']


region_list = ['af-south-1', 'ap-east-1', 'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'me-south-1', 'sa-east-1', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']


# 1. Create a Bucket and Lifecycle Policy
def create_bucket():
    """Function to create the bucket for storing logs"""
    try:
        account_number = sts.get_caller_identity()["Account"]
        logging.info("Creating bucket in %s" % account_number)
        logging.info("CreateBucket API Call")
        if region == 'us-east-1':
            logging_bucket_dict = s3.create_bucket(
                Bucket="aws-log-collection-" + account_number + "-" + region
            )
        else:
            logging_bucket_dict = s3.create_bucket(
                Bucket="aws-log-collection-" + account_number + "-" + region,
                CreateBucketConfiguration={
                    'LocationConstraint': region
                }
            )
        logging.info("Bucket Created.")
        logging.info("Setting lifecycle policy.")
        logging.info("PutBucketLifecycleConfiguration API Call")
        lifecycle_policy = s3.put_bucket_lifecycle_configuration(
            Bucket="aws-log-collection-" + account_number + "-" + region,
            LifecycleConfiguration={
                'Rules': [
                    {
                        'Expiration': {
                            'Days': 365
                        },
                        'Status': 'Enabled',
                        'Prefix': '',
                        'ID': 'LogStorage',
                        'Transitions': [
                            {
                                'Days': 90,
                                'StorageClass': 'INTELLIGENT_TIERING'
                            }
                        ]
                    }
                ]
            }
        )
        logging.info("Lifecycle Policy successfully set.")
        logging.info("PutObject API Call")
        create_ct_path = s3.put_object(
            Bucket="aws-log-collection-" + account_number + "-" + region,
            Key='cloudtrail/AWSLogs/' + account_number + '/')
        logging.info("PutBucketPolicy API Call")
        bucket_policy = s3.put_bucket_policy(
            Bucket="aws-log-collection-" + account_number + "-" + region,
            Policy='{"Version": "2012-10-17", "Statement": [{"Sid": "AWSCloudTrailAclCheck20150319","Effect": "Allow","Principal": {"Service": "cloudtrail.amazonaws.com"},"Action": "s3:GetBucketAcl","Resource": "arn:aws:s3:::aws-log-collection-' + account_number + '-' + region + '"},{"Sid": "AWSCloudTrailWrite20150319","Effect": "Allow","Principal": {"Service": "cloudtrail.amazonaws.com"},"Action": "s3:PutObject","Resource": "arn:aws:s3:::aws-log-collection-' + account_number + '-' + region + '/cloudtrail/AWSLogs/' + account_number + '/*","Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}}]}'
        )
        logging.info("Setting the S3 bucket Public Access to Blocked")
        logging.info("PutPublicAccessBlock API Call")
        bucket_private = s3.put_public_access_block(
            Bucket="aws-log-collection-" + account_number + "-" + region,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            },
        )
    except Exception as exception_handle:
        logging.error(exception_handle)
    return account_number


# 2. Find VPCs and turn flow logs on if not on already.
def flow_log_activator(region_list, account_number):
    """Function that turns on the VPC Flow Logs, for VPCs identifed without them"""
    for aws_region in region_list:
        ec2 = boto3.client('ec2', region_name=aws_region)
        logging.info("Creating a list of VPCs without Flow Logs on in region " + aws_region + ".")
        try:
            VPCList: list = []
            FlowLogList: list = []
            logging.info("DescribeVpcs API Call")
            vpcs = ec2.describe_vpcs()
            for vpc_id in vpcs["Vpcs"]:
                VPCList.append(vpc_id["VpcId"])
            logging.info("List of VPCs found within account " + account_number + ", region " + aws_region + ":")
            print(VPCList)
            logging.info("DescribeFlowLogs API Call")
            vpcflowloglist = ec2.describe_flow_logs()
            for resource_id in vpcflowloglist["FlowLogs"]:
                FlowLogList.append(resource_id["ResourceId"])
            working_list = (list(set(VPCList) - set(FlowLogList)))
            logging.info("List of VPCs found within account " + account_number + ", region " + aws_region + " WITHOUT VPC Flow Logs:")
            print(working_list)
            for no_logs in working_list:
                logging.info(no_logs + " does not have VPC Flow logging on. It will be turned on within this function.")
            logging.info("Activating logs for VPCs that do not have them turned on.")
            logging.info("If all VPCs have Flow Logs turned on, you will get an MissingParameter error. That is normal.")
            logging.info("CreateFlowLogs API Call")
            flow_log_on =  ec2.create_flow_logs(
                ResourceIds=working_list,
                ResourceType='VPC',
                TrafficType='ALL',
                LogDestinationType='s3',
                LogDestination='arn:aws:s3:::aws-log-collection-' + account_number + '-' + region + '/vpcflowlogs',
                LogFormat='${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${type} ${tcp-flags} ${subnet-id} ${sublocation-type} ${sublocation-id} ${region} ${pkt-srcaddr} ${pkt-dstaddr} ${instance-id} ${az-id} ${pkt-src-aws-service} ${pkt-dst-aws-service} ${flow-direction} ${traffic-path}'
            )
            logging.info("VPC Flow Logs are turned on.")
        except Exception as exception_handle:
            logging.error(exception_handle)


# 3. Check to see if a CloudTrail trail is configured, and turn it on if it is not.
def check_cloudtrail(account_number):
    """Function to check if CloudTrail is enabled"""
    logging.info("Checking to see if CloudTrail is on, and will activate if needed.")
    try:
        logging.info("DescribeTrails API Call")
        cloudtrail_status = cloudtrail.describe_trails(
            includeShadowTrails=True
        )
        if cloudtrail_status["trailList"][0]["Name"] == "":
            logging.info("CreateTrail API Call")
            cloudtrail_activate = cloudtrail.create_trail(
                Name='aws-cloudtrail-em-' + account_number,
                S3BucketName="aws-log-collection-" + account_number + "-" + region,
                S3KeyPrefix='cloudtrail',
                IsMultiRegionTrail=True,
                EnableLogFileValidation=True
                )
            cloudtrail_name = cloudtrail_activate["Name"]
            logging.info("StartLogging API Call")
            cloudtrail_on = cloudtrail.start_logging(
                Name=cloudtrail_name
                )
            logging.info("Trail " + cloudtrail_name + " is created and active.")    
            return
        else:
            logging.info("There is a CloudTrail trail active. No action needed.")
            return
    except Exception as exception_handle:
        logging.error(exception_handle)


# 4. Turn on EKS audit and authenticator logs.
def eks_logging(region_list):
    """Function to turn on logging for EKS Clusters"""
    for aws_region in region_list:
        logging.info("Turning on audit and authenticator logging for EKS clusters in region " + aws_region + ".")
        eks = boto3.client('eks', region_name=aws_region)
        try:
            logging.info("ListClusters API Call")
            eks_clusters = eks.list_clusters()
            eks_cluster_list = eks_clusters ['clusters']
            logging.info("EKS Clusters found in " + aws_region + ":")
            print(eks_cluster_list)
            for cluster in eks_cluster_list:
                logging.info("UpdateClusterConfig API Call")
                eks_activate = eks.update_cluster_config(
                    name=cluster,
                    logging={
                        'clusterLogging': [
                            {
                                'types': [
                                    'audit',
                                ],
                                'enabled': True
                            },
                            {
                                'types': [
                                    'authenticator',
                                ],
                                'enabled': True
                            },
                        ]
                    }
                )
                if eks_activate['update']['status'] == 'InProgress':
                    logging.info(cluster + " EKS Cluster is currently updating. Status: InProgress")
                elif eks_activate['update']['status'] == 'Failed':
                    logging.info(cluster + " EKS Cluster failed to turn on logs. Please check if you have permissions to update the logging configuration of EKS. Status: Failed")
                elif eks_activate['update']['status'] == 'Cancelled':
                    logging.info(cluster + " EKS Cluster log update was cancelled. Status: Cancelled.")
                else:
                    logging.info(cluster + " EKS Cluster has audit and authenticator logs turned on.")
        except Exception as exception_handle:
            logging.error(exception_handle)


# 5. Turn on Route 53 Query Logging.
def route_53_query_logs(region_list, account_number):
    """Function to turn on Route 53 Query Logs for VPCs"""
    for aws_region in region_list:
        logging.info("Turning on Route 53 Query Logging on for VPCs in region " + aws_region + ".")
        ec2 = boto3.client('ec2', region_name=aws_region)
        route53resolver = boto3.client('route53resolver', region_name=aws_region)
        try:
            VPCList: list = []
            QueryLogList: list = []
            logging.info("DescribeVpcs API Call")
            vpcs = ec2.describe_vpcs()
            for vpc_id in vpcs["Vpcs"]:
                VPCList.append(vpc_id["VpcId"])
            logging.info("List of VPCs found within account " + account_number + ", region " + aws_region + ":")
            print(VPCList)
            logging.info("ListResolverQueryLogConfigAssociations API Call")
            query_log_details = route53resolver.list_resolver_query_log_config_associations()
            for query_log_vpc_id in query_log_details['ResolverQueryLogConfigAssociations']:
                QueryLogList.append(query_log_vpc_id['ResourceId'])
            r53_working_list = (list(set(VPCList) - set(QueryLogList)))
            logging.info("List of VPCs found within account " + account_number + ", region " + aws_region + " WITHOUT Route 53 Query Logs:")
            print(r53_working_list)
            for no_query_logs in r53_working_list:
                logging.info(no_query_logs + " does not have Route 53 Query logging on. It will be turned on within this function.")
            logging.info("Activating logs for VPCs that do not have Route 53 Query logging turned on.")
            logging.info("CreateResolverQueryLogConfig API Call")
            create_query_log = route53resolver.create_resolver_query_log_config(
                Name='Assisted_Log_Enabler_Query_Logs_' + aws_region,
                DestinationArn='arn:aws:s3:::aws-log-collection-' + account_number + '-' + region + '/r53querylogs',
                CreatorRequestId=timestamp_date_string,
                Tags=[
                    {
                        'Key': 'Workflow',
                        'Value': 'assisted-log-enabler'
                    },
                ]
            )
            r53_query_log_id = create_query_log['ResolverQueryLogConfig']['Id']
            logging.info("Route 53 Query Logging Created. Resource ID:" + r53_query_log_id)
            for vpc in r53_working_list:
                logging.info("Associating " + vpc + " with the created Route 53 Query Logging.")
                logging.info("AssocateResolverQueryLogConfig")
                activate_r5_logs = route53resolver.associate_resolver_query_log_config(
                    ResolverQueryLogConfigId=r53_query_log_id,
                    ResourceId=vpc
                )
        except Exception as exception_handle:
            logging.error(exception_handle)


def lambda_handler(event, context):
    """Function that runs all of the previously defined functions"""
    account_number = create_bucket()
    flow_log_activator(region_list, account_number)
    check_cloudtrail(account_number)
    eks_logging(region_list)
    route_53_query_logs(region_list, account_number)
    logging.info("This is the end of the script. Please feel free to validate that logs have been turned on.")


if __name__ == '__main__':
   event = "event"
   context = "context"
   lambda_handler(event, context)
