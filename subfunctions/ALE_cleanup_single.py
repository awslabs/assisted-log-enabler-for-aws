#// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#// SPDX-License-Identifier: Apache-2.0
# Assisted Log Enabler for AWS - Find resources that are not logging, and turn them on.
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
timestamp_date = datetime.datetime.now(tz=timezone.utc).strftime("%Y-%m-%d-%H%M%S")
timestamp_date_string = str(timestamp_date)


cloudtrail = boto3.client('cloudtrail') 
region = os.environ['AWS_REGION']


region_list = ['af-south-1', 'ap-east-1', 'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'me-south-1', 'sa-east-1', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']


# 1. Remove the Route 53 Resolver Query Logging Resources created by Assisted Log Enabler
def r53_cleanup():
    """Function to clean up Route 53 Query Logging Resources"""
    logging.info("Note: This script can take a while to finish, depending about how many Route 53 Query Log resources exist (about 60 seconds per Query Log resource) that were created by Assisted Log Enabler for AWS")
    time.sleep(1)
    for aws_region in region_list:
        logging.info("---- LINE BREAK BETWEEN REGIONS ----")
        logging.info("Cleaning up Route 53 Query Logging Resources in region " + aws_region + ".")
        route53resolver = boto3.client('route53resolver', region_name=aws_region)
        try:
            QueryLogList: list = []
            QueryLogArnRemoveList: list = []
            QueryLogIdRemoveList: list = []
            logging.info("ListResolverQueryLogConfigs API Call")
            ale_r53_logs = route53resolver.list_resolver_query_log_configs() # Collecting Arn of all Query Logs
            for r53_arn in ale_r53_logs['ResolverQueryLogConfigs']:
                QueryLogList.append(r53_arn['Arn'])
            for r53_tag_info in QueryLogList:
                logging.info("Listing Tags for " + r53_tag_info)
                logging.info("ListTagsForResource API Call")
                r53_tags = route53resolver.list_tags_for_resource( # Looking at tags for each Arn collected
                    ResourceArn=r53_tag_info
                )
                for value in r53_tags['Tags']:
                    if (value['Key'] == 'Workflow' and value['Value'] == 'assisted-log-enabler'):
                        logging.info("The following Route 53 Query Logger was created by Assisted Log Enabler for AWS, and will be removed within this function: " + r53_tag_info)
                        QueryLogArnRemoveList.append(r53_tag_info)
            for Id in QueryLogArnRemoveList:
                logging.info("Gathering Resource ID for Route 53 Query Logging Resource to be removed.")
                logging.info("ListResolverQueryLogConfigs API Call")
                r53_resource_id = route53resolver.list_resolver_query_log_configs()['ResolverQueryLogConfigs'][QueryLogArnRemoveList.index(Id)]['Id'] # Collecting Resource ID for each Arn collected
                QueryLogIdRemoveList.append(r53_resource_id)
                logging.info(r53_resource_id + " added to removal list.")
            logging.info("The following Resource IDs were created by Assisted Log Enabler for AWS, and will be removed within this function.")
            print(QueryLogIdRemoveList)
            for r53_remove in QueryLogIdRemoveList:
                logging.info("Gathering Query Log Config Associations for " + r53_remove)
                logging.info("ListResolverQueryLogConfigAssociations API Call")
                associated_vpcs = route53resolver.list_resolver_query_log_config_associations(
                )
                if associated_vpcs['TotalCount'] > 0 and associated_vpcs['ResolverQueryLogConfigAssociations'][0]['ResolverQueryLogConfigId'] == r53_remove:
                    logging.info("The following Route 53 Query Logger is associated with a VPC, and will be removed within this function: " + r53_remove)
                    VPCRemovalList = []
                    for vpc_info in associated_vpcs['ResolverQueryLogConfigAssociations']:
                        VPCRemovalList.append(vpc_info['ResourceId'])
                    logging.info("List of VPCs to be disassociated:")
                    print(VPCRemovalList)
                    for vpc in VPCRemovalList:
                        logging.info("Removing " + vpc + " from Route 53 Query Logging configuration " + r53_remove)
                        logging.info("DisassociateResolverQueryLogConfig API Call")
                        removing_vpc = route53resolver.disassociate_resolver_query_log_config(
                            ResolverQueryLogConfigId=r53_remove,
                            ResourceId=vpc
                        )
                        logging.info(vpc + " removed from " + r53_remove)
                        time.sleep(1)
                    logging.info("60 second pause to ensure disassociation of Amazon VPCs...")
                    time.sleep(60)
                    logging.info("Removing Route 53 Query Logger: " + r53_remove)
                    logging.info("DeleteResolverQueryLogConfig")
                    r53_cleanup = route53resolver.delete_resolver_query_log_config(
                        ResolverQueryLogConfigId=r53_remove
                    )
                    logging.info(r53_remove + " has been removed.")
                    time.sleep(2)
                else:
                    logging.info("Removing Route 53 Query Logger: " + r53_remove)
                    logging.info("DeleteResolverQueryLogConfig")
                    r53_cleanup = route53resolver.delete_resolver_query_log_config(
                        ResolverQueryLogConfigId=r53_remove
                    )
                    logging.info(r53_remove + " has been removed.")
                    time.sleep(2)
        except Exception as exception_handle:
            logging.error(exception_handle)


# 2. Remove the CloudTrail Logging Resources created by Assisted Log Enabler.
def cloudtrail_cleanup():
    """Function to clean up CloudTrail Logs"""
    logging.info("Cleaning up CloudTrail Logs.")
    try:
        logging.info("Cleaning up CloudTrail Logs created by Assisted Log Enabler for AWS.")
        trail_list: list = []
        removal_list: list = []
        logging.info("DescribeTrails API Call")
        cloudtrail_trails = cloudtrail.describe_trails()
        for trail in cloudtrail_trails['trailList']:
            trail_list.append(trail['TrailARN'])
        logging.info("Listing CloudTrail trails created by Assisted Log Enabler for AWS.")
        print("Full trail list")
        print(trail_list)
        for removal_trail in trail_list:
            logging.info("Checking tags for trails created by Assisted Log Enabler for AWS.")
            logging.info("ListTags API Call")
            trail_tags = cloudtrail.list_tags(
                ResourceIdList=[removal_trail]
            )
            for tag_lists in trail_tags['ResourceTagList']:
                for key_info in tag_lists['TagsList']:
                    print(key_info)
                    if key_info['Key'] == 'workflow' and key_info['Value'] == 'assisted-log-enabler':
                        removal_list.append(removal_trail)
        print("Trails to be removed")
        print(removal_list)
        for delete_trail in removal_list:
            logging.info("Deleting trails created by Assisted Log Enabler for AWS.")
            logging.info("DeleteTrail API Call")
            cloudtrail.delete_trail(
                Name=delete_trail
            )
            logging.info(delete_trail + " has been deleted.")
            time.sleep(1)
    except Exception as exception_handle:
        logging.error(exception_handle)


# 3. Remove the VPC Flow Log Resources created by Assisted Log Enabler for AWS.
def vpcflow_cleanup():
    """Function to clean up VPC Flow Logs"""
    logging.info("Cleaning up VPC Flow Logs created by Assisted Log Enabler for AWS.")
    for aws_region in region_list:
        try:
            logging.info("---- LINE BREAK BETWEEN REGIONS ----")
            logging.info("Cleaning up VPC Flow Logs created by Assisted Log Enabler for AWS in region " + aws_region + ".")
            removal_list: list = []
            ec2 = boto3.client('ec2', region_name=aws_region)
            logging.info("DescribeFlowLogs API Call")
            vpc_flow_logs = ec2.describe_flow_logs(
                Filter=[
                    {
                        'Name': 'tag:workflow',
                        'Values': [
                            'assisted-log-enabler'
                        ]
                    },
                ]
            )
            for flow_log_id in vpc_flow_logs['FlowLogs']:
                print(flow_log_id['FlowLogId'])
                removal_list.append(flow_log_id['FlowLogId'])
            print(removal_list)
            logging.info("DeleteFlowLogs API Call")
            delete_logs = ec2.delete_flow_logs(
                FlowLogIds=removal_list
            )
            logging.info("Deleted Flow Logs that were created by Assisted Log Enabler for AWS.")
            time.sleep(1)
        except Exception as exception_handle:
            logging.error(exception_handle)


def run_vpcflow_cleanup():
    """Function to run the vpcflow_cleanup function"""
    vpcflow_cleanup()
    logging.info("This is the end of the script. Please feel free to validate that logging resources have been cleaned up.")


def run_cloudtrail_cleanup():
    """Function to run the cloudtrail_cleanup function"""
    cloudtrail_cleanup()
    logging.info("This is the end of the script. Please feel free to validate that logging resources have been cleaned up.")


def run_r53_cleanup():
    """Function to run the r53_cleanup function"""
    r53_cleanup()
    logging.info("This is the end of the script. Please feel free to validate that logging resources have been cleaned up.")


def lambda_handler(event, context):
    """Function that runs all of the previously defined functions"""
    r53_cleanup()
    logging.info("This is the end of the script. Please feel free to validate that logging resources have been cleaned up.")


if __name__ == '__main__':
   event = "event"
   context = "context"
   lambda_handler(event, context)
