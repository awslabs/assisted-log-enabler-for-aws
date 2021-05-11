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
import argparse
import csv
from botocore.exceptions import ClientError


logger = logging.getLogger()
logger.setLevel(logging.INFO)
current_date = datetime.datetime.now()
current_date_string = str(current_date)


ec2 = boto3.client('ec2')
sts = boto3.client('sts')
s3 = boto3.client('s3')
cloudtrail = boto3.client('cloudtrail')
organizations = boto3.client('organizations')
region = os.environ['AWS_REGION']


def org_account_grab():
    """Function to list account inside of AWS Organizations"""
    try:
        OrgAccountIdList: list = []
        org_account_list = organizations.list_accounts()
        for accounts in org_account_list['Accounts']:
            OrgAccountIdList.append(accounts['Id'])
        get_organization_id = organizations.describe_organization()
        organization_id = get_organization_id['Organization']['Id']
    except Exception as exception_handle:
        logging.error(exception_handle)
        logging.error("Multi account mode is only for accounts using AWS Organizations.")
        logging.error("Please run the Assisted Log Enabler in single account mode to turn on AWS Logs.")
        exit()
    return OrgAccountIdList, organization_id


def get_account_number():
    """Function to grab AWS Account number that Assisted Log Enabler runs from."""
    sts = boto3.client('sts')
    account_number = sts.get_caller_identity()["Account"]
    return account_number


def create_bucket(organization_id, account_number):
    """Function to create the bucket for storing logs"""
    try:
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
        create_ct_path = s3.put_object(
            Bucket="aws-log-collection-" + account_number + "-" + region,
            Key='cloudtrail/AWSLogs/' + account_number + '/')
        create_ct_path_vpc = s3.put_object(
            Bucket="aws-log-collection-" + account_number + "-" + region,
            Key='vpcflowlogs/')
        create_ct_path_r53 = s3.put_object(
            Bucket="aws-log-collection-" + account_number + "-" + region,
            Key='r53querylogs/')
        bucket_policy = s3.put_bucket_policy(
            Bucket="aws-log-collection-" + account_number + "-" + region,
            Policy='{"Version": "2012-10-17", "Statement": [{"Sid": "AWSCloudTrailAclCheck20150319","Effect": "Allow","Principal": {"Service": "cloudtrail.amazonaws.com"},"Action": "s3:GetBucketAcl","Resource": "arn:aws:s3:::aws-log-collection-' + account_number + '-' + region + '"},{"Sid": "AWSCloudTrailWrite20150319","Effect": "Allow","Principal": {"Service": "cloudtrail.amazonaws.com"},"Action": "s3:PutObject","Resource": "arn:aws:s3:::aws-log-collection-' + account_number + '-' + region + '/cloudtrail/AWSLogs/' + account_number + '/*","Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}},{"Sid": "AWSLogDeliveryAclCheck","Effect": "Allow","Principal": {"Service": "delivery.logs.amazonaws.com"},"Action": "s3:GetBucketAcl","Resource": "arn:aws:s3:::aws-log-collection-' + account_number + '-' + region + '"},{"Sid": "AWSLogDeliveryWriteVPC","Effect": "Allow","Principal": {"Service": "delivery.logs.amazonaws.com"},"Action": "s3:PutObject","Resource": "arn:aws:s3:::aws-log-collection-' + account_number + '-' + region + '/vpcflowlogs/*","Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}},{"Sid": "AWSLogDeliveryWriteR53","Effect": "Allow","Principal": {"Service": "delivery.logs.amazonaws.com"},"Action": "s3:PutObject","Resource": "arn:aws:s3:::aws-log-collection-' + account_number + '-' + region + '/r53querylogs/*","Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}}]}'
        )
    except Exception as exception_handle:
        logging.error(exception_handle)
    return account_number


def vpc_list(account_number, OrgAccountIdList):
    """Function to define the list of VPCs without logging turned on"""
    logging.info("Creating a list of VPCs without Flow Logs on.")
    for org_account in OrgAccountIdList:
        sts = boto3.client('sts')
        RoleArn = 'arn:aws:iam::%s:role/Assisted_Log_Enabler_IAM_Role' % org_account
        logging.info('Assuming Target Role %s for Assisted Log Enabler...' % RoleArn)
        assisted_log_enabler_sts = sts.assume_role(
            RoleArn=RoleArn,
            RoleSessionName='assisted-log-enabler-activation',
            DurationSeconds=3600,
        )
        ec2_ma = boto3.client(
        'ec2',
        aws_access_key_id=assisted_log_enabler_sts['Credentials']['AccessKeyId'],
        aws_secret_access_key=assisted_log_enabler_sts['Credentials']['SecretAccessKey'],
        aws_session_token=assisted_log_enabler_sts['Credentials']['SessionToken'],
        region_name=region
        )
        vpcs = ec2_ma.describe_vpcs()
        vpcflowloglist = ec2_ma.describe_flow_logs()
        VPCList: list = []
        FlowLogList: list = []
        for vpc_id in vpcs["Vpcs"]:
            VPCList.append(vpc_id["VpcId"])
        for resource_id in vpcflowloglist["FlowLogs"]:
            logging.info("Making list of VPCs without logging, then making them into a working list")
            FlowLogList.append(resource_id["ResourceId"])
        flow_log_activator(VPCList, FlowLogList, account_number, OrgAccountIdList, ec2_ma)


def flow_log_activator(VPCList, FlowLogList, account_number, OrgAccountIdList, ec2_ma):
        """Function that turns on the VPC Flow Logs, for VPCs identifed without them"""
        working_list = (list(set(VPCList) - set(FlowLogList)))
        print("List of VPCs without Flow Logs:")
        print(working_list)
        for no_logs in working_list:
            logging.info(no_logs + " does not have VPC Flow logging on. It will be turned on within this function.")
            logging.info("Activating logs for VPCs that do not have them turned on.")
            logging.info("If all VPCs have Flow Logs turned on, you will get an MissingParameter error. That is normal.")
            time.sleep(2)
            flow_log_on = ec2_ma.create_flow_logs(
                ResourceIds=working_list,
                ResourceType='VPC',
                TrafficType='ALL',
                LogDestinationType='s3',
                LogDestination='arn:aws:s3:::aws-log-collection-' + account_number + '-' + region + '/vpcflowlogs',
                LogFormat='${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${type} ${tcp-flags} ${subnet-id} ${sublocation-type} ${sublocation-id} ${region} ${pkt-srcaddr} ${pkt-dstaddr} ${instance-id} ${az-id} ${pkt-src-aws-service} ${pkt-dst-aws-service} ${flow-direction} ${traffic-path}'
            )
            logging.info("VPC Flow Logs are turned on.")


def lambda_handler(event, context):
    """Function that runs all of the previously defined functions"""
    account_number = get_account_number()
    OrgAccountIdList, organization_id = org_account_grab()
    create_bucket(organization_id, account_number)
    vpc_list(account_number, OrgAccountIdList)
    logger.info("This is the end of the script. Please feel free to validate that logs have been turned on.")


if __name__ == '__main__':
    event = "event"
    context = "context"
    lambda_handler(event, context)
