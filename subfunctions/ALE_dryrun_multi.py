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
import argparse
import csv
import string
import random
from botocore.exceptions import ClientError
from datetime import timezone


current_date = datetime.datetime.now(tz=timezone.utc)
current_date_string = str(current_date)
timestamp_date = datetime.datetime.now(tz=timezone.utc).strftime("%Y-%m-%d-%H%M%S")
timestamp_date_string = str(timestamp_date)


sts = boto3.client('sts')
cloudtrail = boto3.client('cloudtrail')
organizations = boto3.client('organizations')
region = os.environ['AWS_REGION']


region_list = ['af-south-1', 'ap-east-1', 'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'me-south-1', 'sa-east-1', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']


# 1. Obtain the AWS Accounts inside of AWS Organizations.
def org_account_grab():
    """Function to list accounts inside of AWS Organizations"""
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


# 2. Obtain the current AWS Account Number.
def get_account_number():
    """Function to grab AWS Account number that Assisted Log Enabler runs from."""
    sts = boto3.client('sts')
    account_number = sts.get_caller_identity()["Account"]
    return account_number


# 3. Find VPCs and check if VPC Flow Logs are on.
def dryrun_flow_log_activator(account_number, OrgAccountIdList, region_list):
    """Function to define the list of VPCs without logging turned on"""
    logging.info("Creating a list of VPCs without Flow Logs on.")
    for org_account in OrgAccountIdList:
        for aws_region in region_list:
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
            region_name=aws_region
            )
            logging.info("Creating a list of VPCs without Flow Logs on in region " + aws_region + ".")
            try:
                VPCList: list = []
                FlowLogList: list = []
                logging.info("DescribeVpcs API Call")
                vpcs = ec2_ma.describe_vpcs()
                for vpc_id in vpcs["Vpcs"]:
                    VPCList.append(vpc_id["VpcId"])
                logging.info("List of VPCs found within account " + org_account + ", region " + aws_region + ":")
                print(VPCList)
                logging.info("DescribeFlowLogs API Call")
                vpcflowloglist = ec2_ma.describe_flow_logs()
                for resource_id in vpcflowloglist["FlowLogs"]:
                    FlowLogList.append(resource_id["ResourceId"])
                working_list = (list(set(VPCList) - set(FlowLogList)))
                logging.info("List of VPCs found within account " + org_account + ", region " + aws_region + " WITHOUT VPC Flow Logs:")
                print(working_list)
                for no_logs in working_list:
                    logging.info(no_logs + " does not have VPC Flow logging on. This will not be turned on within the Dry Run option.")
            except Exception as exception_handle:
                logging.error(exception_handle)


# 4. List EKS Clusters for visibility.
def dryrun_eks_logging(region_list, OrgAccountIdList):
    """Function to turn on logging for EKS Clusters"""
    for org_account in OrgAccountIdList:
        for aws_region in region_list:
            logging.info("Showing Amazon EKS clusters in AWS account " + org_account + ", in region " + aws_region + ".")
            sts = boto3.client('sts')
            RoleArn = 'arn:aws:iam::%s:role/Assisted_Log_Enabler_IAM_Role' % org_account
            logging.info('Assuming Target Role %s for Assisted Log Enabler...' % RoleArn)
            assisted_log_enabler_sts = sts.assume_role(
                RoleArn=RoleArn,
                RoleSessionName='assisted-log-enabler-activation',
                DurationSeconds=3600,
            )
            eks_ma = boto3.client(
            'eks',
            aws_access_key_id=assisted_log_enabler_sts['Credentials']['AccessKeyId'],
            aws_secret_access_key=assisted_log_enabler_sts['Credentials']['SecretAccessKey'],
            aws_session_token=assisted_log_enabler_sts['Credentials']['SessionToken'],
            region_name=aws_region
            )
            try:
                logging.info("ListClusters API Call")
                eks_clusters = eks_ma.list_clusters()
                eks_cluster_list = eks_clusters ['clusters']
                logging.info("EKS Clusters found in " + aws_region + ":")
                print(eks_cluster_list)
                for cluster in eks_cluster_list:
                    logging.info("Please check if Audit and Authenticator logs are on for EKS Cluster " + cluster)
            except Exception as exception_handle:
                logging.error(exception_handle)


# 6. Turn on Route 53 Query Logging.
def dryrun_route_53_query_logs(region_list, account_number, OrgAccountIdList):
    """Function to turn on Route 53 Query Logs for VPCs"""
    for org_account in OrgAccountIdList:
        for aws_region in region_list:
            logging.info("Checking Route 53 Query Logging on in AWS Account " + org_account + " VPCs, in region " + aws_region + ".")
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
            region_name=aws_region
            )
            route53resolver_ma = boto3.client(
            'route53resolver',
            aws_access_key_id=assisted_log_enabler_sts['Credentials']['AccessKeyId'],
            aws_secret_access_key=assisted_log_enabler_sts['Credentials']['SecretAccessKey'],
            aws_session_token=assisted_log_enabler_sts['Credentials']['SessionToken'],
            region_name=aws_region
            )
            try:
                VPCList: list = []
                QueryLogList: list = []
                logging.info("DescribeVpcs API Call")
                vpcs = ec2_ma.describe_vpcs()
                for vpc_id in vpcs["Vpcs"]:
                    VPCList.append(vpc_id["VpcId"])
                logging.info("List of VPCs found within account " + org_account + ", region " + aws_region + ":")
                print(VPCList)
                logging.info("ListResolverQueryLogConfigAssociations API Call")
                query_log_details = route53resolver_ma.list_resolver_query_log_config_associations()
                for query_log_vpc_id in query_log_details['ResolverQueryLogConfigAssociations']:
                    QueryLogList.append(query_log_vpc_id['ResourceId'])
                r53_working_list = (list(set(VPCList) - set(QueryLogList)))
                logging.info("List of VPCs found within account " + org_account + ", region " + aws_region + " WITHOUT Route 53 Query Logs:")
                print(r53_working_list)
                for no_query_logs in r53_working_list:
                    logging.info(no_query_logs + " does not have Route 53 Query logging on. Running Assisted Log Enabler for AWS will turn this on.")
            except Exception as exception_handle:
                logging.error(exception_handle)


def lambda_handler(event, context):
    """Function that runs all of the previously defined functions"""
    account_number = get_account_number()
    OrgAccountIdList, organization_id = org_account_grab()
    dryrun_flow_log_activator(account_number, OrgAccountIdList, region_list)
    dryrun_eks_logging(region_list, OrgAccountIdList)
    dryrun_route_53_query_logs(region_list, account_number, OrgAccountIdList)
    logging.info("This is the end of the script. Please check the logs for the resources that would be turned on outside of the Dry Run option.")


if __name__ == '__main__':
   event = "event"
   context = "context"
   lambda_handler(event, context)