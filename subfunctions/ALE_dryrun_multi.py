#// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#// SPDX-License-Identifier: Apache-2.0
# Assisted Log Enabler for AWS - Find resources that are not logging, and turn them on.
# Joshua "DozerCat" McKiddy - Customer Incident Response Team (CIRT) - AWS


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

# 7. Turn on S3 Logging.
def dryrun_s3_logs(region_list, account_number, OrgAccountIdList):
    """Function to turn on Bucket Logs for Buckets"""
    for org_account in OrgAccountIdList:
        for aws_region in region_list:
            logging.info("Turning on Bucket Logging on in AWS Account " + org_account + " Buckets, in region " + aws_region + ".")
            sts = boto3.client('sts')
            RoleArn = 'arn:aws:iam::%s:role/Assisted_Log_Enabler_IAM_Role' % org_account
            logging.info('Assuming Target Role %s for Assisted Log Enabler...' % RoleArn)
            assisted_log_enabler_sts = sts.assume_role(
                RoleArn=RoleArn,
                RoleSessionName='assisted-log-enabler-activation',
                DurationSeconds=3600,
            )
            s3_ma = boto3.client(
            's3',
            aws_access_key_id=assisted_log_enabler_sts['Credentials']['AccessKeyId'],
            aws_secret_access_key=assisted_log_enabler_sts['Credentials']['SecretAccessKey'],
            aws_session_token=assisted_log_enabler_sts['Credentials']['SessionToken'],
            region_name=aws_region
            )
            try:
                S3List: list = []
                S3LogList: list = []
                logging.info("ListBuckets API Call")
                buckets = s3_ma.list_buckets()
                for bucket in buckets['Buckets']:
                    s3region=s3_ma.get_bucket_location(Bucket=bucket["Name"])['LocationConstraint']
                    if s3region == aws_region:
                        S3List.append(bucket["Name"])
                    elif s3region is None and aws_region == 'us-east-1':
                        S3List.append(bucket["Name"])
                if S3List != []:
                    logging.info("List of Buckets found within account " + org_account + ", region " + aws_region + ":")
                    print(S3List)
                    logging.info("Parsed out buckets created by Assisted Log Enabler for AWS in " + aws_region)
                    logging.info("Checking remaining buckets to see if logs were enabled by Assisted Log Enabler for AWS in " + aws_region)
                    logging.info("GetBucketLogging API Call")
                    for bucket in S3List:
                        if 'aws-log-collection-' + org_account + '-' + aws_region not in str(bucket):
                            s3temp=s3_ma.get_bucket_logging(Bucket=bucket)
                            if 'TargetBucket' not in str(s3temp):
                                S3LogList.append(bucket)
                    if S3LogList != []:
                        logging.info("List of Buckets found within account " + org_account + ", region " + aws_region + " WITHOUT S3 Bucket Logs:")
                        print(S3LogList)
                        for bucket in S3LogList:
                            logging.info(bucket + " does not have S3 BUCKET logging on. It will be turned on within this function.")
                    else:
                        logging.info("No S3 Bucket WITHOUT Logging enabled on account " + org_account + " region " + aws_region)
                else: 
                    logging.info("No S3 Buckets found within account " + org_account + ", region " + aws_region + ":")
            except Exception as exception_handle:
                logging.error(exception_handle)


# 8. Turn on LB Logging.
def dryrun_lb_logs(region_list, account_number, OrgAccountIdList):
    """Function to turn on Load Balancer Logs"""
    for org_account in OrgAccountIdList:
        for aws_region in region_list:
            logging.info("Checking for Load Balancer Logging in the account "  + org_account + " in region " + aws_region + ".")
            sts = boto3.client('sts')
            RoleArn = 'arn:aws:iam::%s:role/Assisted_Log_Enabler_IAM_Role' % org_account
            logging.info('Assuming Target Role %s for Assisted Log Enabler...' % RoleArn)
            assisted_log_enabler_sts = sts.assume_role(
                RoleArn=RoleArn,
                RoleSessionName='assisted-log-enabler-activation',
                DurationSeconds=3600,
            )
            elbv1_ma = boto3.client(
            'elb',
            aws_access_key_id=assisted_log_enabler_sts['Credentials']['AccessKeyId'],
            aws_secret_access_key=assisted_log_enabler_sts['Credentials']['SecretAccessKey'],
            aws_session_token=assisted_log_enabler_sts['Credentials']['SessionToken'],
            region_name=aws_region
            )
            elbv2_ma = boto3.client(
            'elbv2',
            aws_access_key_id=assisted_log_enabler_sts['Credentials']['AccessKeyId'],
            aws_secret_access_key=assisted_log_enabler_sts['Credentials']['SecretAccessKey'],
            aws_session_token=assisted_log_enabler_sts['Credentials']['SessionToken'],
            region_name=aws_region
            )
            try:
                ELBList1: list = []
                ELBList2: list = []
                ELBLogList: list = []
                ELBv1LogList: list = []
                ELBv2LogList: list = []
                logging.info("DescribeLoadBalancers API Call")
                ELBList1 = elbv1_ma.describe_load_balancers()
                for lb in ELBList1['LoadBalancerDescriptions']:
                    logging.info("DescribeLoadBalancerAttibute API Call")
                    lblog=elbv1_ma.describe_load_balancer_attributes(LoadBalancerName=lb['LoadBalancerName'])
                    logging.info("Parsing out for ELB Access Logging")
                    if lblog['LoadBalancerAttributes']['AccessLog']['Enabled'] == False:
                        ELBv1LogList.append([lb['LoadBalancerName'],'classic'])
                logging.info("DescribeLoadBalancers v2 API Call")
                ELBList2 = elbv2_ma.describe_load_balancers()
                for lb in ELBList2['LoadBalancers']:
                    logging.info("DescribeLoadBalancerAttibute v2 API Call")
                    lblog=elbv2_ma.describe_load_balancer_attributes(LoadBalancerArn=lb['LoadBalancerArn'])
                    logging.info("Parsing out for ELBv2 Access Logging")
                    for lbtemp in lblog['Attributes']:
                        if lbtemp['Key'] == 'access_logs.s3.enabled':
                            if lbtemp['Value'] == 'false':
                                ELBv2LogList.append([lb['LoadBalancerName'],lb['LoadBalancerArn']])
                ELBLogList=ELBv1LogList+ELBv2LogList      
                if ELBLogList != []:
                    logging.info("List of Load Balancers found within account " + account_number + ", region " + aws_region + " without logging enabled:")
                    print(ELBLogList)
                    for elb in ELBLogList:
                        logging.info(elb[0] + " does not have Load Balancer logging on. It will be turned on within this function.")
                    logging.info("Creating S3 Logging Bucket for Load Balancers")
                else: 
                    logging.info("No Load Balancers WITHOUT logging found within account " + account_number + ", region " + aws_region + ":")
            except Exception as exception_handle:
                logging.error(exception_handle)

def dryrun_check_guardduty(region_list, OrgAccountIdList):
    """Function to check if GuardDuty is enabled"""
    logging.info("Creating KMS key for GuardDuty to export findings.")
    logging.info("Creating /guardduty folder in S3 Bucket")
    for org_account in OrgAccountIdList:
        for aws_region in region_list:
            logging.info("Checking for GuardDuty detectors in the account "  + org_account + " in region " + aws_region + ".")
            sts = boto3.client('sts')
            RoleArn = 'arn:aws:iam::%s:role/Assisted_Log_Enabler_IAM_Role' % org_account
            logging.info('Assuming Target Role %s for Assisted Log Enabler...' % RoleArn)
            assisted_log_enabler_sts = sts.assume_role(
                RoleArn=RoleArn,
                RoleSessionName='assisted-log-enabler-activation',
                DurationSeconds=3600,
            )
            guardduty_ma = boto3.client(
            'guardduty',
            aws_access_key_id=assisted_log_enabler_sts['Credentials']['AccessKeyId'],
            aws_secret_access_key=assisted_log_enabler_sts['Credentials']['SecretAccessKey'],
            aws_session_token=assisted_log_enabler_sts['Credentials']['SessionToken'],
            region_name=aws_region
            )
            try:
                logging.info("ListDetectors API Call")
                detectors = guardduty_ma.list_detectors()
                if detectors["DetectorIds"] == []:
                    logging.info("GuardDuty is not enabled in the account " + org_account + ", region " + aws_region)
                    logging.info("Enabling GuardDuty")
                    logging.info("Exporting GuardDuty findings to an S3 bucket.")
                    logging.info("Setting S3 Bucket as publishing destination for GuardDuty detector.")
                else:
                    detector_id = detectors["DetectorIds"][0]
                    logging.info("GetDetector API Call")
                    if guardduty_ma.get_detector(DetectorId=detector_id)["Status"] == "DISABLED":
                        logging.info("GuardDuty is suspended in the account " + org_account + ", region " + aws_region)
                        logging.info("Enabling GuardDuty")
                        logging.info("UpdateDetector API Call")
                    else:
                        logging.info("GuardDuty is already enabled in the account " + org_account + ", region " + aws_region)

                    logging.info("Checking if GuardDuty detector publishes findings to S3.")
                    logging.info("ListPublishingDestinations API Call")
                    gd_destinations = guardduty_ma.list_publishing_destinations(DetectorId=detector_id)["Destinations"]
                    if gd_destinations == []:
                        logging.info("Detector does not publish findings to a destination. Setting S3 Bucket as publishing destination for GuardDuty detector.")
                    else:
                        for dest in gd_destinations:
                            if dest["DestinationType"] == "S3":
                                dest_id = dest["DestinationId"]
                                logging.info("DescribePublishingDestination API Call")
                                dest_info = guardduty_ma.describe_publishing_destination(
                                    DetectorId=detector_id,
                                    DestinationId=dest_id
                                )
                                dest_s3_arn = dest_info["DestinationProperties"]["DestinationArn"]
                                logging.info("Detector already publishes findings to S3 bucket " + dest_s3_arn.split(":")[-1])
            except Exception as exception_handle:
                logging.error(exception_handle)

def dryrun_wafv2_logs(region_list, OrgAccountIdList):
    """Function to check WAFv2 Logging"""
    for org_account in OrgAccountIdList:
            for aws_region in region_list:
                logging.info("Checking for WAF Logging in the account "  + org_account + ", region " + aws_region + ".")
                sts = boto3.client('sts')
                RoleArn = 'arn:aws:iam::%s:role/Assisted_Log_Enabler_IAM_Role' % org_account
                logging.info('Assuming Target Role %s for Assisted Log Enabler...' % RoleArn)
                assisted_log_enabler_sts = sts.assume_role(
                    RoleArn=RoleArn,
                    RoleSessionName='assisted-log-enabler-activation',
                    DurationSeconds=3600,
                )
                wafv2_ma = boto3.client(
                'wafv2',
                aws_access_key_id=assisted_log_enabler_sts['Credentials']['AccessKeyId'],
                aws_secret_access_key=assisted_log_enabler_sts['Credentials']['SecretAccessKey'],
                aws_session_token=assisted_log_enabler_sts['Credentials']['SessionToken'],
                region_name=aws_region
                )

                try:
                    WAFv2List: list = [] # list of all WAFv2 ARNs
                    WAFv2LogList: list = [] # list of WAFv2 ARNs with logging enabled
                    WAFv2NoLogList: list = [] # list of WAFv2 ARNs to enable logging

                    # Get regional WAFv2 Web ACLs
                    logging.info("ListWebAcls API Call")
                    wafv2_regional_acl_list = wafv2_ma.list_web_acls(Scope='REGIONAL')["WebACLs"]
                    for acl in wafv2_regional_acl_list:
                        WAFv2List.append(acl["ARN"])
                    
                    if aws_region == 'us-east-1':
                        # Get CloudFront (global) WAFv2 Web ACLs
                        logging.info("Checking for Global (CloudFront) Web ACLs")
                        logging.info("ListWebAcls API Call")
                        wafv2_cf_acl_list = wafv2_ma.list_web_acls(Scope='CLOUDFRONT')["WebACLs"]
                        for acl in wafv2_cf_acl_list:
                            WAFv2List.append(acl["ARN"])
                    
                    logging.info("List of Web ACLs found within account " + org_account + ", region " + aws_region + ":")
                    print(WAFv2List)

                    # ListLoggingConfigurations returns only Web ACLs with logging already enabled
                    logging.info("ListLoggingConfigurations API Call")
                    wafv2_regional_log_configs = wafv2_ma.list_logging_configurations(Scope='REGIONAL')["LoggingConfigurations"]
                    for acl in wafv2_regional_log_configs:
                        WAFv2LogList.append(acl["ResourceArn"])

                    if aws_region == 'us-east-1':
                        logging.info("Checking Global (CloudFront) Web ACL Logging Configurations")
                        logging.info("ListLoggingConfigurations API Call")
                        wafv2_cf_log_configs = wafv2_ma.list_logging_configurations(Scope='CLOUDFRONT')["LoggingConfigurations"]
                        for acl in wafv2_cf_log_configs:
                            WAFv2LogList.append(acl["ResourceArn"])
                    
                    WAFv2NoLogList = list(set(WAFv2List) - set(WAFv2LogList))
                    logging.info("List of Web ACLs found within account " + org_account + ", region " + aws_region + " WITHOUT logging enabled:")
                    print(WAFv2NoLogList)

                    # If an S3 bucket has been created, use it as the log destination
                    if WAFv2NoLogList != []:
                        for arn in WAFv2NoLogList:
                            logging.info(arn + " does not have logging turned on. Assisted Log Enabler would enable logging.")
                    else:
                        logging.info("No WAFv2 Web ACLs to enable logging for in account " + org_account + ", region " + aws_region + ".")
                
                except Exception as exception_handle:
                    logging.error(exception_handle)


def lambda_handler(event, context):
    """Function that runs all of the previously defined functions"""
    account_number = get_account_number()
    OrgAccountIdList, organization_id = org_account_grab()
    dryrun_flow_log_activator(account_number, OrgAccountIdList, region_list)
    dryrun_eks_logging(region_list, OrgAccountIdList)
    dryrun_route_53_query_logs(region_list, account_number, OrgAccountIdList)
    dryrun_s3_logs(region_list, account_number, OrgAccountIdList)
    dryrun_lb_logs(region_list, account_number, OrgAccountIdList)
    dryrun_check_guardduty(region_list, OrgAccountIdList)
    dryrun_wafv2_logs(region_list, OrgAccountIdList)
    logging.info("This is the end of the script. Please check the logs for the resources that would be turned on outside of the Dry Run option.")


if __name__ == '__main__':
   event = "event"
   context = "context"
   lambda_handler(event, context)
