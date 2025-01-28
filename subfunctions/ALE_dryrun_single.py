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
region = os.environ['AWS_REGION']
account_number = sts.get_caller_identity()["Account"]


region_list = ['af-south-1', 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-south-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ap-southeast-4', 'ap-southeast-5', 'ca-central-1', 'ca-west-1', 'cn-north-1', 'cn-northwest-1', 'eu-central-1', 'eu-central-2', 'eu-north-1', 'eu-south-1', 'eu-south-2', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'il-central-1', 'me-central-1', 'me-south-1', 'sa-east-1', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']


# 1. Find VPCs and check if VPC Flow Logs are on.
def dryrun_flow_log_activator(region_list, account_number):
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
                logging.info(no_logs + " does not have VPC Flow logging on. This will not be turned on within the Dry Run option.")
        except Exception as exception_handle:
            logging.error(exception_handle)


# 2. Check to see if a CloudTrail trail is configured.
def dryrun_check_cloudtrail(account_number):
    """Function to check if CloudTrail is enabled"""
    logging.info("Checking to see if CloudTrail is on, and will activate if needed.")
    try:
        logging.info("DescribeTrails API Call")
        cloudtrail_status = cloudtrail.describe_trails(
            includeShadowTrails=True
        )
        if cloudtrail_status["trailList"][0]["Name"] == "":
            logging.info("There is no CloudTrail trail created within this account. Running Assisted Log Enabler for AWS will create the CloudTrail trail for this account.")
        else:
            cloudtrail_name = cloudtrail_status["trailList"][0]["Name"]
            logging.info("There is a CloudTrail trail active. Name: " + cloudtrail_name)
    except Exception as exception_handle:
        logging.error(exception_handle)

# 3. List EKS Clusters for visibility.
def dryrun_eks_logging(region_list):
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
                logging.info("Please check if Audit and Authenticator logs are on for EKS Cluster " + cluster)
        except Exception as exception_handle:
            logging.error(exception_handle)


# 4. Check if Route 53 Query Logging is turned on.
def dryrun_route_53_query_logs(region_list, account_number):
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
                logging.info(no_query_logs + " does not have Route 53 Query logging on. Running Assisted Log Enabler for AWS will turn this on.")
        except Exception as exception_handle:
            logging.error(exception_handle)

# 5. Check if S3 Logging is on.
def dryrun_s3_logs(region_list, account_number):
    """Function to turn on S3 Logs for Buckets"""
    for aws_region in region_list:
        logging.info("Turning on S3 Logging on for Buckets in region " + aws_region + ".")
        s3 = boto3.client('s3', region_name=aws_region)
        try:
            S3List: list = []
            S3LogList: list = []
            logging.info("ListBuckets API Call")
            buckets = s3.list_buckets()
            for bucket in buckets['Buckets']:
                s3region=s3.get_bucket_location(Bucket=bucket["Name"])['LocationConstraint']
                if s3region == aws_region:
                    S3List.append(bucket["Name"])
                elif s3region is None and aws_region == 'us-east-1':
                    S3List.append(bucket["Name"])
            if S3List != []:
                logging.info("List of Buckets found within account " + account_number + ", region " + aws_region + ":")
                print(S3List)
                logging.info("Parsed out buckets created by Assisted Log Enabler for AWS in " + aws_region)
                logging.info("Checking remaining buckets to see if logs were enabled by Assisted Log Enabler for AWS in " + aws_region)
                logging.info("GetBucketLogging API Call")
                for bucket in S3List:
                    if 'aws-s3-log-collection-' + account_number + '-' + aws_region not in str(bucket):
                        s3temp=s3.get_bucket_logging(Bucket=bucket)
                        if 'TargetBucket' not in str(s3temp):
                            S3LogList.append(bucket)
                if S3LogList != []:
                    logging.info("List of Buckets found within account " + account_number + ", region " + aws_region + " WITHOUT S3 Bucket Logs:")
                    print(S3LogList)
                    for bucket in S3LogList:
                        logging.info(bucket + " does not have S3 BUCKET logging on. It will be turned on within this function.")
                else:
                    logging.info("No S3 Bucket WITHOUT Logging enabled on account " + account_number + " region " + aws_region)
            else: 
                logging.info("No S3 Buckets found within account " + account_number + ", region " + aws_region + ":")
        except Exception as exception_handle:
            logging.error(exception_handle)

# 6. Check if Load Balancer Logging is on.
def dryrun_lb_logs(region_list, account_number):
    """Function to turn on LB Logs"""
    for aws_region in region_list:
        elbv1client = boto3.client('elb', region_name=aws_region)
        elbv2client = boto3.client('elbv2', region_name=aws_region)
        account_number = sts.get_caller_identity()["Account"]
        logging.info("Checking for Load Balancer Logging in the account " + account_number + ", region " + aws_region)
        try:
            ELBList1: list = []
            ELBList2: list = []
            ELBLogList: list = []
            ELBv1LogList: list = []
            ELBv2LogList: list = []
            logging.info("DescribeLoadBalancers API Call")
            ELBList1 = elbv1client.describe_load_balancers()
            for lb in ELBList1['LoadBalancerDescriptions']:
                logging.info("DescribeLoadBalancerAttibute API Call")
                lblog=elbv1client.describe_load_balancer_attributes(LoadBalancerName=lb['LoadBalancerName'])
                logging.info("Parsing out for ELB Access Logging")
                if lblog['LoadBalancerAttributes']['AccessLog']['Enabled'] == False:
                    ELBv1LogList.append([lb['LoadBalancerName'],'classic'])
            logging.info("DescribeLoadBalancers v2 API Call")
            ELBList2 = elbv2client.describe_load_balancers()
            for lb in ELBList2['LoadBalancers']:
                logging.info("DescribeLoadBalancerAttibute v2 API Call")
                lblog=elbv2client.describe_load_balancer_attributes(LoadBalancerArn=lb['LoadBalancerArn'])
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
            else: 
                logging.info("No Load Balancers WITHOUT logging found within account " + account_number + ", region " + aws_region + ":")
        except Exception as exception_handle:
            logging.error(exception_handle)

def dryrun_check_guardduty(region_list, account_number):
    """Function to check if GuardDuty is enabled"""
    logging.info("Creating KMS key for GuardDuty to export findings.")
    logging.info("Creating /guardduty folder in S3 Bucket")
    for aws_region in region_list:
        guardduty = boto3.client('guardduty', region_name=aws_region)
        logging.info("Checking for GuardDuty detector in the account " + account_number + ", region " + aws_region)
        try:
            logging.info("ListDetectors API Call")
            detectors = guardduty.list_detectors()
            if detectors["DetectorIds"] == []:
                logging.info("GuardDuty is not enabled in the account" + account_number + ", region " + aws_region)
                logging.info("Enabling GuardDuty")
                logging.info("Exporting GuardDuty findings to an S3 bucket.")
                logging.info("Setting S3 Bucket as publishing destination for GuardDuty detector.")
            else:
                detector_id = detectors["DetectorIds"][0]
                logging.info("GetDetector API Call")
                if guardduty.get_detector(DetectorId=detector_id)["Status"] == "DISABLED":
                    logging.info("GuardDuty is suspended in the account " + account_number + ", region " + aws_region)
                    logging.info("Enabling GuardDuty")
                    logging.info("UpdateDetector API Call")
                else:
                    logging.info("GuardDuty is already enabled in the account " + account_number + ", region " + aws_region)
                
                logging.info("Checking if GuardDuty detector publishes findings to S3.")
                logging.info("ListPublishingDestinations API Call")
                gd_destinations = guardduty.list_publishing_destinations(DetectorId=detector_id)["Destinations"]
                if gd_destinations == []:
                    logging.info("Detector does not publish findings to a destination. Setting S3 Bucket as publishing destination for GuardDuty detector.")
                else:
                    for dest in gd_destinations:
                        if dest["DestinationType"] == "S3":
                            dest_id = dest["DestinationId"]
                            logging.info("DescribePublishingDestination API Call")
                            dest_info = guardduty.describe_publishing_destination(
                                DetectorId=detector_id,
                                DestinationId=dest_id
                            )
                            dest_s3_arn = dest_info["DestinationProperties"]["DestinationArn"]
                            logging.info("Detector already publishes findings to S3 bucket " + dest_s3_arn.split(":")[-1])
        except Exception as exception_handle:
            logging.error(exception_handle)

def dryrun_wafv2_logs(region_list, account_number):
    """Function to check WAFv2 Logging"""
    for aws_region in region_list:
        wafv2 = boto3.client('wafv2', region_name=aws_region)
        logging.info("Checking for WAFv2 Logging in the account " + account_number + ", region " + aws_region)
        try:
            WAFv2List: list = [] # list of all WAFv2 ARNs
            WAFv2LogList: list = [] # list of WAFv2 ARNs with logging enabled
            WAFv2NoLogList: list = [] # list of WAFv2 ARNs to enable logging

            # Get regional WAFv2 Web ACLs
            logging.info("ListWebAcls API Call")
            wafv2_regional_acl_list = wafv2.list_web_acls(Scope='REGIONAL')["WebACLs"]
            for acl in wafv2_regional_acl_list:
                WAFv2List.append(acl["ARN"])
            
            if aws_region == 'us-east-1':
                # Get CloudFront (global) WAFv2 Web ACLs
                logging.info("Checking for Global (CloudFront) Web ACLs")
                logging.info("ListWebAcls API Call")
                wafv2_cf_acl_list = wafv2.list_web_acls(Scope='CLOUDFRONT')["WebACLs"]
                for acl in wafv2_cf_acl_list:
                    WAFv2List.append(acl["ARN"])
            
            logging.info("List of Web ACLs found within account " + account_number + ", region " + aws_region + ":")
            print(WAFv2List)

            logging.info("ListLoggingConfigurations API Call")
            wafv2_regional_log_configs = wafv2.list_logging_configurations(Scope='REGIONAL')["LoggingConfigurations"]
            for acl in wafv2_regional_log_configs:
                WAFv2LogList.append(acl["ResourceArn"])
            
            if aws_region == 'us-east-1':
                logging.info("Checking Global (CloudFront) Web ACL Logging Configurations")
                logging.info("ListLoggingConfigurations API Call")
                wafv2_cf_log_configs = wafv2.list_logging_configurations(Scope='CLOUDFRONT')["LoggingConfigurations"]
                for acl in wafv2_cf_log_configs:
                    WAFv2LogList.append(acl["ResourceArn"])
            
            WAFv2NoLogList = list(set(WAFv2List) - set(WAFv2LogList))
            logging.info("List of Web ACLs found within account " + account_number + ", region " + aws_region + " WITHOUT logging enabled:")
            print(WAFv2NoLogList)
            
            if WAFv2NoLogList != []:
                for arn in WAFv2NoLogList:
                    logging.info(arn + " does not have logging turned on. Assisted Log Enabler would enable logging.")
            else:
                logging.info("No WAFv2 Web ACLs to enable logging for in account " + account_number + ", region " + aws_region + ".")

        except Exception as exception_handle:
            logging.error(exception_handle)

def lambda_handler(event, context):
    """Function that runs all of the previously defined functions"""
    dryrun_flow_log_activator(region_list, account_number)
    dryrun_check_cloudtrail(account_number)
    dryrun_eks_logging(region_list)
    dryrun_route_53_query_logs(region_list, account_number)
    dryrun_s3_logs(region_list, account_number)
    dryrun_lb_logs(region_list, account_number)
    dryrun_check_guardduty(region_list, account_number)
    dryrun_wafv2_logs(region_list, account_number)
    logging.info("This is the end of the script. Please check the logs for the resources that would be turned on outside of the Dry Run option.")


if __name__ == '__main__':
   event = "event"
   context = "context"
   lambda_handler(event, context)
