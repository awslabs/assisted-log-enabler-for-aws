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
from botocore.exceptions import ClientError
from datetime import timezone

current_date = datetime.datetime.now(tz=timezone.utc)
current_date_string = str(current_date)
timestamp_date = datetime.datetime.now(tz=timezone.utc).strftime("%Y-%m-%d-%H%M%S")
timestamp_date_string = str(timestamp_date)


cloudtrail = boto3.client('cloudtrail') 
region = os.environ['AWS_REGION']


region_list = ['af-south-1', 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-south-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ap-southeast-4', 'ap-southeast-5', 'ca-central-1', 'ca-west-1', 'cn-north-1', 'cn-northwest-1', 'eu-central-1', 'eu-central-2', 'eu-north-1', 'eu-south-1', 'eu-south-2', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'il-central-1', 'me-central-1', 'me-south-1', 'sa-east-1', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']


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

# 4. Remove the S3 Logging Resources created by Assisted Log Enabler
def s3_cleanup():
    """Function to clean up Bucket Logs"""
    logging.info("Cleaning up Bucket Logs created by Assisted Log Enabler for AWS.")
    for aws_region in region_list:
        s3 = boto3.client('s3', region_name=aws_region)
        try:
            logging.info("---- LINE BREAK BETWEEN REGIONS ----")
            logging.info("Cleaning up Bucket Logs created by Assisted Log Enabler for AWS in region " + aws_region + ".")
            removal_list: list = []
            logging.info("ListBuckets API Call")
            buckets = s3.list_buckets()
            for bucket in buckets['Buckets']:
                s3region=s3.get_bucket_location(Bucket=bucket["Name"])['LocationConstraint']
                if s3region == aws_region:
                    if 'aws-s3-log-collection-' not in str(bucket["Name"]):
                        logging.info("Parsed out buckets created by Assisted Log Enabler for AWS in " + aws_region)
                        logging.info("Checking remaining buckets to see if logs were enabled by Assisted Log Enabler for AWS in " + aws_region)
                        logging.info("GetBucketLogging API Call for " + bucket["Name"])
                        s3temp=s3.get_bucket_logging(Bucket=bucket["Name"])
                        if 'aws-s3-log-collection-' in str(s3temp):
                            removal_list.append(bucket["Name"])
                elif s3region is None and aws_region == 'us-east-1':
                    if 'aws-s3-log-collection-' not in str(bucket["Name"]):
                        logging.info("Parsed out buckets created by Assisted Log Enabler for AWS in " + aws_region)
                        logging.info("Checking remaining buckets to see if logs were enabled by Assisted Log Enabler for AWS in " + aws_region)
                        logging.info("GetBucketLogging API Call for " + bucket["Name"])
                        s3temp=s3.get_bucket_logging(Bucket=bucket["Name"])
                        if 'aws-s3-log-collection-' in str(s3temp):
                            removal_list.append(bucket["Name"])
            if removal_list != []:
                logging.info("List S3 Buckets with Logging enabled by by Assisted Log Enabler for AWS in " + aws_region)
                print(removal_list)
                for bucket in removal_list:
                    logging.info("Removing S3 Bucket Logging for " + bucket)
                    logging.info("PutBucketLogging API Call")
                    delete_s3_log = s3.put_bucket_logging(
                        Bucket=bucket,
                        BucketLoggingStatus={}
                    )
                logging.info("Removed S3 Bucket Logging created by Assisted Log Enabler for AWS.")
                time.sleep(1)
            else:
                logging.info("There are no S3 Bucket set by Log Enabler in " + aws_region)
        except Exception as exception_handle:
            logging.error(exception_handle)

# 5. Remove the Load Balancer Logging Resources created by Assisted Log Enabler
def lb_cleanup():
    """Function to clean up Load Balancer Logs"""
    logging.info("Cleaning up Load Balancer Logs created by Assisted Log Enabler for AWS.")
    for aws_region in region_list:
        elbv1client = boto3.client('elb', region_name=aws_region)
        elbv2client = boto3.client('elbv2', region_name=aws_region)
        ELBList1: list = []
        ELBList2: list = []
        ELBv1LogList: list = []
        ELBv2LogList: list = []
        removal_list: list = []
        try:
            logging.info("---- LINE BREAK BETWEEN REGIONS ----")
            logging.info("Cleaning up Bucket Logs created by Assisted Log Enabler for AWS in region " + aws_region + ".")
            logging.info("DescribeLoadBalancers API Call")
            ELBList1 = elbv1client.describe_load_balancers()
            for lb in ELBList1['LoadBalancerDescriptions']:
                logging.info("DescribeLoadBalancerAttibute API Call")
                lblog=elbv1client.describe_load_balancer_attributes(LoadBalancerName=lb['LoadBalancerName'])
                logging.info("Parsing out for ELB Access Logging")
                if lblog['LoadBalancerAttributes']['AccessLog']['Enabled'] == True:
                    if 'aws-lb-log-collection-' in str(lblog['LoadBalancerAttributes']['AccessLog']['S3BucketName']):
                        ELBv1LogList.append([lb['LoadBalancerName'],'classic'])
            logging.info("DescribeLoadBalancers v2 API Call")
            ELBList2 = elbv2client.describe_load_balancers()
            for lb in ELBList2['LoadBalancers']:
                logging.info("DescribeLoadBalancerAttibute v2 API Call")
                lblog=elbv2client.describe_load_balancer_attributes(LoadBalancerArn=lb['LoadBalancerArn'])
                logging.info("Parsing out for ELBv2 Access Logging")
                for lbtemp in lblog['Attributes']:
                    if lbtemp['Key'] == 'access_logs.s3.enabled':
                        if lbtemp['Value'] == 'true':
                            for lbtemp2 in lblog['Attributes']:
                                if lbtemp2['Key'] == 'access_logs.s3.bucket':
                                    if 'aws-lb-log-collection-' in str(lbtemp2['Value']):
                                        ELBv2LogList.append([lb['LoadBalancerName'],lb['LoadBalancerArn']])
            removal_list=ELBv1LogList+ELBv2LogList   
            if removal_list != []:
                logging.info("List Load Balancers with Logging enabled by by Assisted Log Enabler for AWS in " + aws_region)
                print(removal_list)
                for elb in removal_list:
                    logging.info(elb[0] + " has Load Balancer logging on. It will be turned on within this function.")
                if ELBv1LogList != []:
                    for elb in ELBv1LogList:
                        logging.info("Removing logs for Load Balancer " + elb[0])
                        logging.info("ModifyLoadBalancerAttributes API Call")
                        remove_lb_log = elbv1client.modify_load_balancer_attributes(
                            LoadBalancerName=elb[0],
                            LoadBalancerAttributes={
                                'AccessLog': {
                                    'Enabled': False }
                            }
                        )
                        logging.info("Logging Disabled for Load Balancer " + elb[0])
                if ELBv2LogList != []:
                    for elb in ELBv2LogList:
                        logging.info("Removing logs for Load Balancer " + elb[0])
                        logging.info("ModifyLoadBalancerAttributes v2 API Call")
                        remove_lb_log = elbv2client.modify_load_balancer_attributes(
                            LoadBalancerArn=elb[1],
                            Attributes=[
                                {
                                    'Key': 'access_logs.s3.enabled',
                                    'Value': 'false'
                                }
                            ]
                        )
                        logging.info("Logging Disabled for Load Balancer " + elb[0])
                logging.info("Removed Load Balancers Logging created by Assisted Log Enabler for AWS.")
                time.sleep(1)
            else:
                logging.info("There are no Load Balancers Logs set by Log Enabler in " + aws_region)
        except Exception as exception_handle:
            logging.error(exception_handle)


def guardduty_cleanup():
    """"Function to cleanup GuardDuty detectors"""
    logging.info("Cleaning up GuardDuty detectors created by Assisted Log Enabler for AWS.")
    for aws_region in region_list:
        detector_list = []
        removal_list = []
        guardduty = boto3.client('guardduty', region_name=aws_region)
        try:
            logging.info("---- LINE BREAK BETWEEN REGIONS ----")
            logging.info("Cleaning up GuardDuty detectors created by Assisted Log Enabler for AWS in region " + aws_region + ".")
            logging.info("ListDetectors API Call")
            detector_list = guardduty.list_detectors()["DetectorIds"]
            if detector_list != []:
                logging.info("GuardDuty detectors found: ")
                print(detector_list)
                logging.info("Checking tags for GuardDuty detectors created by Assisted Log Enabler.")
                for detector_id in detector_list:
                    logging.info("GetDetector API Call")
                    detector = guardduty.get_detector(DetectorId=detector_id)
                    for tag in detector["Tags"]:
                        if tag == "workflow":
                            if detector["Tags"]["workflow"] == "assisted-log-enabler":
                                removal_list.append(detector_id)
                if removal_list != []:
                    logging.info("GuardDuty detectors created by Assisted Log Enabler to be deleted: ")
                    print(removal_list)
                    for detector_id in removal_list:
                        logging.info("Removing GuardDuty detector " + detector_id)
                        logging.info("DeleteDetector API Call")
                        guardduty.delete_detector(DetectorId=detector_id)
                else:
                    logging.info("There are no GuardDuty detectors created by Assisted Log Enabler in region " +  aws_region + ".")
            else:
                logging.info("No GuardDuty detectors enabled in region " + aws_region + ".")

        except Exception as exception_handle:
            logging.error(exception_handle)

def waf_cleanup():
    """Function to cleanup WAFv2 Logging Configurations"""
    logging.info("Cleaning up WAFv2 logging previously enabled by Assisted Log Enabler.")

    for aws_region in region_list:
        wafv2 = boto3.client('wafv2', region_name=aws_region)
        try:
            logging.info("Checking Web ACL logging configurations in region " + aws_region + ".")
            logging.info("ListLoggingConfigurations API Call")
            log_configs_regional = wafv2.list_logging_configurations(Scope='REGIONAL')["LoggingConfigurations"]
            for acl in log_configs_regional:
                for destination in acl["LogDestinationConfigs"]:
                    if "aws-waf-logs-ale-" in destination:
                        logging.info("Deleting logging configuration for " + acl["ResourceArn"])
                        logging.info("DeleteLoggingConfiguration API Call")
                        wafv2.delete_logging_configuration(ResourceArn=acl["ResourceArn"])

            if aws_region == 'us-east-1':
                logging.info("Checking Global Web ACL logging configurations.")
                logging.info("ListLoggingConfigurations API Call")
                log_configs_cf = wafv2.list_logging_configurations(Scope='CLOUDFRONT')["LoggingConfigurations"]
                for acl in log_configs_cf:
                    for destination in acl["LogDestinationConfigs"]:
                        if "aws-waf-logs-ale-" in destination:
                            logging.info("Deleting logging configuration for " + acl["ResourceArn"])
                            logging.info("DeleteLoggingConfiguration API Call")
                            wafv2.delete_logging_configuration(ResourceArn=acl["ResourceArn"])
        
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

def run_s3_cleanup():
    """Function to run the s3_cleanup function"""
    s3_cleanup()
    logging.info("This is the end of the script. Please feel free to validate that logging resources have been cleaned up.")

def run_lb_cleanup():
    """Function to run the lb_cleanup function"""
    lb_cleanup()
    logging.info("This is the end of the script. Please feel free to validate that logging resources have been cleaned up.")

def run_guardduty_cleanup():
    """Function to run the guardduty_cleanup function"""
    guardduty_cleanup()
    logging.info("This is the end of the script. Please feel free to validate that logging resources have been cleaned up.")

def run_wafv2_cleanup():
    """Function to run the wafv2_cleanup function"""
    waf_cleanup()
    logging.info("This is the end of the script. Please feel free to validate that logging resources have been cleaned up.")

def lambda_handler(event, context):
    """Function that runs all of the previously defined functions"""
    r53_cleanup()
    vpcflow_cleanup()
    cloudtrail_cleanup()
    s3_cleanup()
    lb_cleanup()
    guardduty_cleanup()
    waf_cleanup()
    logging.info("This is the end of the script. Please feel free to validate that logging resources have been cleaned up.")


if __name__ == '__main__':
   event = "event"
   context = "context"
   lambda_handler(event, context)
