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


logFormatter = '%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(format=logFormatter, level=logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
output_handle = logging.FileHandler('ALE_' + timestamp_date_string + '.log')
output_handle.setLevel(logging.INFO)
logger.addHandler(output_handle)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
output_handle.setFormatter(formatter)


region = os.environ['AWS_REGION']


region_list = ['af-south-1', 'ap-east-1', 'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'me-south-1', 'sa-east-1', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']


# 1. Remove the Route 53 Resolver Query Logging Resources created by Assisted Log Enabler
def r53_cleanup():
    """Function to clean up Route 53 Query Logging Resources"""
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
