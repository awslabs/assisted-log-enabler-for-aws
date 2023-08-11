#// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#// SPDX-License-Identifier: Apache-2.0
# Assisted Log Enabler for AWS - Find resources that are not logging, and turn them on.
# Joshua "DozerCat" McKiddy - Customer Incident Response Team (CIRT) - AWS

import logging
import os
import json
import boto3
import time
import sys
import datetime
import argparse
from botocore.exceptions import ClientError
from datetime import timezone

from subfunctions import ALE_multi_account
from subfunctions import ALE_single_account
from subfunctions import ALE_cleanup_single
from subfunctions import ALE_dryrun_single
from subfunctions import ALE_dryrun_multi


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


def banner():
    """Function for Assisted Log Enabler banner"""
    print('''
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
         Joshua "DozerCat" McKiddy - Customer Incident Response Team (CIRT) - AWS
         Twitter: @jdubm31
         Type -h for help.
    ''')


def assisted_log_enabler():
    """Function to run Assisted Log Enabler"""
    output_handle = logging.FileHandler('ALE_' + timestamp_date_string + '.log')
    output_handle.setLevel(logging.INFO)
    logger.addHandler(output_handle)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    output_handle.setFormatter(formatter)

    parser = argparse.ArgumentParser(description='Assisted Log Enabler - Find resources that are not logging, and turn them on.')
    parser.add_argument('--mode',help=' Choose the mode that you want to run Assisted Log Enabler in. Available modes: single_account, multi_account, cleanup, dryrun. WARNING: For multi_account, You must have the associated CloudFormation template deployed as a StackSet. See the README file for more details.')
    parser.add_argument('--bucket',help=' Specify the name of a pre-existing S3 bucket that you want Assisted Log Enabler to store logs in. Otherwise, a new S3 bucket will be created (default). Only used for Amazon VPC Flow Logs, Amazon Route 53 Resolver Query Logs, and AWS CloudTrail logs. WARNING: For multi_account, this will replace the bucket policy. For single_account, this may add statements to the bucket policy.')
    parser.add_argument('--include_accounts',help=' Specify AWS accounts to include for multi_account mode.')
    parser.add_argument('--exclude_accounts',help=' Specify AWS accounts to exclude for multi_account mode.')

    function_parser_group = parser.add_argument_group('Single & Multi Account Options', 'Use these flags to choose which services you want to turn logging on for.')
    function_parser_group.add_argument('--all', action='store_true', help=' Turns on all of the log types within the Assisted Log Enabler for AWS.')
    function_parser_group.add_argument('--eks', action='store_true', help=' Turns on Amazon EKS audit & authenticator logs.')
    function_parser_group.add_argument('--vpcflow', action='store_true', help=' Turns on Amazon VPC Flow Logs.')
    function_parser_group.add_argument('--r53querylogs', action='store_true', help=' Turns on Amazon Route 53 Resolver Query Logs.')
    function_parser_group.add_argument('--s3logs', action='store_true', help=' Turns on Amazon Bucket Logs.')
    function_parser_group.add_argument('--lblogs', action='store_true', help=' Turns on Amazon Load Balancer Logs.')
    function_parser_group.add_argument('--cloudtrail', action='store_true', help=' Turns on AWS CloudTrail. Only available in Single Account version.')

    cleanup_parser_group = parser.add_argument_group('Cleanup Options', 'Use these flags to choose which resources you want to turn logging off for.')
    cleanup_parser_group.add_argument('--single_r53querylogs', action='store_true', help=' Removes Amazon Route 53 Resolver Query Log resources created by Assisted Log Enabler for AWS.')
    cleanup_parser_group.add_argument('--single_cloudtrail', action='store_true', help=' Removes AWS CloudTrail trails created by Assisted Log Enabler for AWS.')
    cleanup_parser_group.add_argument('--single_vpcflow', action='store_true', help=' Removes Amazon VPC Flow Log resources created by Assisted Log Enabler for AWS.')
    cleanup_parser_group.add_argument('--single_all', action='store_true', help=' Turns off all of the log types within the Assisted Log Enabler for AWS.')
    cleanup_parser_group.add_argument('--single_s3logs', action='store_true', help=' Removes Amazon Bucket Log resources created by Assisted Log Enabler for AWS.')
    cleanup_parser_group.add_argument('--single_lblogs', action='store_true', help=' Removes Amazon Load Balancer Log resources created by Assisted Log Enabler for AWS.')

    dryrun_parser_group = parser.add_argument_group('Dry Run Options', 'Use these flags to run Assisted Log Enabler for AWS in Dry Run mode.')
    dryrun_parser_group.add_argument('--single_account', action='store_true', help=' Runs Assisted Log Enabler for AWS in Dry Run mode for a single AWS account.')
    dryrun_parser_group.add_argument('--multi_account', action='store_true', help=' Runs Assisted Log Enabler for AWS in Dry Run mode for a multi-account AWS environment, using AWS Organizations.')

    args = parser.parse_args()
    banner()

    event = 'event'
    context = 'context'
    bucket_name = 'default'
    included_accounts = 'all'
    excluded_accounts = 'none'
    if args.mode == 'single_account':
        if args.bucket:
            bucket_name = args.bucket
        if args.eks:
            ALE_single_account.run_eks()
        elif args.vpcflow:
            ALE_single_account.run_vpc_flow_logs(bucket_name)
        elif args.r53querylogs:
            ALE_single_account.run_r53_query_logs(bucket_name)
        elif args.s3logs:
            ALE_single_account.run_s3_logs()
        elif args.lblogs:
            ALE_single_account.run_lb_logs()
        elif args.cloudtrail:
            ALE_single_account.run_cloudtrail(bucket_name)
        elif args.all:
            ALE_single_account.lambda_handler(event, context, bucket_name)
        else:
            logging.info("No valid option selected. Please run with -h to display valid options.")
    elif args.mode == 'multi_account':
        if args.include_accounts:
            included_accounts_list = args.include_accounts.strip().split(",")
            if all(len(a) == 12 for a in included_accounts_list):
                logging.info("Account numbers to be included: ")
                print(*included_accounts_list, sep=",")
                included_accounts = included_accounts_list
            else:
                print("An invalid account number specified for --include_accounts. Account numbers are 12 digits long.")
        if args.exclude_accounts:
            excluded_accounts_list = args.exclude_accounts.strip().split(",")
            if all(len(a) == 12 for a in excluded_accounts_list):
                logging.info("Account numbers to be excluded: ")
                print(*excluded_accounts_list, sep=",")
                excluded_accounts = excluded_accounts_list
            else:
                sys.exit("An invalid account number was specified for --exclude_accounts. Account numbers are 12 digits long.")

        if args.bucket:
            bucket_name = args.bucket
        if args.eks:
            ALE_multi_account.run_eks(included_accounts, excluded_accounts)
        elif args.vpcflow:
            ALE_multi_account.run_vpc_flow_logs(bucket_name, included_accounts, excluded_accounts)
        elif args.r53querylogs:
            ALE_multi_account.run_r53_query_logs(bucket_name, included_accounts, excluded_accounts)
        elif args.s3logs:
            ALE_multi_account.run_s3_logs(included_accounts, excluded_accounts)
        elif args.lblogs:
            ALE_multi_account.run_lb_logs(included_accounts, excluded_accounts)
        elif args.all:
            ALE_multi_account.lambda_handler(event, context, bucket_name, included_accounts, excluded_accounts)
        else:
            logging.info("No valid option selected. Please run with -h to display valid options.")
    elif args.mode == 'cleanup':
        if args.single_r53querylogs:
            ALE_cleanup_single.run_r53_cleanup()
        elif args.single_s3logs:
            ALE_cleanup_single.run_s3_cleanup()
        elif args.single_lblogs:
            ALE_cleanup_single.run_lb_cleanup()
        elif args.single_cloudtrail:
            ALE_cleanup_single.run_cloudtrail_cleanup()
        elif args.single_vpcflow:
            ALE_cleanup_single.run_vpcflow_cleanup()
        elif args.single_all:
            ALE_cleanup_single.lambda_handler(event, context)
        else:
            logging.info("No valid option selected. Please run with -h to display valid options.")
    elif args.mode == 'dryrun':
        if args.single_account:
            ALE_dryrun_single.lambda_handler(event, context)
        elif args.multi_account:
            ALE_dryrun_multi.lambda_handler(event, context)
        else:
            logging.info("No valid option selected. Please run with -h to display valid options.")
    else:
        print("No valid option selected. Please run with -h to display valid options.")


if __name__ == '__main__':
    assisted_log_enabler()
