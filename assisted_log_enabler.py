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
         Joshua "DozerCat" McKiddy - Team DragonCat - AWS
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
    parser.add_argument('--mode',help=' Choose the mode that you want to run Assisted Log Enabler in. Available modes: single_account, multi_account. WARNING: For multi_account, You must have the associated CloudFormation template deployed as a StackSet. See the README file for more details.')
    
    function_parser_group = parser.add_argument_group('Service Options', 'Use these flags to choose which services you want to turn logging on for.')
    function_parser_group.add_argument('--all', action='store_true', help=' Turns on all of the log types within the Assisted Log Enabler for AWS.')
    function_parser_group.add_argument('--eks', action='store_true', help=' Turns on Amazon EKS audit & authenticator logs.')
    function_parser_group.add_argument('--vpcflow', action='store_true', help=' Turns on Amazon VPC Flow Logs.')
    function_parser_group.add_argument('--r53querylogs', action='store_true', help=' Turns on Amazon Route 53 Resolver Query Logs.')
    function_parser_group.add_argument('--cloudtrail', action='store_true', help=' Turns on AWS CloudTrail.')

    cleanup_parser_group = parser.add_argument_group('Cleanup Options', 'Use these flags to choose which resources you want to turn logging off for.')
    cleanup_parser_group.add_argument('--single_r53querylogs', action='store_true', help=' Turns on Amazon Route 53 Resolver Query Logs.')

    dryrun_parser_group = parser.add_argument_group('Dry Run Options', 'Use these flags to run Assisted Log Enabler for AWS in Dry Run mode.')
    dryrun_parser_group.add_argument('--single_account', action='store_true', help=' Runs Assisted Log Enabler for AWS in Dry Run mode for a single AWS account.')
    dryrun_parser_group.add_argument('--multi_account', action='store_true', help=' Runs Assisted Log Enabler for AWS in Dry Run mode for a multi-account AWS environment, using AWS Organizations.')

    args = parser.parse_args()
    banner()

    event = 'event'
    context = 'context'
    if args.mode == 'single_account':
        if args.eks:
            ALE_single_account.run_eks()
        elif args.vpcflow:
            ALE_single_account.run_vpc_flow_logs()
        elif args.r53querylogs:
            ALE_single_account.run_r53_query_logs()
        elif args.cloudtrail:
            ALE_single_account.run_cloudtrail()
        elif args.all:
            ALE_single_account.lambda_handler(event, context)
        else:
            logging.info("No valid option selected. Please run with -h to display valid options.")
    elif args.mode == 'multi_account':
        if args.eks:
            ALE_multi_account.run_eks()
        elif args.vpcflow:
            ALE_multi_account.run_vpc_flow_logs()
        elif args.r53querylogs:
            ALE_multi_account.run_r53_query_logs()
        elif args.all:
            ALE_multi_account.lambda_handler(event, context)
        else:
            logging.info("No valid option selected. Please run with -h to display valid options.")
    elif args.mode == 'cleanup':
        if args.single_r53querylogs:
            ALE_cleanup_single.run_r53_cleanup()
    elif args.mode == 'dryrun':
        if args.single_account:
            ALE_dryrun_single.lambda_handler(event, context)
        elif args.multi_account:
            ALE_dryrun_multi.lambda_handler(event, context)
    else:
        print("No valid option selected. Please run with -h to display valid options.")


if __name__ == '__main__':
    assisted_log_enabler()
