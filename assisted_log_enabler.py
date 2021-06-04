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
from botocore.exceptions import ClientError
from datetime import timezone


from subfunctions import ALE_multi_account
from subfunctions import ALE_single_account


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
    parser.add_argument('--single_account',help=' Run Assisted Log Enabler against a single AWS account.', action='store_true', required=False)
    parser.add_argument('--multi_account',help=' Run Assisted Log Enabler against a multi account AWS environment. WARNING: You must have the associated CloudFormation template deployed as a StackSet before running this option.', action='store_true', required=False)
    args = parser.parse_args()
    banner()

    event = 'event'
    context = 'context'
    if args.single_account:
        ALE_single_account.lambda_handler(event, context)
    elif args.multi_account:
        ALE_multi_account.lambda_handler(event, context)
    else:
        print("No valid option selected. Please run with -h to display valid options.")


if __name__ == '__main__':
    assisted_log_enabler()
