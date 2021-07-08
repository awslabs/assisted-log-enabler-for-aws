# Changelog

## [1.0.0] - 2021-05-04

### Added
* Assisted Log Enabler for AWS
    * Main file
    * Subfuction files
    * Diagram files
    * LICENSE file
    * README file
    * NOTICE file
    * THIRD-PARTY file
    * CODE_OF_CONDUCT file
    * CONTRIBUTING file

## [1.0.1] - 2021-05-04

### Added
* PutPublicAccessBlock for Amazon S3 bucket created (single-account version).
* Step-by-step instructions for running Assisted Log Enabler for AWS in single-account mode using AWS CloudShell within the README file.

## [1.0.2] - 2021-05-04

### Added
* Error handling for AWS Organizations API call within multi-account version.

## [1.1.0] - 2021-05-11

### Added
* Route 53 Resolver Query Logging for single-account mode.

### Fixed
* Issue with Amazon S3 bucket creation.

### Changed
* IAM Permissions examples.
* Diagram to reflect Route 53 Resolver Query Logging.
* Diagram to correctly reflect Amazon EKS Audit & Authentication logs going to AWS CloudWatch.
* AWS CloudFormation template for deploying multi-account IAM roles.
* README documentation.

## [1.1.1] - 2021-05-14

### Added
* Multi-Account support for Route 53 Resolver Query Logging.
* Multi-Account support for Amazon EKS Audit & Authenticator Logs.
* Step-by-step instructions for running Assisted Log Enabler for AWS in multi-account mode using AWS CloudShell within the README file.

### Fixed
* Issue with log file output.

### Changed
* IAM Permissions examples.
* AWS CloudFormation template.

## [1.1.2] - 2021-05-17

### Added
* PutPublicAccessBlock for Amazon S3 bucket created (multi-account version).

### Changed
* Updates to IAM Permissions examples.
    * Added examples for both single account and multi-account.
* README documentation.

## [1.1.3] - 2021-05-18

### Fixed
* Documentation details about iam:CreateServiceLinkedRole.

## [1.1.4] - 2021-05-25

### Added
* Cleanup details in the README file.
* Cost details in the README file.

## [1.1.5] - 2021-06-04

### Added
* ap-northeast-3 Osaka to function code.

### Changed
* Log output file name to show clear date.
* Datetime output to show UTC time explicitly.
* README documentation.

## [1.2.0] - 2021-06-21

### Added
* Options for running the code for individual supported AWS services.
    * Maintained the ability to run for all services currently supported at once.
    * Documentation to reflect new supported commands.

### Changed
* README documentation.

## [1.2.1] - 2021-06-29

### Added
* CHANGELOG file

## [1.3.0] - 2021-07-08

### Added
* Code for cleaning up AWS resources created by Assisted Log Enabler for AWS.
    * Amazon Route 53 Resolver Query Logging in single account mode is only currently supported.
* Options for running cleanup mode within the main function.
* IAM Permissions example for cleanup operations.
* Information within the Step-by-Step instructions for multi-account to reflect details about AWS CloudFormation StackSets Delegated Administrator.

### Changed
* README documentation.
    * Updated Cleanup section to reflect new cleanup capabilities.
    * Updated IAM Permissions examples within the README.
* AWS CloudFormation template for deploying IAM Permissions to run cleanup code.
* Header in files to reflect "Assisted Log Enabler for AWS", instead of "Assisted Log Enabler (ALE)".