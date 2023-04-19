import boto3
import json
import os
import cfnresponse
from botocore.exceptions import ClientError

# Lambda Environment Variables
guardduty_master_account_id=os.environ['GUARDDUTY_MASTER_ACCOUNT_ID']
log_archive_account_id=os.environ['LOG_ARCHIVE_ACCOUNT_ID']
role_to_assume=os.environ['ROLE_TO_ASSUME']

def lambda_handler(event, context):

    # Get a list of all Available Regions supported by Amazon GuardDuty
    guardduty_regions=boto3.Session().get_available_regions('guardduty')

    # Get a list of all Regions that are governed by AWS Control Tower
    control_tower_regions=get_control_tower_regions()

    # Generate a STS Session with the AWS Account that will be used for the GuardDuty Master Account
    guardduty_master_account_session=assume_role(guardduty_master_account_id, role_to_assume)

    # Get a list of all 'ACTIVE' AWS Account within the AWS Organization
    accounts=get_all_accounts()

    if 'RequestType' in event:

        # AWS CloudFormation Create/Update Stack.
        if (event['RequestType'] == 'Create' or event['RequestType'] == 'Update'):
            try:

                # Create KMS Key with an appropriate Key Policy and Key Rotation Enabled. Create an S3 Bucket that then has Encryption Enabled by Default using the KMS Key and apply a Bucket Policy that enforces GuardDuty to ensure any objects are encryped when written to the bucket.
                publishing_destination=create_s3_destination(guardduty_master_account_session)

                # Loop through all AWS Control Tower Governed Regions
                skipregion=False
                for region in control_tower_regions:
                    if region in guardduty_regions:

                        # Configure Amazon GuardDuty in the Control Tower Management Account and Delegate Admin to an AWS Account as defined in the Lambda Environment Variables.
                        skipregion=enable_guardduty_master(region)
                        if skipregion:
                            continue
                        else:

                            # Configure Amazon GuardDuty with a Publishing Destination for GuardDuty Findings in the GuardDuty Admin Account that leverages the Amazon S3 Bucket that has been created in "create_s3_destination". Then loop through all 'ACTIVE' AWS Account in the AWS Organization and add them as a GuardDuty Member (and therefore behind the scenes creating a Detector).  Finally update the Organization Configuration and all GuardDuty Members so that S3 Protection is enabled.
                            enable_guardduty_member(guardduty_master_account_session, region, publishing_destination, accounts)
            except ClientError as e:
                print(e.response['Error']['Message'])
                cfnresponse.send(event, context, cfnresponse.FAILED, e.response)

        # AWS CloudFormation Delete Stack.
        elif (event['RequestType'] == 'Delete'):
            try:

                # Loop through all AWS Control Tower Governed Regions
                for region in control_tower_regions:
                    if region in guardduty_regions:

                        # Disable Amazon GuardDuty in all 'ACTIVE' AWS Accounts in the AWS Organization (and therefore behind the scenes deleting a Detector).
                        disable_guardduty_member(guardduty_master_account_session, region, accounts)

                # Disable the Delegated Admin for Amazon GuardDuty.
                disable_guardduty_master()

            except ClientError as e:
                print(e.response['Error']['Message'])
                cfnresponse.send(event, context, cfnresponse.FAILED, e.response)

        cfnresponse.send(event, context, cfnresponse.SUCCESS, {})

    else:
        print("Invoked by Amazon EventBridge Rule")
        # Create KMS Key with an appropriate Key Policy and Key Rotation Enabled. Create an S3 Bucket that then has Encryption Enabled by Default using the KMS Key and apply a Bucket Policy that enforces GuardDuty to ensure any objects are encryped when written to the bucket.
        publishing_destination=create_s3_destination(guardduty_master_account_session)

        # Loop through all AWS Control Tower Governed Regions
        skipregion=False
        for region in control_tower_regions:
            if region in guardduty_regions:

                # Configure Amazon GuardDuty in the Control Tower Management Account and Delegate Admin to an AWS Account as defined in the Lambda Environment Variables.
                skipregion=enable_guardduty_master(region)
                if skipregion:
                    continue
                else:

                    # Configure Amazon GuardDuty with a Publishing Destination for GuardDuty Findings in the GuardDuty Admin Account that leverages the Amazon S3 Bucket that has been created in "create_s3_destination". Then loop through all 'ACTIVE' AWS Account in the AWS Organization and add them as a GuardDuty Member (and therefore behind the scenes creating a Detector).  Finally update the Organization Configuration and all GuardDuty Members so that S3 Protection is enabled.
                    enable_guardduty_member(guardduty_master_account_session, region, publishing_destination, accounts)

def get_control_tower_regions():
    """
    Description:
        Finds the AWS Control Tower governed regions by Identifying the AWS Regions used within the AWS CloudFormation StackSets deployed by AWS Control Tower.
    Returns:
        List of AWS Control Tower governed regions.
    """

    cloudformation_client=boto3.client('cloudformation')
    control_tower_regions=set()
    try:
        stack_instances=cloudformation_client.list_stack_instances(
            StackSetName="AWSControlTowerBP-BASELINE-CLOUDWATCH"
        )
        for stack in stack_instances['Summaries']:
            control_tower_regions.add(stack['Region'])
    except Exception as e:
        print(f"Control Tower StackSet not found in this region")
        control_tower_regions = {'us-east-1', 'eu-west-2'}
    print(f"Control Tower Regions: {list(control_tower_regions)}")
    return list(control_tower_regions)

def assume_role(aws_account_id, role_to_assume):
    """
    Description:
        Assumes the provided role in the specified AWS Account and returns a GuardDuty Client.
    Parameters:
        "aws_account_id" = AWS Account Number.
        "role_to_assume" = Role to assume in target account.
    Returns:
        GuardDuty Client in the specified AWS Account and AWS Region.
    """

    # Beginning the AssumeRole process for the Account.
    sts_client=boto3.client('sts')
    response=sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{aws_account_id}:role/{role_to_assume}',
        RoleSessionName='EnableGuardDuty'
    )
    # Storing STS Credentials.
    sts_session=boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )
    print(f"Assumed session for Account ID: {aws_account_id}.")
    return sts_session

def get_all_accounts():
    """
    Description:
        Get all Accounts within the AWS Organization.
    Returns:
        A list of all AWS Accounts in the AWS Organization that have a Status of 'ACTIVE'.
    """

    org_client=boto3.client('organizations')
    all_accounts=[]
    active_accounts=[]
    token_tracker={}
    while True:
        member_accounts=org_client.list_accounts(
            **token_tracker
        )
        all_accounts.extend(member_accounts['Accounts'])
        if 'NextToken' in member_accounts:
            token_tracker['NextToken'] = member_accounts['NextToken']
        else:
            break
    for account in all_accounts:
        if account['Status'] == 'ACTIVE':
            active_accounts.append(account)
    return active_accounts

def create_s3_destination(sts_session):
    """
    Description:
        Create the S3 Bucket to be used for the Amazon GuardDuty Publishing Destination in the Control Tower Log Archive Account for the purpose of centralized logging. Amazon GuardDuty findings are encrypted using the AWS KMS Key in the GuardDuty Master Account.  Typically Best Practise would be to use the Control Tower Audit Account.
    Parameters:
        "sts_session" = AWS STS session of the GuardDuty Master Account.
    Returns:
        Properties for the Amazon GuardDuty Publishing Destination.
    """

    log_archive_account_session=assume_role(log_archive_account_id, role_to_assume)
    sts_client=log_archive_account_session.client('sts')
    s3_client=log_archive_account_session.client('s3')
    region_session=boto3.session.Session()
    aws_account_id=sts_client.get_caller_identity()
    bucket_region=region_session.region_name
    bucket_name=f"guardduty-{aws_account_id['Account']}-{bucket_region}"
    access_logging_bucket_name=f"aws-controltower-s3-access-logs-{aws_account_id['Account']}-{bucket_region}"
    allowed_regions=['af-south-1','ap-east-1','ap-northeast-1','ap-northeast-2','ap-northeast-3','ap-south-1','ap-southeast-1','ap-southeast-2','ca-central-1','cn-north-1','cn-northwest-1','eu-central-1','eu-north-1','eu-south-1','eu-west-1','eu-west-2','eu-west-3','me-south-1','sa-east-1','us-east-2','us-gov-east-1','us-gov-west-1','us-west-1','us-west-2']
    kms_key_arn=""
    try:
        if bucket_region in allowed_regions:
            kms_key_arn=create_kms_key(sts_session, bucket_region)
            print("Creating Amazon S3 Bucket to be used as the Amazon GuardDuty Publishing Destination.")
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={
                    'LocationConstraint': bucket_region
                }
            )
        elif bucket_region.startswith('eu'):
            kms_key_arn=create_kms_key(sts_session, bucket_region)
            print("Creating Amazon S3 Bucket to be used as the Amazon GuardDuty Publishing Destination.")
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={
                    'LocationConstraint': 'EU'
                }
            )
        else:
            # Bucket will be created in us-east-1
            kms_key_arn=create_kms_key(sts_session, 'us-east-1')
            print("Creating Amazon S3 Bucket to be used as the Amazon GuardDuty Publishing Destination.")
            s3_client.create_bucket(Bucket=bucket_name)
    except Exception as e:
        print(f"Amazon S3 Bucket {bucket_name} already exists.")
    bucket_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Sid': 'AWSBucketPermissionsCheck',
                'Effect': 'Allow',
                'Principal': {
                    'Service': 'guardduty.amazonaws.com'
                },
                'Action': [
                    's3:GetBucketAcl',
                    's3:ListBucket',
                    's3:GetBucketLocation'
                ],
                'Resource': f'arn:aws:s3:::{bucket_name}'
            },
            {
                'Sid': 'AWSBucketDelivery',
                'Effect': 'Allow',
                'Principal': {
                    'Service': 'guardduty.amazonaws.com'
                },
                'Action': 's3:PutObject',
                'Resource': f'arn:aws:s3:::{bucket_name}/*'
            },
            {
                'Sid': 'Deny unencrypted object uploads. This is optional',
                'Effect': 'Deny',
                'Principal': {
                    'Service': 'guardduty.amazonaws.com'
                },
                'Action': 's3:PutObject',
                'Resource': f'arn:aws:s3:::{bucket_name}/*',
                'Condition': {
                    'StringNotEquals': {
                        's3:x-amz-server-side-encryption': 'aws:kms'
                    }
                }
            },
            {
                'Sid': 'Deny incorrect encryption header. This is optional',
                'Effect': 'Deny',
                'Principal': {
                    'Service': 'guardduty.amazonaws.com'
                },
                'Action': 's3:PutObject',
                'Resource': f'arn:aws:s3:::{bucket_name}/*',
                'Condition': {
                    'StringNotEquals': {
                        's3:x-amz-server-side-encryption-aws-kms-key-id': kms_key_arn
                    }
                }
            },
            {
                'Sid': 'Deny non-HTTPS access',
                'Effect': 'Deny',
                'Principal': '*',
                'Action': 's3:*',
                'Resource': f'arn:aws:s3:::{bucket_name}/*',
                'Condition': {
                    'Bool': {
                        'aws:SecureTransport': 'false'
                    }
                }
            }
        ]
    }
    bucket_policy = json.dumps(bucket_policy)
    s3_client.put_bucket_policy(Bucket=bucket_name, Policy=bucket_policy)
    s3_client.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            'Rules': [
                {
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'aws:kms',
                        'KMSMasterKeyID': kms_key_arn
                    }
                },
            ]
        }
    )
    s3_client.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={
            'MFADelete': 'Disabled',
            'Status': 'Enabled'
        },
        ExpectedBucketOwner=aws_account_id['Account']
    )
    s3_client.put_bucket_logging(
        Bucket=bucket_name,
        BucketLoggingStatus={
            'LoggingEnabled': {
                'TargetBucket': access_logging_bucket_name,
                'TargetPrefix': 'guardduty-logs'
            }
        },
        ExpectedBucketOwner=aws_account_id['Account']
    )
    destination_properties = {
            'DestinationArn': f'arn:aws:s3:::{bucket_name}',
            'KmsKeyArn': kms_key_arn
    }
    return destination_properties

def create_kms_key(session, region):
    """
    Description:
        Create the AWS KMS Key required for the GuardDuty Publishing Destination in the specified region.
    Parameters:
        "session" = STS Session of the GuardDuty Master Account.
        "region" = AWS Region where GuardDuty Delegated Admin is to be enabled.
    Returns:
        ARN of the KMS Key that is created.
    """

    kms_client=session.client('kms', region_name=region)
    key_alias='alias/ControlTowerGuardduty'

    try:
        key_response=kms_client.describe_key(KeyId=key_alias)
        print(f"Found an existing AWS KMS Key with the Alias: {key_alias}.")
        return key_response['KeyMetadata']['Arn']
    except Exception as e:
        print(f"Creating a new AWS KMS Key with the Alias {key_alias}.")
        key_policy={
            'Version': '2012-10-17',
            'Id': 'auto-controltower-guardduty',
            'Statement': [
                {
                    'Sid': 'Enable IAM User Permissions',
                    'Effect': 'Allow',
                    'Principal': {
                        'AWS': f'arn:aws:iam::{guardduty_master_account_id}:root'
                    },
                    'Action': 'kms:*',
                    'Resource': '*'
                },
                {
                    'Sid': 'Allow access for Key Administrators',
                    'Effect': 'Allow',
                    'Principal': {
                        'AWS': f'arn:aws:iam::{guardduty_master_account_id}:role/AWSControlTowerExecution'
                    },
                    'Action': [
                        'kms:Create*',
                        'kms:Describe*',
                        'kms:Enable*',
                        'kms:List*',
                        'kms:Put*',
                        'kms:Update*',
                        'kms:Revoke*',
                        'kms:Disable*',
                        'kms:Get*',
                        'kms:Delete*',
                        'kms:TagResource',
                        'kms:UntagResource',
                        'kms:ScheduleKeyDeletion',
                        'kms:CancelKeyDeletion'
                    ],
                    'Resource': '*'
                },
                {
                    'Sid': 'Allow use of the key',
                    'Effect': 'Allow',
                    'Principal': {
                        'Service': 'guardduty.amazonaws.com'
                    },
                    'Action': [
                        'kms:Encrypt',
                        'kms:Decrypt',
                        'kms:ReEncrypt*',
                        'kms:GenerateDataKey*',
                        'kms:DescribeKey'
                    ],
                    'Resource': '*'
                },
                {
                    'Sid': 'Allow attachment of persistent resources',
                    'Effect': 'Allow',
                    'Principal': {
                        'Service': 'guardduty.amazonaws.com'
                    },
                    'Action': [
                        'kms:CreateGrant',
                        'kms:ListGrants',
                        'kms:RevokeGrant'
                    ],
                    'Resource': '*',
                    'Condition': {
                        'Bool': {
                            'kms:GrantIsForAWSResource': 'true'
                        }
                    }
                }
            ]
        }
        key_policy=json.dumps(key_policy)
        key_result=kms_client.create_key(
            Policy=key_policy,
            Description='The Encryption Key to Encrypt/Decrypt Amazon GuardDuty findings'
        )
        kms_client.create_alias(
            AliasName=key_alias,
            TargetKeyId=key_result['KeyMetadata']['KeyId']
        )
        kms_client.enable_key_rotation(
           KeyId=key_result['KeyMetadata']['KeyId']
        )
        return key_result['KeyMetadata']['Arn']

def enable_guardduty_master(region):
    """
    Description:
        Enable the Amaazon GuardDuty Delegated Admin Account from the AWS Control Tower Management Account.
    Parameters:
        "region" = AWS Region where GuardDuty Delegated Admin is to be enabled.
    """

    guardduty_client=boto3.client('guardduty', region_name=region)
    skipregion=False
    try:
        detectors=guardduty_client.list_detectors()
        delegated_admin=guardduty_client.list_organization_admin_accounts()
        if len(detectors['DetectorIds']) > 0:
            print(f"Amazon GuardDuty has already been enabled in the AWS Control Tower Management Account in region {region}.")
        else:
            guardduty_client.create_detector(
                Enable=True
            )
            print(f"Created Amazon GuardDuty Detector in the AWS Control Tower Management Account in region {region}.")
    except Exception as e:
        skipregion=True
        print(e)
    try:
        if skipregion:
            return skipregion
        elif delegated_admin['AdminAccounts'] and delegated_admin['AdminAccounts'][0]['AdminAccountId'] == guardduty_master_account_id:
            print(f"Account ID: {guardduty_master_account_id} is the Delegated Admin for Amazon GuardDuty.")
        else:
            print(f"Delegating Admin for Amazon GuardDuty to Account ID: {guardduty_master_account_id}.")
            new_delegated_admin=guardduty_client.enable_organization_admin_account(
                AdminAccountId=guardduty_master_account_id
            )
        return skipregion
    except Exception as e:
        print(e)

def enable_guardduty_member(guardduty_master_account_session, region, destination_properties, accounts):
    """
    Description:
        Configure Amazon GuardDuty with a Publishing Destination for GuardDuty Findings. Add all 'ACTIVE' AWS Accounts in the AWS Organization as a GuardDuty Member (and therefore behind the scenes creating a Detector). Finally update the GuardDuty Master Account, the Organization Configuration and all GuardDuty Members so that S3 Protection is enabled.
    Parameters:
        "guardduty_master_account_session" = AWS STS sesion of the GuardDuty Master Account
        "region" = AWS Region where GuardDuty Delegated Admin is to be enabled.
        "destination_properties" = Properties for the Amazon GuardDuty Publishing Destination.
        "accounts" = List of all Active AWS Accounts within the AWS Organization.
    """

    delegated_admin_client=guardduty_master_account_session.client('guardduty', region_name=region)
    try:
        detector_ids=delegated_admin_client.list_detectors()
    except Exception as ex:
        print(f"Unable to list Amazon GuardDuty Detectors in region {region}. Error: {ex}")
        return
    detector_id=detector_ids['DetectorIds'][0]
    publishing_destinations=delegated_admin_client.list_publishing_destinations(
        DetectorId=detector_id
    )
    try:
      if not publishing_destinations['Destinations']:
          delegated_admin_client.create_publishing_destination(
              DetectorId=detector_id,
              DestinationType='S3',
              DestinationProperties=destination_properties,
              ClientToken=detector_id
          )
          print(f"Created the Amazon GuardDuty Publishing Destination for region {region}.")
      else:
          delegated_admin_client.update_publishing_destination(
              DetectorId=detector_id,
              DestinationId=publishing_destinations['Destinations'][0]['DestinationId'],
              DestinationProperties=destination_properties
          )
          print(f"Updated the Amazon GuardDuty Publishing Destination for region {region}.")
    except Exception as e:
        print(f"Error Creating or Updating the Amazon GuardDuty Publishing Destination: {e}")
    delegated_admin_client.update_detector(
        DetectorId=detector_id,
        DataSources={
            'S3Logs': {
                'Enable': True
            },
            'Kubernetes': {
                'AuditLogs': {
                    'Enable': True
                }
            }
        }
    )
    delegated_admin_client.update_organization_configuration(
        DetectorId=detector_id,
        AutoEnable=True,
        DataSources={
            'S3Logs': {
                'AutoEnable': True
            },
            'Kubernetes': {
                'AuditLogs': {
                    'AutoEnable': True
                }
            }
        }
    )
    print(f"Updated the Organization Configuration to AutoEnable Amazon S3 Protection & AWS EKS Audit Log Protection for Amazon GuardDuty in region {region}.")
    details=[]
    failed_accounts=[]
    s3_failed_accounts=[]
    all_account_ids=[]
    for account in accounts:
        if (account['Id'] != guardduty_master_account_id):
            details.append(
                {
                'AccountId': account['Id'],
                'Email': account['Email']
                }
            )
            all_account_ids.append(account['Id'])
    details_batch=chunks(details, 50)
    ids_batch=chunks(all_account_ids, 50)
    try:
        for b in details_batch:
            unprocessed_accounts=delegated_admin_client.create_members(
                DetectorId=detector_id,
                AccountDetails=details
            )['UnprocessedAccounts']
            if (len(unprocessed_accounts) > 0):
                failed_accounts.append(unprocessed_accounts)
        try:
            for i in ids_batch:
                s3_unprocessed_accounts=delegated_admin_client.update_member_detectors(
                    DetectorId=detector_id,
                    AccountIds=i,
                    DataSources={
                        'S3Logs': {
                            'Enable': True
                        }
                    }
                )['UnprocessedAccounts']
                print(f"Enabled Amazon S3 Protection in Amazon GuardDuty for Account ID(s): {i} in {region}.")
                if (len(s3_unprocessed_accounts) >0 ):
                    s3_failed_accounts.extend(s3_unprocessed_accounts)
        except ClientError as s3_exception:
            print(f"Error configuring Amazon S3 Protection in Amazon GuardDuty for Account ID: {account}, Region: {region}. Error: {s3_exception}")
    except ClientError as e:
        print(f"Error Processing Account ID {account}. Error: {e}")

def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i+n]

def disable_guardduty_master():
    """
    Description:
        Disable the Amazon GuardDuty Delegated Admin Account from the Control Tower Management Account.
    Parameters:
        "region" = AWS Region where the Delegated Admin for Amazon GuardDuty is to be disabled.
    """

    guardduty_client=boto3.client('guardduty')
    try:
        guardduty_client.disable_organization_admin_account(
            AdminAccountId=guardduty_master_account_id
        )
        print(f"Disabled Delegated Admin for Amazon GuardDuty in Account ID: {guardduty_master_account_id}.")
    except Exception as e:
        print(e)

def disable_guardduty_member(guardduty_master_account_session, region, accounts):
    """
    Description:
        Disable Amazon GuardDuty in all 'ACTIVE' AWS Accounts in the AWS Organization (and therefore behind the scenes deleting a Detector).
    Parameters:
        "region" = AWS Region where Amazon GuardDuty is to be disabled.
        "accounts" = List of all Active AWS Accounts within the AWS Organization.
    """
    delegated_admin_client=guardduty_master_account_session.client('guardduty', region_name=region)
    try:
        detector_ids=delegated_admin_client.list_detectors()
    except Exception as ex:
        print(f"Unable to list Amazon GuardDuty Detectors in region {region}. Error: {ex}")
        return
    detector_id=detector_ids['DetectorIds'][0]
    all_account_ids=[]
    for account in accounts:
        member_account_session=assume_role(account['Id'], role_to_assume)
        member_client=member_account_session.client('guardduty', region_name=region)
        try:
            detector_ids=member_client.list_detectors()
        except Exception as ex:
            print(f"Unable to list Amazon GuardDuty Detectors in region {region}.")
            return
        detector_id=detector_ids['DetectorIds'][0]
        member_client.delete_detector(
            DetectorId=detector_id
        )
        print(f"Disabled Amazon GuardDuty in Account ID: {account['Id']} in region {region}.")
        all_account_ids.append(account['Id'])