import json
import boto3
import os
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Define valid BackupGroup tag values for instances and volumes
VALID_INSTANCE_BACKUP_GROUPS = {
    'eks-nobackup', 'ec2-nobackup', 'ec2-app-nonprod', 'ec2-app-prod-gold',
    'ec2-app-prod-silver', 'ec2-app-prod-bronze', 'ec2-web-nonprod',
    'ec2-web-prod-gold', 'ec2-web-prod-silver', 'ec2-web-prod-bronze'
}

VALID_VOLUME_BACKUP_GROUPS = {
    'ebs-nobackup', 'ebs-nonprod', 'ebs-prod-gold', 'ebs-prod-silver',
    'ebs-prod-bronze', 'ebs-sql-prod-bronze', 'ebs-sql-nonprod',
    'ebs-sql-prod-silver', 'ebs-sql-prod-gold', 'ebs-ora-prod-bronze',
    'ebs-ora-nonprod', 'ebs-ora-prod-silver', 'ebs-ora-prod-gold'
}

def get_tags(obj):
    """Helper function to convert a list of tags into a dictionary."""
    return {tag['Key']: tag['Value'] for tag in (obj.tags or [])}

def lambda_handler(event, context):
    ec2_regions = ["us-east-1", "us-east-2", "eu-west-2"]
    account = os.environ['ACCOUNT']

    for region in ec2_regions:
        ec2 = boto3.resource("ec2", region_name=region)
        instances = ec2.instances.all()
        volumes = ec2.volumes.all()

        instance_issue_list = []
        volume_issue_list = []

        # Process instances
        for instance in instances:
            tags = get_tags(instance)
            comment = ''
            if 'BackupGroup' not in tags:
                comment = 'Rubrik BackupGroup tag not present in the instance -'
            elif tags['BackupGroup'] not in VALID_INSTANCE_BACKUP_GROUPS:
                comment = 'Rubrik BackupGroup tag does not have a valid value in the instance -'

            if comment:
                instance_id = instance.id
                hostname = tags.get('Hostname', '')
                issue = ', '.join([instance_id, hostname, comment])
                instance_issue_list.append(issue)
                logger.info('Instance issue: ' + issue)

        # Process volumes
        for volume in volumes:
            tags = get_tags(volume)
            comment = ''
            if 'BackupGroup' not in tags:
                comment = 'Rubrik BackupGroup tag not present in the volume -'
            elif tags['BackupGroup'] not in VALID_VOLUME_BACKUP_GROUPS:
                comment = 'Rubrik BackupGroup tag does not have a valid value in the volume -'

            if comment:
                volume_id = volume.id
                hostname = tags.get('Hostname', '')
                issue = ', '.join([volume_id, hostname, comment])
                volume_issue_list.append(issue)
                logger.info('Volume issue: ' + issue)

        # Construct message
        msg_lines = [f"\n{account} {region}\n"]
        total_issues = len(instance_issue_list) + len(volume_issue_list)

        if total_issues == 0:
            msg_lines.append("All Instances and Volumes have valid Rubrik BackupGroup tags.")
        else:
            msg_lines.append(f"Total {total_issues} issues found\n")
            if instance_issue_list:
                msg_lines.append("Rubrik BackupGroup Tag is missing or incorrect for the following Instances:")
                msg_lines.extend(instance_issue_list)
            if volume_issue_list:
                msg_lines.append("\nRubrik BackupGroup Tag is missing or incorrect for the following Volumes:")
                msg_lines.extend(volume_issue_list)
        msg = '\n'.join(msg_lines)
        logger.info('msg: ' + msg)
        _send_message(msg)

def _send_message(msg):
    """Sends the message to an SQS queue."""
    role_arn = os.environ['ROLE_ARN']
    sqs_url = os.environ['SQS_URL']
    sts_connection = boto3.client('sts')
    acct_b = sts_connection.assume_role(
        RoleArn=role_arn,
        RoleSessionName="cross_acct_lambda"
    )
    sqs = boto3.resource(
        'sqs',
        region_name='us-east-1',
        aws_access_key_id=acct_b['Credentials']['AccessKeyId'],
        aws_secret_access_key=acct_b['Credentials']['SecretAccessKey'],
        aws_session_token=acct_b['Credentials']['SessionToken']
    )
    queue = sqs.Queue(sqs_url)
    queue.send_message(MessageBody=msg)
