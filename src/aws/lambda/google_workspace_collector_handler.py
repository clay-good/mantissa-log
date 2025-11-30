"""
Google Workspace Reports API Collector Lambda Handler

Collects audit logs from Google Workspace Admin SDK Reports API and stores them in S3.
Supports:
- Admin activity logs
- Login activity logs
- Drive activity logs
- Token activity logs
- Groups activity logs
- Mobile activity logs
"""

import json
import os
import boto3
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
import logging
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Setup logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS Clients
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
secrets_client = boto3.client('secretsmanager')

# Environment variables
LOGS_BUCKET = os.environ.get('LOGS_BUCKET', "logs-bucket")
CHECKPOINT_TABLE = os.environ.get('CHECKPOINT_TABLE', "mantissa-checkpoint-table")
SERVICE_ACCOUNT_SECRET = os.environ.get('SERVICE_ACCOUNT_SECRET', "mantissa/service/account/secret")
DELEGATED_ADMIN_EMAIL = os.environ.get('DELEGATED_ADMIN_EMAIL', "")

# Google Workspace API configuration
API_SCOPES = ['https://www.googleapis.com/auth/admin.reports.audit.readonly']
APPLICATION_NAMES = ['admin', 'login', 'drive', 'token', 'groups', 'mobile']


class GoogleWorkspaceCollector:
    """Collector for Google Workspace audit logs"""

    def __init__(self):
        """Initialize the collector with service account credentials"""
        self.credentials = self._get_credentials()
        self.service = build('admin', 'reports_v1', credentials=self.credentials)
        self.checkpoint_table = dynamodb.Table(CHECKPOINT_TABLE)

    def _get_credentials(self):
        """Retrieve and configure service account credentials"""
        # Get service account JSON from Secrets Manager
        response = secrets_client.get_secret_value(SecretId=SERVICE_ACCOUNT_SECRET)
        service_account_info = json.loads(response['SecretString'])

        # Create credentials with delegated admin
        credentials = service_account.Credentials.from_service_account_info(
            service_account_info,
            scopes=API_SCOPES
        )

        # Delegate to admin user
        delegated_credentials = credentials.with_subject(DELEGATED_ADMIN_EMAIL)
        return delegated_credentials

    def get_checkpoint(self, application_name: str) -> Optional[str]:
        """
        Get last fetch timestamp for application from DynamoDB.

        Args:
            application_name: Google Workspace application name

        Returns:
            ISO 8601 timestamp or None
        """
        try:
            response = self.checkpoint_table.get_item(
                Key={'source': f'google_workspace_{application_name}'}
            )
            if 'Item' in response:
                return response['Item']['last_fetch_timestamp']
            return None
        except Exception as e:
            logger.warning(f"Failed to get checkpoint for {application_name}: {e}")
            return None

    def save_checkpoint(self, application_name: str, timestamp: str):
        """
        Save last fetch timestamp to DynamoDB.

        Args:
            application_name: Google Workspace application name
            timestamp: ISO 8601 timestamp
        """
        try:
            self.checkpoint_table.put_item(
                Item={
                    'source': f'google_workspace_{application_name}',
                    'last_fetch_timestamp': timestamp,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
            )
            logger.info(f"Checkpoint saved for {application_name}: {timestamp}")
        except Exception as e:
            logger.error(f"Failed to save checkpoint for {application_name}: {e}")

    def fetch_activities(
        self,
        application_name: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        max_results: int = 1000
    ) -> List[Dict]:
        """
        Fetch activities from Google Workspace Reports API with pagination.

        Args:
            application_name: Application to fetch logs for (admin, login, drive, etc.)
            start_time: RFC 3339 timestamp to start from
            end_time: RFC 3339 timestamp to end at
            max_results: Maximum results per page

        Returns:
            List of activity events
        """
        if not start_time:
            # Default to last 15 minutes
            start_time = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat() + 'Z'

        all_activities = []
        page_token = None

        try:
            while True:
                # Build request parameters
                params = {
                    'userKey': 'all',
                    'applicationName': application_name,
                    'startTime': start_time,
                    'maxResults': max_results
                }

                if end_time:
                    params['endTime'] = end_time
                if page_token:
                    params['pageToken'] = page_token

                # Execute API request
                request = self.service.activities().list(**params)
                response = request.execute()

                # Extract activities
                activities = response.get('items', [])
                all_activities.extend(activities)

                logger.info(
                    f"Fetched {len(activities)} {application_name} activities "
                    f"(total: {len(all_activities)})"
                )

                # Check for next page
                page_token = response.get('nextPageToken')
                if not page_token:
                    break

            return all_activities

        except HttpError as e:
            if e.resp.status == 403:
                logger.error(f"Permission denied for {application_name} API: {e}")
            elif e.resp.status == 429:
                logger.warning(f"Rate limit exceeded for {application_name}, implement backoff")
            else:
                logger.error(f"HTTP error fetching {application_name} activities: {e}")
            raise
        except Exception as e:
            logger.error(f"Error fetching {application_name} activities: {e}")
            raise

    def store_logs_in_s3(self, application_name: str, activities: List[Dict]):
        """
        Store activities in S3 with time-based partitioning.

        Args:
            application_name: Application name for S3 path
            activities: List of activity events to store
        """
        if not activities:
            logger.info(f"No {application_name} activities to store")
            return

        now = datetime.now(timezone.utc)

        # Create S3 key with partitioning
        s3_key = (
            f"google_workspace/raw/{application_name}/"
            f"{now.year:04d}/{now.month:02d}/{now.day:02d}/{now.hour:02d}/"
            f"{now.strftime('%Y%m%d_%H%M%S')}.json"
        )

        # Convert to newline-delimited JSON
        ndjson_content = '\n'.join(json.dumps(activity) for activity in activities)

        try:
            s3_client.put_object(
                Bucket=LOGS_BUCKET,
                Key=s3_key,
                Body=ndjson_content.encode('utf-8'),
                ContentType='application/x-ndjson'
            )
            logger.info(
                f"Stored {len(activities)} {application_name} activities to s3://{LOGS_BUCKET}/{s3_key}"
            )
        except Exception as e:
            logger.error(f"Failed to store {application_name} activities in S3: {e}")
            raise


def lambda_handler(event, context):
    """
    Lambda handler to collect Google Workspace audit logs.

    Environment Variables:
        LOGS_BUCKET: S3 bucket for log storage
        CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
        SERVICE_ACCOUNT_SECRET: Secrets Manager secret with service account JSON
        DELEGATED_ADMIN_EMAIL: Email of admin user to delegate to

    Event Parameters (optional):
        application_names: List of applications to collect (default: all)
        start_time: Override start time (RFC 3339)
        end_time: Override end time (RFC 3339)
    """
    try:
        collector = GoogleWorkspaceCollector()

        # Get application names to collect
        application_names = event.get('application_names', APPLICATION_NAMES)
        if isinstance(application_names, str):
            application_names = [application_names]

        total_collected = 0
        results = {}

        # Collect logs for each application
        for app_name in application_names:
            logger.info(f"Collecting {app_name} activities")

            try:
                # Get checkpoint or use event override
                start_time = event.get('start_time')
                if not start_time:
                    checkpoint = collector.get_checkpoint(app_name)
                    if checkpoint:
                        start_time = checkpoint
                    else:
                        # First run - get last 24 hours
                        start_time = (
                            datetime.now(timezone.utc) - timedelta(hours=24)
                        ).isoformat() + 'Z'

                end_time = event.get('end_time')

                # Fetch activities
                activities = collector.fetch_activities(
                    application_name=app_name,
                    start_time=start_time,
                    end_time=end_time
                )

                # Store in S3
                if activities:
                    collector.store_logs_in_s3(app_name, activities)

                    # Update checkpoint with latest activity time
                    latest_time = max(
                        activity['id']['time'] for activity in activities
                    )
                    collector.save_checkpoint(app_name, latest_time)

                total_collected += len(activities)
                results[app_name] = {
                    'count': len(activities),
                    'start_time': start_time,
                    'end_time': end_time,
                    'status': 'success'
                }

                logger.info(f"Successfully collected {len(activities)} {app_name} activities")

            except Exception as e:
                logger.error(f"Failed to collect {app_name} activities: {e}")
                results[app_name] = {
                    'count': 0,
                    'status': 'failed',
                    'error': str(e)
                }

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully collected {total_collected} activities',
                'results': results
            })
        }

    except Exception as e:
        logger.error(f"Lambda execution failed: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Failed to collect Google Workspace logs',
                'error': str(e)
            })
        }
