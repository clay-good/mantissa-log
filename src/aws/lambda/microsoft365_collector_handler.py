"""
Microsoft 365 Management Activity API Collector Lambda Handler

Collects audit logs from Microsoft 365 (Exchange, SharePoint, Teams, Azure AD)
via the Office 365 Management Activity API and stores them in S3.
"""

import json
import os
import boto3
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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
CREDENTIALS_SECRET = os.environ.get('CREDENTIALS_SECRET', "mantissa/credentials/secret")
TENANT_ID = os.environ.get('TENANT_ID', "")

# Microsoft 365 API configuration
OAUTH_URL = f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token'
API_BASE = 'https://manage.office.com/api/v1.0'

# Content types to collect
CONTENT_TYPES = [
    'Audit.AzureActiveDirectory',
    'Audit.Exchange',
    'Audit.SharePoint',
    'Audit.General',
    'DLP.All'
]


class Microsoft365Collector:
    """Collector for Microsoft 365 Management Activity API"""

    def __init__(self):
        """Initialize the collector with OAuth credentials"""
        self.credentials = self._get_credentials()
        self.session = self._create_session()
        self.access_token = None
        self.checkpoint_table = dynamodb.Table(CHECKPOINT_TABLE)
        self._authenticate()

    def _get_credentials(self) -> Dict[str, str]:
        """Retrieve OAuth credentials from Secrets Manager"""
        response = secrets_client.get_secret_value(SecretId=CREDENTIALS_SECRET)
        return json.loads(response['SecretString'])

    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic"""
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=['GET', 'POST']
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('https://', adapter)
        return session

    def _authenticate(self):
        """Authenticate with Microsoft 365 OAuth2"""
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.credentials['client_id'],
            'client_secret': self.credentials['client_secret'],
            'scope': 'https://manage.office.com/.default'
        }

        try:
            response = self.session.post(OAUTH_URL, data=data)
            response.raise_for_status()
            token_data = response.json()
            self.access_token = token_data['access_token']
            logger.info("Successfully authenticated to Microsoft 365 API")
        except Exception as e:
            logger.error(f"Failed to authenticate: {e}")
            raise

    def get_checkpoint(self, content_type: str) -> Optional[str]:
        """
        Get last fetch timestamp for content type from DynamoDB.

        Args:
            content_type: Microsoft 365 content type

        Returns:
            ISO 8601 timestamp or None
        """
        try:
            response = self.checkpoint_table.get_item(
                Key={'source': f'microsoft365_{content_type}'}
            )
            if 'Item' in response:
                return response['Item']['last_fetch_timestamp']
            return None
        except Exception as e:
            logger.warning(f"Failed to get checkpoint for {content_type}: {e}")
            return None

    def save_checkpoint(self, content_type: str, timestamp: str):
        """
        Save last fetch timestamp to DynamoDB.

        Args:
            content_type: Microsoft 365 content type
            timestamp: ISO 8601 timestamp
        """
        try:
            self.checkpoint_table.put_item(
                Item={
                    'source': f'microsoft365_{content_type}',
                    'last_fetch_timestamp': timestamp,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
            )
            logger.info(f"Checkpoint saved for {content_type}: {timestamp}")
        except Exception as e:
            logger.error(f"Failed to save checkpoint for {content_type}: {e}")

    def start_subscription(self, content_type: str) -> bool:
        """
        Start subscription to a content type (required before listing content).

        Args:
            content_type: Content type to subscribe to

        Returns:
            True if successful
        """
        url = f'{API_BASE}/{TENANT_ID}/activity/feed/subscriptions/start'
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        params = {'contentType': content_type}

        try:
            response = self.session.post(url, headers=headers, params=params)

            # 200 or 409 (already subscribed) are both OK
            if response.status_code in [200, 409]:
                logger.info(f"Subscription active for {content_type}")
                return True

            response.raise_for_status()
            return True

        except Exception as e:
            logger.error(f"Failed to start subscription for {content_type}: {e}")
            return False

    def list_content(
        self,
        content_type: str,
        start_time: str,
        end_time: str
    ) -> List[str]:
        """
        List available content blobs for a time range.

        Args:
            content_type: Content type to list
            start_time: Start time (ISO 8601)
            end_time: End time (ISO 8601)

        Returns:
            List of content URIs
        """
        url = f'{API_BASE}/{TENANT_ID}/activity/feed/subscriptions/content'
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        params = {
            'contentType': content_type,
            'startTime': start_time,
            'endTime': end_time
        }

        try:
            response = self.session.get(url, headers=headers, params=params)
            response.raise_for_status()

            content_list = response.json()
            content_uris = [item['contentUri'] for item in content_list]

            logger.info(f"Found {len(content_uris)} content blobs for {content_type}")
            return content_uris

        except Exception as e:
            logger.error(f"Failed to list content for {content_type}: {e}")
            return []

    def fetch_content(self, content_uri: str) -> List[Dict]:
        """
        Fetch audit records from a content blob.

        Args:
            content_uri: URI to fetch content from

        Returns:
            List of audit records
        """
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        try:
            response = self.session.get(content_uri, headers=headers)
            response.raise_for_status()

            records = response.json()
            logger.info(f"Fetched {len(records)} records from content blob")
            return records

        except Exception as e:
            logger.error(f"Failed to fetch content from {content_uri}: {e}")
            return []

    def store_logs_in_s3(self, content_type: str, records: List[Dict]):
        """
        Store audit records in S3 with time-based partitioning.

        Args:
            content_type: Content type for S3 path
            records: List of audit records to store
        """
        if not records:
            logger.info(f"No {content_type} records to store")
            return

        now = datetime.now(timezone.utc)

        # Sanitize content type for path
        content_type_clean = content_type.replace('.', '_').lower()

        # Create S3 key with partitioning
        s3_key = (
            f"microsoft365/raw/{content_type_clean}/"
            f"{now.year:04d}/{now.month:02d}/{now.day:02d}/{now.hour:02d}/"
            f"{now.strftime('%Y%m%d_%H%M%S')}.json"
        )

        # Convert to newline-delimited JSON
        ndjson_content = '\n'.join(json.dumps(record) for record in records)

        try:
            s3_client.put_object(
                Bucket=LOGS_BUCKET,
                Key=s3_key,
                Body=ndjson_content.encode('utf-8'),
                ContentType='application/x-ndjson'
            )
            logger.info(
                f"Stored {len(records)} {content_type} records to s3://{LOGS_BUCKET}/{s3_key}"
            )
        except Exception as e:
            logger.error(f"Failed to store {content_type} records in S3: {e}")
            raise


def lambda_handler(event, context):
    """
    Lambda handler to collect Microsoft 365 audit logs.

    Environment Variables:
        LOGS_BUCKET: S3 bucket for log storage
        CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
        CREDENTIALS_SECRET: Secrets Manager secret with OAuth credentials
        TENANT_ID: Microsoft 365 tenant ID

    Event Parameters (optional):
        content_types: List of content types to collect (default: all)
        start_time: Override start time (ISO 8601)
        end_time: Override end time (ISO 8601)
    """
    try:
        collector = Microsoft365Collector()

        # Get content types to collect
        content_types = event.get('content_types', CONTENT_TYPES)
        if isinstance(content_types, str):
            content_types = [content_types]

        # Get time range (API supports max 24 hour window)
        end_time = event.get('end_time')
        if not end_time:
            end_time = datetime.now(timezone.utc)
        else:
            end_time = datetime.fromisoformat(end_time.replace('Z', '+00:00'))

        total_collected = 0
        results = {}

        # Collect logs for each content type
        for content_type in content_types:
            logger.info(f"Collecting {content_type} logs")

            try:
                # Ensure subscription is active
                if not collector.start_subscription(content_type):
                    results[content_type] = {
                        'count': 0,
                        'status': 'failed',
                        'error': 'Failed to start subscription'
                    }
                    continue

                # Get start time from checkpoint or default
                start_time = event.get('start_time')
                if not start_time:
                    checkpoint = collector.get_checkpoint(content_type)
                    if checkpoint:
                        start_time = datetime.fromisoformat(checkpoint.replace('Z', '+00:00'))
                    else:
                        # First run - get last 24 hours
                        start_time = end_time - timedelta(hours=24)
                else:
                    start_time = datetime.fromisoformat(start_time.replace('Z', '+00:00'))

                # Ensure window is not more than 24 hours
                if (end_time - start_time) > timedelta(hours=24):
                    start_time = end_time - timedelta(hours=24)

                start_time_str = start_time.isoformat() + 'Z'
                end_time_str = end_time.isoformat() + 'Z'

                # List available content
                content_uris = collector.list_content(
                    content_type=content_type,
                    start_time=start_time_str,
                    end_time=end_time_str
                )

                # Fetch and store each content blob
                all_records = []
                for uri in content_uris:
                    records = collector.fetch_content(uri)
                    all_records.extend(records)

                if all_records:
                    collector.store_logs_in_s3(content_type, all_records)
                    collector.save_checkpoint(content_type, end_time_str)

                total_collected += len(all_records)
                results[content_type] = {
                    'count': len(all_records),
                    'content_blobs': len(content_uris),
                    'start_time': start_time_str,
                    'end_time': end_time_str,
                    'status': 'success'
                }

                logger.info(f"Successfully collected {len(all_records)} {content_type} records")

            except Exception as e:
                logger.error(f"Failed to collect {content_type} logs: {e}")
                results[content_type] = {
                    'count': 0,
                    'status': 'failed',
                    'error': str(e)
                }

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully collected {total_collected} records',
                'results': results
            })
        }

    except Exception as e:
        logger.error(f"Lambda execution failed: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Failed to collect Microsoft 365 logs',
                'error': str(e)
            })
        }
