"""
Slack Audit Logs Collector Lambda Handler

Collects audit logs from Slack Enterprise Grid Audit Logs API and stores them in S3.
Requires Slack Enterprise Grid plan for audit log access.
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
LOGS_BUCKET = os.environ['LOGS_BUCKET']
CHECKPOINT_TABLE = os.environ['CHECKPOINT_TABLE']
API_TOKEN_SECRET = os.environ['API_TOKEN_SECRET']

# Slack API configuration
SLACK_API_BASE = 'https://api.slack.com'
AUDIT_LOGS_ENDPOINT = f'{SLACK_API_BASE}/api/audit/v1/logs'


class SlackCollector:
    """Collector for Slack Enterprise Grid Audit Logs"""

    def __init__(self):
        """Initialize the collector with API token"""
        self.api_token = self._get_api_token()
        self.session = self._create_session()
        self.checkpoint_table = dynamodb.Table(CHECKPOINT_TABLE)

    def _get_api_token(self) -> str:
        """Retrieve Slack API token from Secrets Manager"""
        response = secrets_client.get_secret_value(SecretId=API_TOKEN_SECRET)
        secret_data = json.loads(response['SecretString'])
        return secret_data['slack_token']

    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic"""
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=['GET']
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('https://', adapter)
        return session

    def get_checkpoint(self) -> Optional[int]:
        """
        Get last fetch timestamp from DynamoDB.

        Returns:
            Unix timestamp or None
        """
        try:
            response = self.checkpoint_table.get_item(
                Key={'source': 'slack_audit_logs'}
            )
            if 'Item' in response:
                return int(response['Item']['last_fetch_timestamp'])
            return None
        except Exception as e:
            logger.warning(f"Failed to get checkpoint: {e}")
            return None

    def save_checkpoint(self, timestamp: int):
        """
        Save last fetch timestamp to DynamoDB.

        Args:
            timestamp: Unix timestamp
        """
        try:
            self.checkpoint_table.put_item(
                Item={
                    'source': 'slack_audit_logs',
                    'last_fetch_timestamp': timestamp,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
            )
            logger.info(f"Checkpoint saved: {timestamp}")
        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")

    def fetch_audit_logs(
        self,
        oldest: Optional[int] = None,
        latest: Optional[int] = None,
        limit: int = 1000
    ) -> List[Dict]:
        """
        Fetch audit logs from Slack API with pagination.

        Args:
            oldest: Unix timestamp for start of range
            latest: Unix timestamp for end of range
            limit: Maximum results per page

        Returns:
            List of audit log events
        """
        if oldest is None:
            # Default to last 30 minutes
            oldest = int((datetime.now(timezone.utc) - timedelta(minutes=30)).timestamp())

        headers = {
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json'
        }

        params = {
            'oldest': oldest,
            'limit': limit
        }

        if latest:
            params['latest'] = latest

        all_entries = []
        cursor = None

        try:
            while True:
                if cursor:
                    params['cursor'] = cursor

                response = self.session.get(
                    AUDIT_LOGS_ENDPOINT,
                    headers=headers,
                    params=params
                )

                # Handle rate limiting
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    logger.warning(f"Rate limited, waiting {retry_after} seconds")
                    import time
                    time.sleep(retry_after)
                    continue

                response.raise_for_status()
                data = response.json()

                if not data.get('ok'):
                    logger.error(f"Slack API error: {data.get('error')}")
                    break

                entries = data.get('entries', [])
                all_entries.extend(entries)

                logger.info(f"Fetched {len(entries)} audit log entries (total: {len(all_entries)})")

                # Check for next page
                response_metadata = data.get('response_metadata', {})
                cursor = response_metadata.get('next_cursor')

                if not cursor:
                    break

            return all_entries

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch audit logs: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise

    def store_logs_in_s3(self, entries: List[Dict]):
        """
        Store audit log entries in S3 with time-based partitioning.

        Args:
            entries: List of audit log entries to store
        """
        if not entries:
            logger.info("No audit log entries to store")
            return

        now = datetime.now(timezone.utc)

        # Create S3 key with partitioning
        s3_key = (
            f"slack/raw/audit_logs/"
            f"{now.year:04d}/{now.month:02d}/{now.day:02d}/{now.hour:02d}/"
            f"{now.strftime('%Y%m%d_%H%M%S')}.json"
        )

        # Convert to newline-delimited JSON
        ndjson_content = '\n'.join(json.dumps(entry) for entry in entries)

        try:
            s3_client.put_object(
                Bucket=LOGS_BUCKET,
                Key=s3_key,
                Body=ndjson_content.encode('utf-8'),
                ContentType='application/x-ndjson'
            )
            logger.info(f"Stored {len(entries)} entries to s3://{LOGS_BUCKET}/{s3_key}")
        except Exception as e:
            logger.error(f"Failed to store entries in S3: {e}")
            raise


def lambda_handler(event, context):
    """
    Lambda handler to collect Slack audit logs.

    Environment Variables:
        LOGS_BUCKET: S3 bucket for log storage
        CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
        API_TOKEN_SECRET: Secrets Manager secret with Slack API token

    Event Parameters (optional):
        oldest: Override start timestamp (Unix)
        latest: Override end timestamp (Unix)
    """
    try:
        collector = SlackCollector()

        # Get time range
        oldest = event.get('oldest')
        if not oldest:
            checkpoint = collector.get_checkpoint()
            if checkpoint:
                oldest = checkpoint
            else:
                # First run - get last 24 hours
                oldest = int((datetime.now(timezone.utc) - timedelta(hours=24)).timestamp())

        latest = event.get('latest')

        # Fetch audit logs
        entries = collector.fetch_audit_logs(
            oldest=oldest,
            latest=latest
        )

        # Store in S3
        if entries:
            collector.store_logs_in_s3(entries)

            # Update checkpoint with latest entry time
            latest_timestamp = max(entry['date_create'] for entry in entries)
            collector.save_checkpoint(latest_timestamp)

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully collected {len(entries)} audit log entries',
                'count': len(entries),
                'oldest': oldest,
                'latest': latest
            })
        }

    except Exception as e:
        logger.error(f"Lambda execution failed: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Failed to collect Slack audit logs',
                'error': str(e)
            })
        }
