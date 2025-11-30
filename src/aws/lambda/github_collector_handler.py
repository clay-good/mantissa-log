"""
GitHub Enterprise Audit Log Collector Lambda Handler

Collects audit logs from GitHub Enterprise Cloud or Server via the Audit Log API
and stores them in S3. Supports both enterprise-level and organization-level audit logs.
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
API_TOKEN_SECRET = os.environ.get('API_TOKEN_SECRET', "mantissa/api/token/secret")
GITHUB_ENTERPRISE = os.environ.get('GITHUB_ENTERPRISE', '')  # Enterprise slug
GITHUB_ORG = os.environ.get('GITHUB_ORG', '')  # Organization name (if not enterprise-level)

# GitHub API configuration
GITHUB_API_BASE = os.environ.get('GITHUB_API_BASE', 'https://api.github.com')


class GitHubCollector:
    """Collector for GitHub Enterprise Audit Logs"""

    def __init__(self):
        """Initialize the collector with API token"""
        self.api_token = self._get_api_token()
        self.session = self._create_session()
        self.checkpoint_table = dynamodb.Table(CHECKPOINT_TABLE)
        self.enterprise = GITHUB_ENTERPRISE
        self.organization = GITHUB_ORG

        # Determine audit log endpoint
        if self.enterprise:
            self.audit_endpoint = f'{GITHUB_API_BASE}/enterprises/{self.enterprise}/audit-log'
            self.source_key = f'github_enterprise_{self.enterprise}'
        elif self.organization:
            self.audit_endpoint = f'{GITHUB_API_BASE}/orgs/{self.organization}/audit-log'
            self.source_key = f'github_org_{self.organization}'
        else:
            raise ValueError("Either GITHUB_ENTERPRISE or GITHUB_ORG must be specified")

    def _get_api_token(self) -> str:
        """Retrieve GitHub API token from Secrets Manager"""
        response = secrets_client.get_secret_value(SecretId=API_TOKEN_SECRET)
        secret_data = json.loads(response['SecretString'])
        return secret_data['github_token']

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
            Unix timestamp (milliseconds) or None
        """
        try:
            response = self.checkpoint_table.get_item(
                Key={'source': self.source_key}
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
            timestamp: Unix timestamp (milliseconds)
        """
        try:
            self.checkpoint_table.put_item(
                Item={
                    'source': self.source_key,
                    'last_fetch_timestamp': timestamp,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
            )
            logger.info(f"Checkpoint saved: {timestamp}")
        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")

    def fetch_audit_logs(
        self,
        phrase: Optional[str] = None,
        include: Optional[str] = None,
        after: Optional[str] = None,
        before: Optional[str] = None,
        order: str = 'asc',
        per_page: int = 100
    ) -> List[Dict]:
        """
        Fetch audit logs from GitHub API with pagination.

        Args:
            phrase: Search phrase for filtering events
            include: Include additional data (e.g., 'web', 'git', 'all')
            after: Return events after this cursor
            before: Return events before this cursor
            order: Order of events ('asc' or 'desc')
            per_page: Results per page (max 100)

        Returns:
            List of audit log events
        """
        headers = {
            'Authorization': f'Bearer {self.api_token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }

        params = {
            'per_page': per_page,
            'order': order
        }

        if phrase:
            params['phrase'] = phrase
        if include:
            params['include'] = include
        if after:
            params['after'] = after
        if before:
            params['before'] = before

        all_events = []
        page = 1

        try:
            while True:
                params['page'] = page

                response = self.session.get(
                    self.audit_endpoint,
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
                events = response.json()

                if not events:
                    break

                all_events.extend(events)
                logger.info(f"Fetched {len(events)} audit log events (page {page}, total: {len(all_events)})")

                # Check if there are more pages
                link_header = response.headers.get('Link', '')
                if 'rel="next"' not in link_header:
                    break

                page += 1

            return all_events

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch audit logs: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise

    def fetch_audit_logs_by_timestamp(
        self,
        start_timestamp: int,
        end_timestamp: Optional[int] = None
    ) -> List[Dict]:
        """
        Fetch audit logs within a timestamp range.

        Args:
            start_timestamp: Start timestamp (milliseconds)
            end_timestamp: End timestamp (milliseconds), defaults to now

        Returns:
            List of audit log events
        """
        if end_timestamp is None:
            end_timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)

        # Convert timestamps to ISO 8601 for phrase search
        start_dt = datetime.fromtimestamp(start_timestamp / 1000, tz=timezone.utc)
        end_dt = datetime.fromtimestamp(end_timestamp / 1000, tz=timezone.utc)

        # GitHub audit log API uses phrase search for time ranges
        # Format: created:>=YYYY-MM-DD created:<=YYYY-MM-DD
        phrase = f"created:>={start_dt.strftime('%Y-%m-%d')} created:<={end_dt.strftime('%Y-%m-%d')}"

        logger.info(f"Fetching audit logs with phrase: {phrase}")

        events = self.fetch_audit_logs(
            phrase=phrase,
            include='all',  # Include web, git, and all available data
            order='asc'
        )

        # Filter events by exact timestamp range (API only filters by day)
        filtered_events = [
            event for event in events
            if start_timestamp <= event.get('@timestamp', 0) <= end_timestamp
        ]

        logger.info(f"Filtered {len(filtered_events)} events within exact timestamp range")
        return filtered_events

    def store_logs_in_s3(self, events: List[Dict]):
        """
        Store audit log events in S3 with time-based partitioning.

        Args:
            events: List of audit log events to store
        """
        if not events:
            logger.info("No audit log events to store")
            return

        now = datetime.now(timezone.utc)

        # Determine source prefix
        if self.enterprise:
            source_prefix = f"enterprise/{self.enterprise}"
        else:
            source_prefix = f"org/{self.organization}"

        # Create S3 key with partitioning
        s3_key = (
            f"github/raw/{source_prefix}/"
            f"{now.year:04d}/{now.month:02d}/{now.day:02d}/{now.hour:02d}/"
            f"{now.strftime('%Y%m%d_%H%M%S')}.json"
        )

        # Convert to newline-delimited JSON
        ndjson_content = '\n'.join(json.dumps(event) for event in events)

        try:
            s3_client.put_object(
                Bucket=LOGS_BUCKET,
                Key=s3_key,
                Body=ndjson_content.encode('utf-8'),
                ContentType='application/x-ndjson'
            )
            logger.info(f"Stored {len(events)} events to s3://{LOGS_BUCKET}/{s3_key}")
        except Exception as e:
            logger.error(f"Failed to store events in S3: {e}")
            raise


def lambda_handler(event, context):
    """
    Lambda handler to collect GitHub audit logs.

    Environment Variables:
        LOGS_BUCKET: S3 bucket for log storage
        CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
        API_TOKEN_SECRET: Secrets Manager secret with GitHub API token
        GITHUB_ENTERPRISE: GitHub Enterprise slug (optional)
        GITHUB_ORG: GitHub organization name (optional, used if GITHUB_ENTERPRISE not set)
        GITHUB_API_BASE: GitHub API base URL (default: https://api.github.com)

    Event Parameters (optional):
        start_timestamp: Override start timestamp (milliseconds)
        end_timestamp: Override end timestamp (milliseconds)
        phrase: Search phrase for filtering events
    """
    try:
        collector = GitHubCollector()

        # Get time range
        start_timestamp = event.get('start_timestamp')
        if not start_timestamp:
            checkpoint = collector.get_checkpoint()
            if checkpoint:
                start_timestamp = checkpoint
            else:
                # First run - get last 24 hours
                start_timestamp = int((datetime.now(timezone.utc) - timedelta(hours=24)).timestamp() * 1000)

        end_timestamp = event.get('end_timestamp')

        # Check for custom phrase search
        phrase = event.get('phrase')

        if phrase:
            # Custom phrase-based search
            events = collector.fetch_audit_logs(
                phrase=phrase,
                include='all'
            )
        else:
            # Timestamp-based search
            events = collector.fetch_audit_logs_by_timestamp(
                start_timestamp=start_timestamp,
                end_timestamp=end_timestamp
            )

        # Store in S3
        if events:
            collector.store_logs_in_s3(events)

            # Update checkpoint with latest event timestamp
            latest_timestamp = max(event.get('@timestamp', 0) for event in events)
            collector.save_checkpoint(latest_timestamp)

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully collected {len(events)} audit log events',
                'count': len(events),
                'start_timestamp': start_timestamp,
                'end_timestamp': end_timestamp
            })
        }

    except Exception as e:
        logger.error(f"Lambda execution failed: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Failed to collect GitHub audit logs',
                'error': str(e)
            })
        }
