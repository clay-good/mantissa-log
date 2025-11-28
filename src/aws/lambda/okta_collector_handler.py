"""
Okta System Log API Collector

Fetches authentication logs, admin activity, and system logs from Okta
and stores them in S3 for processing by Mantissa Log.
"""

import json
import os
import boto3
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class OktaCollector:
    """Collects logs from Okta System Log API"""

    def __init__(self, api_token: str, org_url: str, s3_bucket: str, checkpoint_table: str):
        """
        Initialize Okta collector.

        Args:
            api_token: Okta API token
            org_url: Okta organization URL (e.g., https://dev-12345.okta.com)
            s3_bucket: S3 bucket for log storage
            checkpoint_table: DynamoDB table for checkpoint tracking
        """
        self.api_token = api_token
        self.org_url = org_url.rstrip('/')
        self.s3_bucket = s3_bucket
        self.checkpoint_table = checkpoint_table

        self.s3 = boto3.client('s3')
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(checkpoint_table)

        # Configure requests session with retry logic
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.headers.update({
            'Authorization': f'SSWS {self.api_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })

    def get_last_checkpoint(self) -> Optional[str]:
        """
        Get last fetch timestamp from DynamoDB.

        Returns:
            ISO 8601 timestamp or None if no checkpoint exists
        """
        try:
            response = self.table.get_item(Key={'source': 'okta'})
            if 'Item' in response:
                return response['Item'].get('last_fetch_timestamp')
        except Exception as e:
            print(f"Error getting checkpoint: {str(e)}")

        return None

    def save_checkpoint(self, timestamp: str) -> None:
        """
        Save checkpoint timestamp to DynamoDB.

        Args:
            timestamp: ISO 8601 timestamp to save
        """
        try:
            self.table.put_item(
                Item={
                    'source': 'okta',
                    'last_fetch_timestamp': timestamp,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
            )
        except Exception as e:
            print(f"Error saving checkpoint: {str(e)}")

    def fetch_system_logs(
        self,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: int = 1000
    ) -> List[Dict]:
        """
        Fetch system logs from Okta API.

        Args:
            since: ISO 8601 timestamp for start of query (default: 15 minutes ago)
            until: ISO 8601 timestamp for end of query (default: now)
            limit: Maximum number of events per page

        Returns:
            List of log events
        """
        if not since:
            since = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()

        if not until:
            until = datetime.now(timezone.utc).isoformat()

        url = f"{self.org_url}/api/v1/logs"
        params = {
            'since': since,
            'until': until,
            'limit': limit,
            'sortOrder': 'ASCENDING'
        }

        all_events = []

        while url:
            try:
                response = self.session.get(url, params=params if params else None)
                response.raise_for_status()

                events = response.json()
                all_events.extend(events)

                # Check for next page
                next_link = response.links.get('next')
                if next_link:
                    url = next_link['url']
                    params = None  # URL already contains params
                else:
                    url = None

                print(f"Fetched {len(events)} events (total: {len(all_events)})")

            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    # Rate limit exceeded
                    retry_after = int(e.response.headers.get('X-Rate-Limit-Reset', 60))
                    print(f"Rate limit exceeded. Retry after {retry_after} seconds")
                    raise
                else:
                    print(f"HTTP error: {str(e)}")
                    raise

            except Exception as e:
                print(f"Error fetching logs: {str(e)}")
                raise

        return all_events

    def write_to_s3(self, events: List[Dict], timestamp: datetime) -> str:
        """
        Write events to S3 in partitioned structure.

        Args:
            events: List of log events
            timestamp: Timestamp for partitioning

        Returns:
            S3 key where data was written
        """
        if not events:
            return None

        # Create partition path: okta/raw/YYYY/MM/DD/HH/
        year = timestamp.strftime('%Y')
        month = timestamp.strftime('%m')
        day = timestamp.strftime('%d')
        hour = timestamp.strftime('%H')
        minute = timestamp.strftime('%M')

        s3_key = f"okta/raw/{year}/{month}/{day}/{hour}/events_{minute}.json"

        # Write events as newline-delimited JSON
        data = '\n'.join([json.dumps(event) for event in events])

        try:
            self.s3.put_object(
                Bucket=self.s3_bucket,
                Key=s3_key,
                Body=data.encode('utf-8'),
                ContentType='application/json'
            )
            print(f"Wrote {len(events)} events to s3://{self.s3_bucket}/{s3_key}")
            return s3_key

        except Exception as e:
            print(f"Error writing to S3: {str(e)}")
            raise

    def collect(self) -> Dict:
        """
        Main collection logic.

        Returns:
            Dictionary with collection statistics
        """
        # Get last checkpoint
        last_checkpoint = self.get_last_checkpoint()

        # If no checkpoint, start from 15 minutes ago
        if not last_checkpoint:
            last_checkpoint = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()

        print(f"Fetching Okta logs since {last_checkpoint}")

        # Fetch logs
        now = datetime.now(timezone.utc)
        events = self.fetch_system_logs(since=last_checkpoint, until=now.isoformat())

        # Write to S3
        s3_key = None
        if events:
            s3_key = self.write_to_s3(events, now)

            # Update checkpoint to the timestamp of the last event
            # This ensures we don't miss events if collection fails partway
            latest_event_time = events[-1].get('published', now.isoformat())
            self.save_checkpoint(latest_event_time)
        else:
            print("No new events to process")
            # Update checkpoint anyway to avoid re-querying same time range
            self.save_checkpoint(now.isoformat())

        return {
            'events_fetched': len(events),
            's3_key': s3_key,
            'checkpoint': last_checkpoint,
            'latest_timestamp': events[-1].get('published') if events else None
        }


def lambda_handler(event, context):
    """
    AWS Lambda handler for Okta log collection.

    Environment Variables:
        OKTA_API_TOKEN_SECRET: AWS Secrets Manager secret ID containing Okta API token
        OKTA_ORG_URL: Okta organization URL
        S3_BUCKET: S3 bucket for log storage
        CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
    """
    # Get configuration from environment
    api_token_secret = os.environ['OKTA_API_TOKEN_SECRET']
    org_url = os.environ['OKTA_ORG_URL']
    s3_bucket = os.environ['S3_BUCKET']
    checkpoint_table = os.environ.get('CHECKPOINT_TABLE', 'mantissa-log-checkpoints')

    # Retrieve API token from Secrets Manager
    secrets_client = boto3.client('secretsmanager')
    try:
        secret_response = secrets_client.get_secret_value(SecretId=api_token_secret)
        secret_data = json.loads(secret_response['SecretString'])
        api_token = secret_data['api_token']
    except Exception as e:
        print(f"Error retrieving secret: {str(e)}")
        raise

    # Initialize collector
    collector = OktaCollector(
        api_token=api_token,
        org_url=org_url,
        s3_bucket=s3_bucket,
        checkpoint_table=checkpoint_table
    )

    # Run collection
    try:
        result = collector.collect()

        return {
            'statusCode': 200,
            'body': json.dumps(result)
        }

    except Exception as e:
        print(f"Collection failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }
