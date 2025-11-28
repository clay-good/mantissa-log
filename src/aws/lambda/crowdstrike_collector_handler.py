"""
CrowdStrike Falcon Event Streams Collector Lambda Handler

Collects detection events and audit logs from CrowdStrike Falcon Event Streams API.
Supports:
- DetectionSummaryEvent (malware, suspicious behavior)
- IncidentSummaryEvent (incidents and investigations)
- AuditEvent (admin activity, policy changes)
- UserActivityAuditEvent (user authentication events)
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
API_CREDENTIALS_SECRET = os.environ['API_CREDENTIALS_SECRET']
FALCON_CLOUD = os.environ.get('FALCON_CLOUD', 'us-1')  # us-1, us-2, eu-1, us-gov-1

# CrowdStrike API configuration
CLOUD_ENDPOINTS = {
    'us-1': 'https://api.crowdstrike.com',
    'us-2': 'https://api.us-2.crowdstrike.com',
    'eu-1': 'https://api.eu-1.crowdstrike.com',
    'us-gov-1': 'https://api.laggar.gcw.crowdstrike.com'
}

STREAM_NAMES = [
    'DetectionSummaryEvent',
    'IncidentSummaryEvent',
    'AuditEvent',
    'UserActivityAuditEvent'
]


class CrowdStrikeCollector:
    """Collector for CrowdStrike Falcon Event Streams"""

    def __init__(self):
        """Initialize the collector with API credentials"""
        self.base_url = CLOUD_ENDPOINTS.get(FALCON_CLOUD)
        self.session = self._create_session()
        self.access_token = None
        self.checkpoint_table = dynamodb.Table(CHECKPOINT_TABLE)
        self._authenticate()

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
        """Authenticate with CrowdStrike API using OAuth2"""
        # Get credentials from Secrets Manager
        response = secrets_client.get_secret_value(SecretId=API_CREDENTIALS_SECRET)
        credentials = json.loads(response['SecretString'])

        client_id = credentials['client_id']
        client_secret = credentials['client_secret']

        # Request OAuth2 token
        url = f"{self.base_url}/oauth2/token"
        data = {
            'client_id': client_id,
            'client_secret': client_secret
        }

        try:
            response = self.session.post(url, data=data)
            response.raise_for_status()
            token_data = response.json()
            self.access_token = token_data['access_token']
            logger.info("Successfully authenticated to CrowdStrike API")
        except Exception as e:
            logger.error(f"Failed to authenticate: {e}")
            raise

    def get_checkpoint(self, stream_name: str) -> Optional[int]:
        """
        Get last offset for stream from DynamoDB.

        Args:
            stream_name: CrowdStrike stream name

        Returns:
            Offset integer or None
        """
        try:
            response = self.checkpoint_table.get_item(
                Key={'source': f'crowdstrike_{stream_name}'}
            )
            if 'Item' in response:
                return int(response['Item']['last_offset'])
            return None
        except Exception as e:
            logger.warning(f"Failed to get checkpoint for {stream_name}: {e}")
            return None

    def save_checkpoint(self, stream_name: str, offset: int):
        """
        Save last offset to DynamoDB.

        Args:
            stream_name: CrowdStrike stream name
            offset: Offset integer
        """
        try:
            self.checkpoint_table.put_item(
                Item={
                    'source': f'crowdstrike_{stream_name}',
                    'last_offset': offset,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
            )
            logger.info(f"Checkpoint saved for {stream_name}: {offset}")
        except Exception as e:
            logger.error(f"Failed to save checkpoint for {stream_name}: {e}")

    def discover_stream(self, stream_name: str) -> Optional[str]:
        """
        Discover data feed URL for a stream.

        Args:
            stream_name: CrowdStrike stream name

        Returns:
            Data feed URL or None
        """
        url = f"{self.base_url}/sensors/entities/datafeed/v2"
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        params = {
            'appId': 'mantissa-log-collector',
            'format': 'json'
        }

        try:
            response = self.session.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

            if data.get('errors'):
                logger.error(f"Error discovering stream: {data['errors']}")
                return None

            resources = data.get('resources', [])
            for resource in resources:
                if resource.get('dataFeedURL'):
                    logger.info(f"Discovered data feed URL for {stream_name}")
                    return resource['dataFeedURL']

            return None
        except Exception as e:
            logger.error(f"Failed to discover stream {stream_name}: {e}")
            return None

    def fetch_events(
        self,
        stream_name: str,
        data_feed_url: str,
        offset: Optional[int] = None
    ) -> tuple[List[Dict], Optional[int]]:
        """
        Fetch events from CrowdStrike Event Stream.

        Args:
            stream_name: Stream name for filtering
            data_feed_url: Data feed URL from discovery
            offset: Starting offset (None for beginning)

        Returns:
            Tuple of (events list, next offset)
        """
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        params = {}
        if offset is not None:
            params['offset'] = offset

        try:
            response = self.session.get(data_feed_url, headers=headers, params=params)
            response.raise_for_status()

            # Parse response
            events = []
            next_offset = None

            # CrowdStrike returns newline-delimited JSON
            for line in response.text.strip().split('\n'):
                if not line:
                    continue

                try:
                    event = json.loads(line)

                    # Extract metadata
                    metadata = event.get('metadata', {})
                    event_type = metadata.get('eventType', '')

                    # Filter by stream name
                    if event_type == stream_name:
                        events.append(event)

                    # Update offset from last event
                    if metadata.get('offset'):
                        next_offset = metadata['offset']

                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse event line: {e}")
                    continue

            logger.info(f"Fetched {len(events)} events from {stream_name} stream")
            return events, next_offset

        except Exception as e:
            logger.error(f"Failed to fetch events from {stream_name}: {e}")
            return [], offset

    def store_logs_in_s3(self, stream_name: str, events: List[Dict]):
        """
        Store events in S3 with time-based partitioning.

        Args:
            stream_name: Stream name for S3 path
            events: List of events to store
        """
        if not events:
            logger.info(f"No {stream_name} events to store")
            return

        now = datetime.now(timezone.utc)

        # Create S3 key with partitioning
        s3_key = (
            f"crowdstrike/raw/{stream_name}/"
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
            logger.info(
                f"Stored {len(events)} {stream_name} events to s3://{LOGS_BUCKET}/{s3_key}"
            )
        except Exception as e:
            logger.error(f"Failed to store {stream_name} events in S3: {e}")
            raise


def lambda_handler(event, context):
    """
    Lambda handler to collect CrowdStrike Falcon events.

    Environment Variables:
        LOGS_BUCKET: S3 bucket for log storage
        CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
        API_CREDENTIALS_SECRET: Secrets Manager secret with CrowdStrike API credentials
        FALCON_CLOUD: CrowdStrike cloud (us-1, us-2, eu-1, us-gov-1)

    Event Parameters (optional):
        stream_names: List of streams to collect (default: all)
    """
    try:
        collector = CrowdStrikeCollector()

        # Get stream names to collect
        stream_names = event.get('stream_names', STREAM_NAMES)
        if isinstance(stream_names, str):
            stream_names = [stream_names]

        total_collected = 0
        results = {}

        # Discover data feed URL (shared across all streams)
        data_feed_url = collector.discover_stream('all')
        if not data_feed_url:
            logger.error("Failed to discover data feed URL")
            return {
                'statusCode': 500,
                'body': json.dumps({
                    'message': 'Failed to discover CrowdStrike data feed',
                    'error': 'No data feed URL available'
                })
            }

        # Collect events for each stream
        for stream_name in stream_names:
            logger.info(f"Collecting {stream_name} events")

            try:
                # Get checkpoint
                offset = collector.get_checkpoint(stream_name)

                # Fetch events
                events, next_offset = collector.fetch_events(
                    stream_name=stream_name,
                    data_feed_url=data_feed_url,
                    offset=offset
                )

                # Store in S3
                if events:
                    collector.store_logs_in_s3(stream_name, events)

                    # Update checkpoint
                    if next_offset is not None:
                        collector.save_checkpoint(stream_name, next_offset)

                total_collected += len(events)
                results[stream_name] = {
                    'count': len(events),
                    'offset': next_offset,
                    'status': 'success'
                }

                logger.info(f"Successfully collected {len(events)} {stream_name} events")

            except Exception as e:
                logger.error(f"Failed to collect {stream_name} events: {e}")
                results[stream_name] = {
                    'count': 0,
                    'status': 'failed',
                    'error': str(e)
                }

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully collected {total_collected} events',
                'results': results
            })
        }

    except Exception as e:
        logger.error(f"Lambda execution failed: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Failed to collect CrowdStrike events',
                'error': str(e)
            })
        }
