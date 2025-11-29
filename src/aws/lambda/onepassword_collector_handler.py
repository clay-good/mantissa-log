"""
1Password Events API Collector

Collects 1Password Business/Enterprise audit events via the Events API.

1Password Event Types Collected:
- Sign-in attempts (success and failure)
- Item usage (access, creation, modification)
- Vault access and changes
- User and group management
- Administrative actions
- Service account activity

Authentication:
- Bearer token from 1Password Events API

Reference:
- https://developer.1password.com/docs/events-api/
- https://developer.1password.com/docs/events-api/reference/
"""

import json
import os
import boto3
import requests
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any

from shared.parsers.onepassword import OnePasswordParser


class OnePasswordCollector:
    """Collects 1Password events via Events API"""

    # 1Password Events API endpoints
    API_BASE_URL = "https://events.1password.com"
    API_VERSION = "api/v1"

    # Event types available in the API
    EVENT_TYPES = {
        'signinattempts': '/signinattempts',
        'itemusages': '/itemusages',
        'auditevents': '/auditevents',
    }

    def __init__(
        self,
        s3_bucket: str,
        output_prefix: str,
        checkpoint_table: str,
        api_token: str,
        features: List[str] = None
    ):
        """
        Initialize 1Password collector.

        Args:
            s3_bucket: S3 bucket for log storage
            output_prefix: S3 prefix for output
            checkpoint_table: DynamoDB table for checkpoint tracking
            api_token: 1Password Events API bearer token
            features: List of event types to collect (signinattempts, itemusages, auditevents)
        """
        self.s3_bucket = s3_bucket
        self.output_prefix = output_prefix
        self.checkpoint_table = checkpoint_table
        self.api_token = api_token
        self.features = features or ['signinattempts', 'itemusages', 'auditevents']

        self.s3 = boto3.client('s3')
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(checkpoint_table)

        self.parser = OnePasswordParser()

    def get_last_checkpoint(self, event_type: str) -> Optional[str]:
        """
        Get last processed cursor from DynamoDB.

        Args:
            event_type: Type of events being collected

        Returns:
            Last cursor or None
        """
        try:
            response = self.table.get_item(
                Key={'source': f'onepassword:{event_type}'}
            )
            if 'Item' in response:
                return response['Item'].get('cursor')
        except Exception as e:
            print(f"Error getting checkpoint: {str(e)}")

        return None

    def save_checkpoint(self, cursor: str, event_type: str) -> None:
        """
        Save checkpoint cursor to DynamoDB.

        Args:
            cursor: Cursor for next page
            event_type: Type of events being collected
        """
        try:
            self.table.put_item(
                Item={
                    'source': f'onepassword:{event_type}',
                    'cursor': cursor,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
            )
        except Exception as e:
            print(f"Error saving checkpoint: {str(e)}")

    def _api_request(
        self,
        endpoint: str,
        cursor: str = None,
        start_time: str = None,
        limit: int = 1000
    ) -> Optional[Dict]:
        """Make authenticated API request to 1Password Events API"""
        url = f"{self.API_BASE_URL}/{self.API_VERSION}{endpoint}"

        headers = {
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json'
        }

        # Build request body
        body = {
            'limit': limit
        }

        if cursor:
            body['cursor'] = cursor
        elif start_time:
            body['start_time'] = start_time

        try:
            response = requests.post(url, headers=headers, json=body)
            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"API request failed for {endpoint}: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response: {e.response.text}")
            return None

    def query_signin_attempts(
        self,
        cursor: str = None,
        start_time: str = None,
        limit: int = 1000
    ) -> Dict:
        """
        Query sign-in attempt events.

        Args:
            cursor: Pagination cursor
            start_time: Start time for events (ISO 8601)
            limit: Maximum events to return

        Returns:
            API response with events and cursor
        """
        endpoint = self.EVENT_TYPES['signinattempts']
        return self._api_request(endpoint, cursor, start_time, limit)

    def query_item_usages(
        self,
        cursor: str = None,
        start_time: str = None,
        limit: int = 1000
    ) -> Dict:
        """
        Query item usage events.

        Args:
            cursor: Pagination cursor
            start_time: Start time for events (ISO 8601)
            limit: Maximum events to return

        Returns:
            API response with events and cursor
        """
        endpoint = self.EVENT_TYPES['itemusages']
        return self._api_request(endpoint, cursor, start_time, limit)

    def query_audit_events(
        self,
        cursor: str = None,
        start_time: str = None,
        limit: int = 1000
    ) -> Dict:
        """
        Query audit events.

        Args:
            cursor: Pagination cursor
            start_time: Start time for events (ISO 8601)
            limit: Maximum events to return

        Returns:
            API response with events and cursor
        """
        endpoint = self.EVENT_TYPES['auditevents']
        return self._api_request(endpoint, cursor, start_time, limit)

    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse and normalize 1Password events.

        Args:
            events: Raw 1Password events

        Returns:
            Normalized events
        """
        normalized = []

        for event in events:
            if not self.parser.validate(event):
                continue

            try:
                normalized_event = self.parser.parse(event)
                normalized.append(normalized_event)
            except Exception as e:
                print(f"Error parsing event: {str(e)}")
                continue

        return normalized

    def write_normalized_events(
        self,
        events: List[Dict[str, Any]],
        event_type: str,
        timestamp: datetime
    ) -> Optional[str]:
        """
        Write normalized events to S3.

        Args:
            events: Normalized events
            event_type: 1Password event type
            timestamp: Timestamp for partitioning

        Returns:
            S3 key where data was written
        """
        if not events:
            return None

        # Create partition path
        year = timestamp.strftime('%Y')
        month = timestamp.strftime('%m')
        day = timestamp.strftime('%d')
        hour = timestamp.strftime('%H')
        minute = timestamp.strftime('%M')
        second = timestamp.strftime('%S')

        s3_key = (
            f"{self.output_prefix}/normalized/{event_type}/"
            f"{year}/{month}/{day}/{hour}/events_{minute}{second}.json"
        )

        # Write as newline-delimited JSON
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

    def collect_signin_attempts(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Collect sign-in attempt events.

        Args:
            hours_back: Hours of history to collect if no checkpoint

        Returns:
            Collection statistics
        """
        event_type = 'signinattempts'

        # Get last checkpoint or calculate start time
        cursor = self.get_last_checkpoint(event_type)
        start_time = None

        if not cursor:
            start_time = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()

        all_events = []
        total_pages = 0
        max_pages = 100  # Safety limit

        while total_pages < max_pages:
            result = self.query_signin_attempts(cursor=cursor, start_time=start_time)

            if not result:
                break

            events = result.get('items', [])
            all_events.extend(events)

            # Check for next page
            cursor = result.get('cursor')
            has_more = result.get('has_more', False)

            if not has_more or not cursor:
                break

            start_time = None  # Only use start_time for first request
            total_pages += 1

        print(f"Collected {len(all_events)} sign-in attempt events")

        if not all_events:
            return {
                'event_type': event_type,
                'events_collected': 0,
                'events_normalized': 0
            }

        # Transform events to have consistent action field
        for event in all_events:
            if 'action' not in event:
                event['action'] = 'signin'
                if event.get('type') == 'mfa':
                    event['action'] = 'mfa_verify'

        # Normalize events
        normalized = self.process_events(all_events)

        # Write to S3
        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, event_type, now)

            # Save cursor for next run
            if cursor:
                self.save_checkpoint(cursor, event_type)

        return {
            'event_type': event_type,
            'events_collected': len(all_events),
            'events_normalized': len(normalized),
            'output_key': output_key
        }

    def collect_item_usages(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Collect item usage events.

        Args:
            hours_back: Hours of history to collect if no checkpoint

        Returns:
            Collection statistics
        """
        event_type = 'itemusages'

        # Get last checkpoint or calculate start time
        cursor = self.get_last_checkpoint(event_type)
        start_time = None

        if not cursor:
            start_time = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()

        all_events = []
        total_pages = 0
        max_pages = 100

        while total_pages < max_pages:
            result = self.query_item_usages(cursor=cursor, start_time=start_time)

            if not result:
                break

            events = result.get('items', [])
            all_events.extend(events)

            cursor = result.get('cursor')
            has_more = result.get('has_more', False)

            if not has_more or not cursor:
                break

            start_time = None
            total_pages += 1

        print(f"Collected {len(all_events)} item usage events")

        if not all_events:
            return {
                'event_type': event_type,
                'events_collected': 0,
                'events_normalized': 0
            }

        # Transform events to have consistent action field
        for event in all_events:
            if 'action' not in event:
                used_version = event.get('used_version', 0)
                if used_version == 0:
                    event['action'] = 'item_create'
                else:
                    event['action'] = 'item_usage'

        # Normalize events
        normalized = self.process_events(all_events)

        # Write to S3
        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, event_type, now)

            if cursor:
                self.save_checkpoint(cursor, event_type)

        return {
            'event_type': event_type,
            'events_collected': len(all_events),
            'events_normalized': len(normalized),
            'output_key': output_key
        }

    def collect_audit_events(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Collect audit events.

        Args:
            hours_back: Hours of history to collect if no checkpoint

        Returns:
            Collection statistics
        """
        event_type = 'auditevents'

        # Get last checkpoint or calculate start time
        cursor = self.get_last_checkpoint(event_type)
        start_time = None

        if not cursor:
            start_time = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()

        all_events = []
        total_pages = 0
        max_pages = 100

        while total_pages < max_pages:
            result = self.query_audit_events(cursor=cursor, start_time=start_time)

            if not result:
                break

            events = result.get('items', [])
            all_events.extend(events)

            cursor = result.get('cursor')
            has_more = result.get('has_more', False)

            if not has_more or not cursor:
                break

            start_time = None
            total_pages += 1

        print(f"Collected {len(all_events)} audit events")

        if not all_events:
            return {
                'event_type': event_type,
                'events_collected': 0,
                'events_normalized': 0
            }

        # Normalize events
        normalized = self.process_events(all_events)

        # Write to S3
        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, event_type, now)

            if cursor:
                self.save_checkpoint(cursor, event_type)

        return {
            'event_type': event_type,
            'events_collected': len(all_events),
            'events_normalized': len(normalized),
            'output_key': output_key
        }


def lambda_handler(event, context):
    """
    AWS Lambda handler for 1Password Events API collection.

    Supports collection modes:
    1. signinattempts: Collect sign-in attempt events
    2. itemusages: Collect item usage events
    3. auditevents: Collect audit events
    4. all: Collect all event types (default)

    Environment Variables:
        S3_BUCKET: S3 bucket for log storage
        OUTPUT_PREFIX: S3 prefix for output
        CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
        ONEPASSWORD_API_TOKEN: 1Password Events API bearer token
    """
    # Get configuration from environment
    s3_bucket = os.environ.get('S3_BUCKET', 'mantissa-log-data')
    output_prefix = os.environ.get('OUTPUT_PREFIX', 'onepassword')
    checkpoint_table = os.environ.get('CHECKPOINT_TABLE', 'mantissa-log-checkpoints')

    # 1Password configuration
    api_token = os.environ.get('ONEPASSWORD_API_TOKEN', '')

    # Validate configuration
    if not api_token:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': 'Missing ONEPASSWORD_API_TOKEN configuration'
            })
        }

    # Determine what to collect
    mode = event.get('mode', 'all')
    hours_back = event.get('hours_back', 24)

    features = []
    if mode == 'all':
        features = ['signinattempts', 'itemusages', 'auditevents']
    elif mode in ['signinattempts', 'itemusages', 'auditevents']:
        features = [mode]
    else:
        features = event.get('features', ['signinattempts', 'itemusages', 'auditevents'])

    # Initialize collector
    collector = OnePasswordCollector(
        s3_bucket=s3_bucket,
        output_prefix=output_prefix,
        checkpoint_table=checkpoint_table,
        api_token=api_token,
        features=features
    )

    try:
        results = {}

        if 'signinattempts' in features:
            results['signinattempts'] = collector.collect_signin_attempts(hours_back)

        if 'itemusages' in features:
            results['itemusages'] = collector.collect_item_usages(hours_back)

        if 'auditevents' in features:
            results['auditevents'] = collector.collect_audit_events(hours_back)

        return {
            'statusCode': 200,
            'body': json.dumps(results)
        }

    except Exception as e:
        print(f"Collection failed: {str(e)}")
        import traceback
        traceback.print_exc()

        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }
