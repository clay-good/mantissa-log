"""
Duo Security Admin API Log Collector

Fetches authentication logs, administrator activity logs, and telephony logs
from Duo Admin API and stores them in S3 for processing by Mantissa Log.

API Reference: https://duo.com/docs/adminapi
"""

import json
import os
import hmac
import hashlib
import base64
import email.utils
import urllib.parse
import boto3
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class DuoCollector:
    """Collects logs from Duo Admin API"""

    def __init__(
        self,
        integration_key: str,
        secret_key: str,
        api_hostname: str,
        s3_bucket: str,
        checkpoint_table: str
    ):
        """
        Initialize Duo collector.

        Args:
            integration_key: Duo Admin API integration key
            secret_key: Duo Admin API secret key
            api_hostname: Duo API hostname (e.g., api-XXXXXXXX.duosecurity.com)
            s3_bucket: S3 bucket for log storage
            checkpoint_table: DynamoDB table for checkpoint tracking
        """
        self.integration_key = integration_key
        self.secret_key = secret_key
        self.api_hostname = api_hostname
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

    def _sign_request(
        self,
        method: str,
        path: str,
        params: Dict[str, str],
        date: str
    ) -> str:
        """
        Sign request using Duo's HMAC-SHA1 signature method.

        Args:
            method: HTTP method
            path: API path
            params: Query parameters
            date: RFC 2822 date string

        Returns:
            Base64-encoded signature
        """
        # Sort params and encode
        sorted_params = sorted(params.items())
        param_string = urllib.parse.urlencode(sorted_params)

        # Create canonical request
        canon = [
            date,
            method.upper(),
            self.api_hostname.lower(),
            path,
            param_string
        ]
        canon_string = '\n'.join(canon)

        # Sign with HMAC-SHA1
        signature = hmac.new(
            self.secret_key.encode('utf-8'),
            canon_string.encode('utf-8'),
            hashlib.sha1
        )

        return base64.b64encode(signature.digest()).decode('utf-8')

    def _make_api_request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, str]] = None
    ) -> Dict:
        """
        Make authenticated request to Duo Admin API.

        Args:
            method: HTTP method
            path: API path
            params: Query parameters

        Returns:
            API response data
        """
        params = params or {}

        # Generate date header
        now = datetime.now(timezone.utc)
        date = email.utils.formatdate(now.timestamp())

        # Sign request
        signature = self._sign_request(method, path, params, date)

        # Build authorization header
        auth = f"{self.integration_key}:{signature}"
        auth_b64 = base64.b64encode(auth.encode('utf-8')).decode('utf-8')

        headers = {
            'Date': date,
            'Authorization': f'Basic {auth_b64}'
        }

        # Make request
        url = f"https://{self.api_hostname}{path}"

        response = self.session.request(
            method=method,
            url=url,
            params=params,
            headers=headers,
            timeout=30
        )

        # Check for rate limiting
        if response.status_code == 429:
            retry_after = int(response.headers.get('Retry-After', 60))
            print(f"Rate limited. Retry after {retry_after} seconds")
            raise Exception(f"Rate limited by Duo API. Retry after {retry_after}s")

        response.raise_for_status()

        data = response.json()

        if data.get('stat') != 'OK':
            error_msg = data.get('message', 'Unknown error')
            raise Exception(f"Duo API error: {error_msg}")

        return data.get('response', {})

    def get_last_checkpoint(self, log_type: str) -> Optional[int]:
        """
        Get last fetch timestamp from DynamoDB.

        Args:
            log_type: Type of log (authentication, admin, telephony)

        Returns:
            Unix timestamp or None
        """
        try:
            response = self.table.get_item(Key={'source': f'duo:{log_type}'})
            if 'Item' in response:
                return int(response['Item'].get('last_fetch_timestamp', 0))
        except Exception as e:
            print(f"Error getting checkpoint: {str(e)}")

        return None

    def save_checkpoint(self, log_type: str, timestamp: int) -> None:
        """
        Save checkpoint timestamp to DynamoDB.

        Args:
            log_type: Type of log
            timestamp: Unix timestamp to save
        """
        try:
            self.table.put_item(
                Item={
                    'source': f'duo:{log_type}',
                    'last_fetch_timestamp': timestamp,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
            )
        except Exception as e:
            print(f"Error saving checkpoint: {str(e)}")

    def fetch_authentication_logs(
        self,
        mintime: Optional[int] = None,
        maxtime: Optional[int] = None,
        limit: int = 1000
    ) -> List[Dict]:
        """
        Fetch authentication logs from Duo API.

        Args:
            mintime: Minimum timestamp (Unix milliseconds)
            maxtime: Maximum timestamp (Unix milliseconds)
            limit: Maximum events per request

        Returns:
            List of authentication events
        """
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

        if mintime is None:
            mintime = now_ms - (15 * 60 * 1000)  # 15 minutes ago

        if maxtime is None:
            maxtime = now_ms

        all_events = []
        next_offset = None

        while True:
            params = {
                'mintime': str(mintime),
                'maxtime': str(maxtime),
                'limit': str(limit)
            }

            if next_offset:
                params['next_offset'] = next_offset

            try:
                data = self._make_api_request('GET', '/admin/v2/logs/authentication', params)

                # Handle v2 API response
                if isinstance(data, dict):
                    events = data.get('authlogs', [])
                    metadata = data.get('metadata', {})
                    next_offset = metadata.get('next_offset')
                else:
                    events = data if isinstance(data, list) else []
                    next_offset = None

                all_events.extend(events)
                print(f"Fetched {len(events)} auth events (total: {len(all_events)})")

                if not next_offset or len(events) < limit:
                    break

            except Exception as e:
                print(f"Error fetching auth logs: {str(e)}")
                raise

        return all_events

    def fetch_admin_logs(
        self,
        mintime: Optional[int] = None
    ) -> List[Dict]:
        """
        Fetch administrator activity logs from Duo API.

        Args:
            mintime: Minimum timestamp (Unix seconds)

        Returns:
            List of admin activity events
        """
        now = int(datetime.now(timezone.utc).timestamp())

        if mintime is None:
            mintime = now - (15 * 60)  # 15 minutes ago

        params = {
            'mintime': str(mintime)
        }

        try:
            events = self._make_api_request('GET', '/admin/v1/logs/administrator', params)
            if not isinstance(events, list):
                events = []

            print(f"Fetched {len(events)} admin events")
            return events

        except Exception as e:
            print(f"Error fetching admin logs: {str(e)}")
            raise

    def fetch_telephony_logs(
        self,
        mintime: Optional[int] = None
    ) -> List[Dict]:
        """
        Fetch telephony logs from Duo API.

        Args:
            mintime: Minimum timestamp (Unix seconds)

        Returns:
            List of telephony events
        """
        now = int(datetime.now(timezone.utc).timestamp())

        if mintime is None:
            mintime = now - (15 * 60)

        params = {
            'mintime': str(mintime)
        }

        try:
            events = self._make_api_request('GET', '/admin/v1/logs/telephony', params)
            if not isinstance(events, list):
                events = []

            print(f"Fetched {len(events)} telephony events")
            return events

        except Exception as e:
            print(f"Error fetching telephony logs: {str(e)}")
            raise

    def write_to_s3(self, events: List[Dict], log_type: str, timestamp: datetime) -> Optional[str]:
        """
        Write events to S3 in partitioned structure.

        Args:
            events: List of log events
            log_type: Type of log for path
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

        s3_key = f"duo/{log_type}/raw/{year}/{month}/{day}/{hour}/events_{minute}.json"

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

    def collect_authentication_logs(self) -> Dict:
        """
        Collect authentication logs.

        Returns:
            Collection statistics
        """
        # Get last checkpoint (milliseconds for v2 API)
        last_checkpoint = self.get_last_checkpoint('authentication')

        if not last_checkpoint:
            # Start from 15 minutes ago
            last_checkpoint = int((datetime.now(timezone.utc) - timedelta(minutes=15)).timestamp() * 1000)

        print(f"Fetching Duo auth logs since {last_checkpoint}")

        # Fetch logs
        now = datetime.now(timezone.utc)
        now_ms = int(now.timestamp() * 1000)
        events = self.fetch_authentication_logs(mintime=last_checkpoint, maxtime=now_ms)

        # Write to S3
        s3_key = None
        if events:
            s3_key = self.write_to_s3(events, 'authentication', now)

            # Update checkpoint to latest event timestamp
            latest_ts = max(e.get('timestamp', 0) for e in events)
            if latest_ts:
                self.save_checkpoint('authentication', latest_ts * 1000 + 1)
        else:
            self.save_checkpoint('authentication', now_ms)

        return {
            'log_type': 'authentication',
            'events_fetched': len(events),
            's3_key': s3_key
        }

    def collect_admin_logs(self) -> Dict:
        """
        Collect administrator activity logs.

        Returns:
            Collection statistics
        """
        # Get last checkpoint (seconds for v1 API)
        last_checkpoint = self.get_last_checkpoint('admin')

        if not last_checkpoint:
            last_checkpoint = int((datetime.now(timezone.utc) - timedelta(minutes=15)).timestamp())

        print(f"Fetching Duo admin logs since {last_checkpoint}")

        # Fetch logs
        now = datetime.now(timezone.utc)
        events = self.fetch_admin_logs(mintime=last_checkpoint)

        # Write to S3
        s3_key = None
        if events:
            s3_key = self.write_to_s3(events, 'admin', now)

            latest_ts = max(e.get('timestamp', 0) for e in events)
            if latest_ts:
                self.save_checkpoint('admin', latest_ts + 1)
        else:
            self.save_checkpoint('admin', int(now.timestamp()))

        return {
            'log_type': 'admin',
            'events_fetched': len(events),
            's3_key': s3_key
        }

    def collect_telephony_logs(self) -> Dict:
        """
        Collect telephony logs.

        Returns:
            Collection statistics
        """
        last_checkpoint = self.get_last_checkpoint('telephony')

        if not last_checkpoint:
            last_checkpoint = int((datetime.now(timezone.utc) - timedelta(minutes=15)).timestamp())

        print(f"Fetching Duo telephony logs since {last_checkpoint}")

        now = datetime.now(timezone.utc)
        events = self.fetch_telephony_logs(mintime=last_checkpoint)

        s3_key = None
        if events:
            s3_key = self.write_to_s3(events, 'telephony', now)

            latest_ts = max(e.get('timestamp', 0) for e in events)
            if latest_ts:
                self.save_checkpoint('telephony', latest_ts + 1)
        else:
            self.save_checkpoint('telephony', int(now.timestamp()))

        return {
            'log_type': 'telephony',
            'events_fetched': len(events),
            's3_key': s3_key
        }

    def collect(self) -> Dict:
        """
        Main collection logic - collects all log types.

        Returns:
            Dictionary with collection statistics
        """
        results = {
            'authentication': None,
            'admin': None,
            'telephony': None,
            'total_events': 0
        }

        # Collect authentication logs
        try:
            auth_result = self.collect_authentication_logs()
            results['authentication'] = auth_result
            results['total_events'] += auth_result['events_fetched']
        except Exception as e:
            print(f"Error collecting auth logs: {str(e)}")
            results['authentication'] = {'error': str(e)}

        # Collect admin logs
        try:
            admin_result = self.collect_admin_logs()
            results['admin'] = admin_result
            results['total_events'] += admin_result['events_fetched']
        except Exception as e:
            print(f"Error collecting admin logs: {str(e)}")
            results['admin'] = {'error': str(e)}

        # Collect telephony logs
        try:
            tel_result = self.collect_telephony_logs()
            results['telephony'] = tel_result
            results['total_events'] += tel_result['events_fetched']
        except Exception as e:
            print(f"Error collecting telephony logs: {str(e)}")
            results['telephony'] = {'error': str(e)}

        return results


def lambda_handler(event, context):
    """
    AWS Lambda handler for Duo log collection.

    Environment Variables:
        DUO_SECRET_ID: AWS Secrets Manager secret ID containing Duo credentials
        S3_BUCKET: S3 bucket for log storage
        CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
    """
    # Get configuration from environment
    secret_id = os.environ.get('DUO_SECRET_ID', "mantissa/duo/secret/id")
    s3_bucket = os.environ['S3_BUCKET']
    checkpoint_table = os.environ.get('CHECKPOINT_TABLE', 'mantissa-log-checkpoints')

    # Retrieve credentials from Secrets Manager
    secrets_client = boto3.client('secretsmanager')
    try:
        secret_response = secrets_client.get_secret_value(SecretId=secret_id)
        secret_data = json.loads(secret_response['SecretString'])

        integration_key = secret_data['integration_key']
        secret_key = secret_data['secret_key']
        api_hostname = secret_data['api_hostname']

    except Exception as e:
        print(f"Error retrieving secret: {str(e)}")
        raise

    # Initialize collector
    collector = DuoCollector(
        integration_key=integration_key,
        secret_key=secret_key,
        api_hostname=api_hostname,
        s3_bucket=s3_bucket,
        checkpoint_table=checkpoint_table
    )

    # Check if specific log type requested
    log_type = event.get('log_type')

    try:
        if log_type == 'authentication':
            result = collector.collect_authentication_logs()
        elif log_type == 'admin':
            result = collector.collect_admin_logs()
        elif log_type == 'telephony':
            result = collector.collect_telephony_logs()
        else:
            # Collect all log types
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
