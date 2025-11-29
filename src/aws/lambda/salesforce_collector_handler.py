"""
Salesforce Event Log Collector

Collects Salesforce EventLogFile data via the Salesforce REST API.
Supports both hourly and daily log files with ECS normalization.

Salesforce Log Types Collected:
- Login History (LoginEvent)
- Logout History
- API Event Logs
- Report Export logs
- Setup Audit Trail
- Apex Execution logs
- Lightning logs
- And many more EventLogFile types

Authentication:
- OAuth 2.0 JWT Bearer Flow (recommended for server-to-server)
- OAuth 2.0 Username-Password Flow (legacy)

Reference:
- https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/event_log_file_hourly_overview.htm
"""

import json
import os
import gzip
import csv
import io
import boto3
import requests
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

from shared.parsers.salesforce import SalesforceParser


class SalesforceCollector:
    """Collects Salesforce EventLogFile data via REST API"""

    def __init__(
        self,
        s3_bucket: str,
        output_prefix: str,
        checkpoint_table: str,
        instance_url: str,
        client_id: str,
        client_secret: str,
        username: str = None,
        password: str = None,
        security_token: str = None,
        private_key: str = None,
        api_version: str = "v59.0"
    ):
        """
        Initialize Salesforce collector.

        Args:
            s3_bucket: S3 bucket for log storage
            output_prefix: S3 prefix for output
            checkpoint_table: DynamoDB table for checkpoint tracking
            instance_url: Salesforce instance URL (e.g., https://yourorg.my.salesforce.com)
            client_id: OAuth Connected App client ID
            client_secret: OAuth Connected App client secret
            username: Salesforce username (for password flow)
            password: Salesforce password (for password flow)
            security_token: Salesforce security token (for password flow)
            private_key: Private key for JWT bearer flow
            api_version: Salesforce API version
        """
        self.s3_bucket = s3_bucket
        self.output_prefix = output_prefix
        self.checkpoint_table = checkpoint_table
        self.instance_url = instance_url.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.security_token = security_token
        self.private_key = private_key
        self.api_version = api_version

        self.s3 = boto3.client('s3')
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(checkpoint_table)

        self.parser = SalesforceParser()
        self.access_token = None
        self.token_instance_url = None

    def authenticate(self) -> bool:
        """
        Authenticate to Salesforce and obtain access token.

        Returns:
            True if authentication successful
        """
        if self.private_key:
            return self._authenticate_jwt()
        else:
            return self._authenticate_password()

    def _authenticate_password(self) -> bool:
        """Authenticate using OAuth 2.0 Username-Password flow"""
        token_url = f"{self.instance_url}/services/oauth2/token"

        payload = {
            'grant_type': 'password',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'username': self.username,
            'password': f"{self.password}{self.security_token or ''}"
        }

        try:
            response = requests.post(token_url, data=payload)
            response.raise_for_status()

            data = response.json()
            self.access_token = data['access_token']
            self.token_instance_url = data['instance_url']
            print(f"Authenticated to Salesforce: {self.token_instance_url}")
            return True

        except requests.exceptions.RequestException as e:
            print(f"Authentication failed: {str(e)}")
            return False

    def _authenticate_jwt(self) -> bool:
        """Authenticate using OAuth 2.0 JWT Bearer flow"""
        import jwt
        from datetime import datetime

        token_url = f"{self.instance_url}/services/oauth2/token"

        # Create JWT claim
        now = datetime.utcnow()
        claim = {
            'iss': self.client_id,
            'sub': self.username,
            'aud': self.instance_url,
            'exp': int((now + timedelta(minutes=5)).timestamp())
        }

        # Sign JWT with private key
        try:
            encoded_jwt = jwt.encode(claim, self.private_key, algorithm='RS256')

            payload = {
                'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion': encoded_jwt
            }

            response = requests.post(token_url, data=payload)
            response.raise_for_status()

            data = response.json()
            self.access_token = data['access_token']
            self.token_instance_url = data['instance_url']
            print(f"Authenticated to Salesforce via JWT: {self.token_instance_url}")
            return True

        except Exception as e:
            print(f"JWT authentication failed: {str(e)}")
            return False

    def get_last_checkpoint(self, log_type: str = 'EventLogFile') -> Optional[str]:
        """
        Get last processed log date from DynamoDB.

        Args:
            log_type: Type of log being collected

        Returns:
            Last processed date string or None
        """
        try:
            response = self.table.get_item(
                Key={'source': f'salesforce:{log_type}'}
            )
            if 'Item' in response:
                return response['Item'].get('last_log_date')
        except Exception as e:
            print(f"Error getting checkpoint: {str(e)}")

        return None

    def save_checkpoint(self, log_date: str, log_type: str = 'EventLogFile') -> None:
        """
        Save checkpoint to DynamoDB.

        Args:
            log_date: Last processed log date
            log_type: Type of log being collected
        """
        try:
            self.table.put_item(
                Item={
                    'source': f'salesforce:{log_type}',
                    'last_log_date': log_date,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
            )
        except Exception as e:
            print(f"Error saving checkpoint: {str(e)}")

    def _api_request(self, endpoint: str, params: Dict = None) -> Optional[Dict]:
        """Make authenticated API request to Salesforce"""
        if not self.access_token:
            if not self.authenticate():
                return None

        base_url = self.token_instance_url or self.instance_url
        url = f"{base_url}/services/data/{self.api_version}/{endpoint}"

        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"API request failed: {str(e)}")
            return None

    def _download_log_file(self, log_file_url: str) -> Optional[str]:
        """Download EventLogFile content"""
        if not self.access_token:
            if not self.authenticate():
                return None

        base_url = self.token_instance_url or self.instance_url
        url = f"{base_url}{log_file_url}"

        headers = {
            'Authorization': f'Bearer {self.access_token}'
        }

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"Failed to download log file: {str(e)}")
            return None

    def query_event_log_files(
        self,
        start_date: str = None,
        end_date: str = None,
        event_types: List[str] = None,
        log_date_only: bool = True
    ) -> List[Dict]:
        """
        Query available EventLogFile records.

        Args:
            start_date: Start date (YYYY-MM-DD)
            end_date: End date (YYYY-MM-DD)
            event_types: List of event types to filter
            log_date_only: If True, query by LogDate; if False, query by CreatedDate

        Returns:
            List of EventLogFile records
        """
        # Build SOQL query
        fields = "Id, EventType, LogDate, LogFileLength, LogFile, Sequence, Interval"
        query = f"SELECT {fields} FROM EventLogFile"

        conditions = []

        if start_date:
            date_field = 'LogDate' if log_date_only else 'CreatedDate'
            conditions.append(f"{date_field} >= {start_date}")

        if end_date:
            date_field = 'LogDate' if log_date_only else 'CreatedDate'
            conditions.append(f"{date_field} <= {end_date}")

        if event_types:
            types_str = ", ".join([f"'{t}'" for t in event_types])
            conditions.append(f"EventType IN ({types_str})")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY LogDate DESC, EventType ASC"

        # Execute query
        result = self._api_request('query', params={'q': query})

        if result and 'records' in result:
            return result['records']

        return []

    def query_login_history(
        self,
        start_date: str = None,
        end_date: str = None,
        limit: int = 2000
    ) -> List[Dict]:
        """
        Query Login History records.

        Args:
            start_date: Start datetime (ISO format)
            end_date: End datetime (ISO format)
            limit: Maximum records to return

        Returns:
            List of LoginHistory records
        """
        fields = (
            "Id, UserId, LoginTime, LoginType, SourceIp, Status, "
            "Application, Browser, Platform, CountryIso, LoginUrl, "
            "AuthenticationServiceId, TlsProtocol, CipherSuite"
        )
        query = f"SELECT {fields} FROM LoginHistory"

        conditions = []

        if start_date:
            conditions.append(f"LoginTime >= {start_date}")

        if end_date:
            conditions.append(f"LoginTime <= {end_date}")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += f" ORDER BY LoginTime DESC LIMIT {limit}"

        result = self._api_request('query', params={'q': query})

        if result and 'records' in result:
            return result['records']

        return []

    def query_setup_audit_trail(
        self,
        start_date: str = None,
        end_date: str = None,
        limit: int = 2000
    ) -> List[Dict]:
        """
        Query Setup Audit Trail records.

        Args:
            start_date: Start datetime (ISO format)
            end_date: End datetime (ISO format)
            limit: Maximum records to return

        Returns:
            List of SetupAuditTrail records
        """
        fields = (
            "Id, Action, CreatedById, CreatedDate, DelegateUser, "
            "Display, ResponsibleNamespacePrefix, Section"
        )
        query = f"SELECT {fields} FROM SetupAuditTrail"

        conditions = []

        if start_date:
            conditions.append(f"CreatedDate >= {start_date}")

        if end_date:
            conditions.append(f"CreatedDate <= {end_date}")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += f" ORDER BY CreatedDate DESC LIMIT {limit}"

        result = self._api_request('query', params={'q': query})

        if result and 'records' in result:
            return result['records']

        return []

    def parse_csv_log_file(self, csv_content: str) -> List[Dict]:
        """Parse CSV EventLogFile content into list of events"""
        events = []

        try:
            reader = csv.DictReader(io.StringIO(csv_content))
            for row in reader:
                events.append(dict(row))
        except Exception as e:
            print(f"Error parsing CSV: {str(e)}")

        return events

    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse and normalize Salesforce events.

        Args:
            events: Raw Salesforce events

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
            event_type: Salesforce event type
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
            f"{self.output_prefix}/normalized/{event_type.lower()}/"
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

    def collect_event_log_files(
        self,
        start_date: str = None,
        event_types: List[str] = None
    ) -> Dict[str, Any]:
        """
        Collect and process EventLogFile records.

        Args:
            start_date: Start date for collection (YYYY-MM-DD)
            event_types: List of event types to collect

        Returns:
            Collection statistics
        """
        # Get last checkpoint if no start date provided
        if not start_date:
            last_date = self.get_last_checkpoint('EventLogFile')
            if last_date:
                # Start from day after last checkpoint
                start_dt = datetime.strptime(last_date, '%Y-%m-%d') + timedelta(days=1)
                start_date = start_dt.strftime('%Y-%m-%d')
            else:
                # Default to 7 days ago
                start_date = (datetime.now(timezone.utc) - timedelta(days=7)).strftime('%Y-%m-%d')

        # Query available log files
        log_files = self.query_event_log_files(
            start_date=start_date,
            event_types=event_types
        )

        print(f"Found {len(log_files)} EventLogFile records")

        total_events = 0
        total_normalized = 0
        processed_files = []
        latest_log_date = None

        for log_file in log_files:
            event_type = log_file.get('EventType', 'Unknown')
            log_date = log_file.get('LogDate', '')
            log_file_url = log_file.get('LogFile', '')

            if not log_file_url:
                continue

            # Download log file
            csv_content = self._download_log_file(log_file_url)
            if not csv_content:
                continue

            # Parse CSV content
            events = self.parse_csv_log_file(csv_content)
            total_events += len(events)

            # Add EventType to each event
            for event in events:
                event['EventType'] = event_type

            # Normalize events
            normalized = self.process_events(events)
            total_normalized += len(normalized)

            # Write to S3
            if normalized:
                now = datetime.now(timezone.utc)
                output_key = self.write_normalized_events(normalized, event_type, now)
                processed_files.append({
                    'event_type': event_type,
                    'log_date': log_date,
                    'events_read': len(events),
                    'events_normalized': len(normalized),
                    'output_key': output_key
                })

            # Track latest log date
            if log_date and (not latest_log_date or log_date > latest_log_date):
                latest_log_date = log_date

        # Update checkpoint
        if latest_log_date:
            self.save_checkpoint(latest_log_date.split('T')[0], 'EventLogFile')

        return {
            'mode': 'event_log_files',
            'start_date': start_date,
            'files_processed': len(processed_files),
            'total_events': total_events,
            'total_normalized': total_normalized,
            'latest_log_date': latest_log_date,
            'files': processed_files
        }

    def collect_login_history(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Collect Login History records.

        Args:
            hours_back: Hours of history to collect

        Returns:
            Collection statistics
        """
        start_time = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()

        # Get last checkpoint
        last_time = self.get_last_checkpoint('LoginHistory')
        if last_time:
            start_time = last_time

        # Query login history
        records = self.query_login_history(start_date=start_time)
        print(f"Found {len(records)} LoginHistory records")

        if not records:
            return {
                'mode': 'login_history',
                'events_collected': 0,
                'events_normalized': 0
            }

        # Normalize events
        normalized = self.process_events(records)

        # Write to S3
        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, 'LoginHistory', now)

            # Update checkpoint with latest login time
            latest_time = records[0].get('LoginTime', '')
            if latest_time:
                self.save_checkpoint(latest_time, 'LoginHistory')

        return {
            'mode': 'login_history',
            'events_collected': len(records),
            'events_normalized': len(normalized),
            'output_key': output_key
        }

    def collect_setup_audit_trail(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Collect Setup Audit Trail records.

        Args:
            hours_back: Hours of history to collect

        Returns:
            Collection statistics
        """
        start_time = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()

        # Get last checkpoint
        last_time = self.get_last_checkpoint('SetupAuditTrail')
        if last_time:
            start_time = last_time

        # Query audit trail
        records = self.query_setup_audit_trail(start_date=start_time)
        print(f"Found {len(records)} SetupAuditTrail records")

        if not records:
            return {
                'mode': 'setup_audit_trail',
                'events_collected': 0,
                'events_normalized': 0
            }

        # Normalize events
        normalized = self.process_events(records)

        # Write to S3
        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, 'SetupAuditTrail', now)

            # Update checkpoint with latest created date
            latest_time = records[0].get('CreatedDate', '')
            if latest_time:
                self.save_checkpoint(latest_time, 'SetupAuditTrail')

        return {
            'mode': 'setup_audit_trail',
            'events_collected': len(records),
            'events_normalized': len(normalized),
            'output_key': output_key
        }


def lambda_handler(event, context):
    """
    AWS Lambda handler for Salesforce log collection.

    Supports multiple collection modes:
    1. event_log_files: Collect EventLogFile data (default)
    2. login_history: Collect Login History
    3. setup_audit_trail: Collect Setup Audit Trail
    4. all: Collect all log types

    Environment Variables:
        S3_BUCKET: S3 bucket for log storage
        OUTPUT_PREFIX: S3 prefix for output
        CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
        SALESFORCE_INSTANCE_URL: Salesforce instance URL
        SALESFORCE_CLIENT_ID: OAuth client ID
        SALESFORCE_CLIENT_SECRET: OAuth client secret
        SALESFORCE_USERNAME: Salesforce username
        SALESFORCE_PASSWORD: Salesforce password
        SALESFORCE_SECURITY_TOKEN: Salesforce security token
        SALESFORCE_API_VERSION: API version (default: v59.0)
    """
    # Get configuration from environment
    s3_bucket = os.environ.get('S3_BUCKET', 'mantissa-log-data')
    output_prefix = os.environ.get('OUTPUT_PREFIX', 'salesforce')
    checkpoint_table = os.environ.get('CHECKPOINT_TABLE', 'mantissa-log-checkpoints')

    # Salesforce configuration
    instance_url = os.environ.get('SALESFORCE_INSTANCE_URL', '')
    client_id = os.environ.get('SALESFORCE_CLIENT_ID', '')
    client_secret = os.environ.get('SALESFORCE_CLIENT_SECRET', '')
    username = os.environ.get('SALESFORCE_USERNAME', '')
    password = os.environ.get('SALESFORCE_PASSWORD', '')
    security_token = os.environ.get('SALESFORCE_SECURITY_TOKEN', '')
    api_version = os.environ.get('SALESFORCE_API_VERSION', 'v59.0')

    # Validate configuration
    if not all([instance_url, client_id, client_secret, username, password]):
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': 'Missing required Salesforce configuration'
            })
        }

    # Initialize collector
    collector = SalesforceCollector(
        s3_bucket=s3_bucket,
        output_prefix=output_prefix,
        checkpoint_table=checkpoint_table,
        instance_url=instance_url,
        client_id=client_id,
        client_secret=client_secret,
        username=username,
        password=password,
        security_token=security_token,
        api_version=api_version
    )

    try:
        # Authenticate
        if not collector.authenticate():
            return {
                'statusCode': 401,
                'body': json.dumps({'error': 'Authentication failed'})
            }

        # Determine collection mode
        mode = event.get('mode', 'event_log_files')
        results = {}

        if mode == 'event_log_files' or mode == 'all':
            event_types = event.get('event_types')
            start_date = event.get('start_date')
            results['event_log_files'] = collector.collect_event_log_files(
                start_date=start_date,
                event_types=event_types
            )

        if mode == 'login_history' or mode == 'all':
            hours_back = event.get('hours_back', 24)
            results['login_history'] = collector.collect_login_history(hours_back)

        if mode == 'setup_audit_trail' or mode == 'all':
            hours_back = event.get('hours_back', 24)
            results['setup_audit_trail'] = collector.collect_setup_audit_trail(hours_back)

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
