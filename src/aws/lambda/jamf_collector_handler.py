"""
Jamf Pro Log Collector

Collects Jamf Pro audit logs, computer events, mobile device events, and
webhook events via the Jamf Pro API.

Jamf Pro Data Types Collected:
- Audit Logs (admin actions, API access)
- Computer Inventory and Events
- Mobile Device Inventory and Events
- Policy Execution History
- Configuration Profile Events
- Application Inventory

Authentication:
- API Roles and Clients (OAuth 2.0 Client Credentials - recommended)
- Basic Authentication (legacy)

Reference:
- https://developer.jamf.com/jamf-pro/docs
- https://developer.jamf.com/jamf-pro/reference
"""

import json
import os
import boto3
import requests
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

from shared.parsers.jamf import JamfParser


class JamfCollector:
    """Collects Jamf Pro data via REST API"""

    # Jamf Pro API endpoints
    ENDPOINTS = {
        'audit_logs': '/api/v1/jamf-pro-server-url/audit',
        'computers': '/api/v1/computers-inventory',
        'computers_detail': '/api/v1/computers-inventory-detail',
        'mobile_devices': '/api/v2/mobile-devices',
        'mobile_device_detail': '/api/v2/mobile-devices/{id}/detail',
        'policies': '/api/v1/policies',
        'policy_logs': '/JSSResource/policies/id/{id}/history',
        'configuration_profiles': '/api/v1/configuration-profiles',
        'patch_software_title_configurations': '/api/v2/patch-software-title-configurations',
        'computer_groups': '/api/v1/computer-groups',
        'scripts': '/api/v1/scripts',
        'webhooks': '/api/v1/webhooks',
    }

    # Classic API endpoints (XML-based, legacy)
    CLASSIC_ENDPOINTS = {
        'computer_history': '/JSSResource/computerhistory/id/{id}',
        'mobile_device_history': '/JSSResource/mobiledevicehistory/id/{id}',
        'policy_history': '/JSSResource/policies/id/{id}/history',
    }

    def __init__(
        self,
        s3_bucket: str,
        output_prefix: str,
        checkpoint_table: str,
        jamf_url: str,
        client_id: str = None,
        client_secret: str = None,
        username: str = None,
        password: str = None
    ):
        """
        Initialize Jamf Pro collector.

        Args:
            s3_bucket: S3 bucket for log storage
            output_prefix: S3 prefix for output
            checkpoint_table: DynamoDB table for checkpoint tracking
            jamf_url: Jamf Pro server URL (e.g., https://yourorg.jamfcloud.com)
            client_id: API client ID (for OAuth)
            client_secret: API client secret (for OAuth)
            username: Jamf Pro username (for basic auth)
            password: Jamf Pro password (for basic auth)
        """
        self.s3_bucket = s3_bucket
        self.output_prefix = output_prefix
        self.checkpoint_table = checkpoint_table
        self.jamf_url = jamf_url.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password

        self.s3 = boto3.client('s3')
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(checkpoint_table)

        self.parser = JamfParser()
        self.access_token = None
        self.token_expires_at = None

    def authenticate(self) -> bool:
        """
        Authenticate to Jamf Pro and obtain access token.

        Returns:
            True if authentication successful
        """
        if self.client_id and self.client_secret:
            return self._authenticate_oauth()
        elif self.username and self.password:
            return self._authenticate_basic()
        else:
            print("No authentication credentials provided")
            return False

    def _authenticate_oauth(self) -> bool:
        """Authenticate using OAuth 2.0 Client Credentials flow"""
        token_url = f"{self.jamf_url}/api/oauth/token"

        payload = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }

        try:
            response = requests.post(
                token_url,
                data=payload,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            response.raise_for_status()

            data = response.json()
            self.access_token = data['access_token']
            expires_in = data.get('expires_in', 3600)
            self.token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
            print(f"Authenticated to Jamf Pro via OAuth: {self.jamf_url}")
            return True

        except requests.exceptions.RequestException as e:
            print(f"OAuth authentication failed: {str(e)}")
            return False

    def _authenticate_basic(self) -> bool:
        """Authenticate using Basic Authentication and get token"""
        token_url = f"{self.jamf_url}/api/v1/auth/token"

        try:
            response = requests.post(
                token_url,
                auth=(self.username, self.password)
            )
            response.raise_for_status()

            data = response.json()
            self.access_token = data['token']
            expires_str = data.get('expires', '')
            if expires_str:
                try:
                    self.token_expires_at = datetime.fromisoformat(
                        expires_str.replace('Z', '+00:00')
                    )
                except ValueError:
                    self.token_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
            print(f"Authenticated to Jamf Pro via Basic Auth: {self.jamf_url}")
            return True

        except requests.exceptions.RequestException as e:
            print(f"Basic authentication failed: {str(e)}")
            return False

    def _ensure_authenticated(self) -> bool:
        """Ensure we have a valid access token"""
        if not self.access_token:
            return self.authenticate()

        # Check if token is expired or about to expire
        if self.token_expires_at:
            buffer = timedelta(minutes=5)
            if datetime.now(timezone.utc) + buffer >= self.token_expires_at:
                return self.authenticate()

        return True

    def get_last_checkpoint(self, log_type: str) -> Optional[str]:
        """
        Get last processed timestamp from DynamoDB.

        Args:
            log_type: Type of log being collected

        Returns:
            Last processed timestamp or None
        """
        try:
            response = self.table.get_item(
                Key={'source': f'jamf:{log_type}'}
            )
            if 'Item' in response:
                return response['Item'].get('last_timestamp')
        except Exception as e:
            print(f"Error getting checkpoint: {str(e)}")

        return None

    def save_checkpoint(self, timestamp: str, log_type: str) -> None:
        """
        Save checkpoint to DynamoDB.

        Args:
            timestamp: Last processed timestamp
            log_type: Type of log being collected
        """
        try:
            self.table.put_item(
                Item={
                    'source': f'jamf:{log_type}',
                    'last_timestamp': timestamp,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
            )
        except Exception as e:
            print(f"Error saving checkpoint: {str(e)}")

    def _api_request(
        self,
        endpoint: str,
        params: Dict = None,
        method: str = 'GET'
    ) -> Optional[Any]:
        """Make authenticated API request to Jamf Pro"""
        if not self._ensure_authenticated():
            return None

        url = f"{self.jamf_url}{endpoint}"

        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Accept': 'application/json'
        }

        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, params=params)
            else:
                response = requests.request(method, url, headers=headers, params=params)

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"API request failed for {endpoint}: {str(e)}")
            return None

    def _paginated_request(
        self,
        endpoint: str,
        params: Dict = None,
        page_size: int = 100,
        max_pages: int = 100
    ) -> List[Dict]:
        """Make paginated API request"""
        all_results = []
        page = 0

        if params is None:
            params = {}

        while page < max_pages:
            params['page'] = page
            params['page-size'] = page_size

            result = self._api_request(endpoint, params)

            if not result:
                break

            # Handle different result formats
            if isinstance(result, dict):
                if 'results' in result:
                    results = result['results']
                elif 'computers' in result:
                    results = result['computers']
                elif 'mobileDevices' in result:
                    results = result['mobileDevices']
                elif 'totalCount' in result and 'results' in result:
                    results = result['results']
                else:
                    results = [result]
            elif isinstance(result, list):
                results = result
            else:
                break

            if not results:
                break

            all_results.extend(results)

            # Check if we've retrieved all results
            if len(results) < page_size:
                break

            page += 1

        return all_results

    def query_audit_logs(
        self,
        start_date: str = None,
        end_date: str = None,
        page_size: int = 100
    ) -> List[Dict]:
        """
        Query Jamf Pro audit logs.

        Args:
            start_date: Start datetime (ISO format)
            end_date: End datetime (ISO format)
            page_size: Number of records per page

        Returns:
            List of audit log entries
        """
        endpoint = '/api/v1/jamf-pro-server-url/audit'

        params = {
            'page-size': page_size,
            'sort': 'dateTime:desc'
        }

        # Jamf Pro API uses filter syntax
        filters = []
        if start_date:
            filters.append(f'dateTime>={start_date}')
        if end_date:
            filters.append(f'dateTime<={end_date}')

        if filters:
            params['filter'] = ' and '.join(filters)

        return self._paginated_request(endpoint, params, page_size)

    def query_computers(
        self,
        section: str = 'GENERAL',
        page_size: int = 100
    ) -> List[Dict]:
        """
        Query computer inventory.

        Args:
            section: Inventory section to retrieve (GENERAL, HARDWARE, etc.)
            page_size: Number of records per page

        Returns:
            List of computer records
        """
        endpoint = self.ENDPOINTS['computers']

        params = {
            'section': section,
            'page-size': page_size,
            'sort': 'general.lastContactTime:desc'
        }

        return self._paginated_request(endpoint, params, page_size)

    def query_computers_detail(
        self,
        section: str = 'GENERAL',
        page_size: int = 50
    ) -> List[Dict]:
        """
        Query detailed computer inventory.

        Args:
            section: Inventory section to retrieve
            page_size: Number of records per page

        Returns:
            List of detailed computer records
        """
        endpoint = self.ENDPOINTS['computers_detail']

        params = {
            'section': section,
            'page-size': page_size,
            'sort': 'general.lastContactTime:desc'
        }

        return self._paginated_request(endpoint, params, page_size)

    def query_mobile_devices(self, page_size: int = 100) -> List[Dict]:
        """
        Query mobile device inventory.

        Args:
            page_size: Number of records per page

        Returns:
            List of mobile device records
        """
        endpoint = self.ENDPOINTS['mobile_devices']

        params = {
            'page-size': page_size,
            'sort': 'lastInventoryUpdateDate:desc'
        }

        return self._paginated_request(endpoint, params, page_size)

    def query_policies(self, page_size: int = 100) -> List[Dict]:
        """
        Query policies.

        Args:
            page_size: Number of records per page

        Returns:
            List of policy records
        """
        endpoint = self.ENDPOINTS['policies']

        params = {
            'page-size': page_size
        }

        return self._paginated_request(endpoint, params, page_size)

    def query_configuration_profiles(self, page_size: int = 100) -> List[Dict]:
        """
        Query configuration profiles.

        Args:
            page_size: Number of records per page

        Returns:
            List of configuration profile records
        """
        endpoint = self.ENDPOINTS['configuration_profiles']

        params = {
            'page-size': page_size
        }

        return self._paginated_request(endpoint, params, page_size)

    def process_events(self, events: List[Dict[str, Any]], event_type: str) -> List[Dict[str, Any]]:
        """
        Parse and normalize Jamf Pro events.

        Args:
            events: Raw Jamf Pro events
            event_type: Type of events being processed

        Returns:
            Normalized events
        """
        normalized = []

        for event in events:
            # Add event type context
            event['eventType'] = event_type

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
            event_type: Jamf event type
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

    def collect_audit_logs(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Collect Jamf Pro audit logs.

        Args:
            hours_back: Hours of history to collect

        Returns:
            Collection statistics
        """
        # Calculate start time
        start_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)

        # Get last checkpoint
        last_time = self.get_last_checkpoint('audit_logs')
        if last_time:
            try:
                checkpoint_time = datetime.fromisoformat(last_time.replace('Z', '+00:00'))
                if checkpoint_time > start_time:
                    start_time = checkpoint_time
            except ValueError:
                pass

        start_date = start_time.isoformat()

        # Query audit logs
        records = self.query_audit_logs(start_date=start_date)
        print(f"Found {len(records)} audit log records")

        if not records:
            return {
                'log_type': 'audit_logs',
                'events_collected': 0,
                'events_normalized': 0
            }

        # Normalize events
        normalized = self.process_events(records, 'AuditLogEntry')

        # Write to S3
        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, 'audit', now)

            # Update checkpoint with latest timestamp
            latest_time = records[0].get('dateTime', records[0].get('date_time', ''))
            if latest_time:
                self.save_checkpoint(latest_time, 'audit_logs')

        return {
            'log_type': 'audit_logs',
            'events_collected': len(records),
            'events_normalized': len(normalized),
            'output_key': output_key
        }

    def collect_computer_inventory(self, modified_since_hours: int = 24) -> Dict[str, Any]:
        """
        Collect computer inventory for recently modified devices.

        Args:
            modified_since_hours: Only collect devices modified in this window

        Returns:
            Collection statistics
        """
        # Query computers with general section
        records = self.query_computers(section='GENERAL')
        print(f"Found {len(records)} computer records")

        if not records:
            return {
                'log_type': 'computers',
                'events_collected': 0,
                'events_normalized': 0
            }

        # Filter to recently modified
        cutoff = datetime.now(timezone.utc) - timedelta(hours=modified_since_hours)
        recent_records = []

        for record in records:
            general = record.get('general', {})
            last_contact = general.get('lastContactTime', general.get('last_contact_time', ''))
            if last_contact:
                try:
                    contact_time = datetime.fromisoformat(last_contact.replace('Z', '+00:00'))
                    if contact_time >= cutoff:
                        recent_records.append(record)
                except ValueError:
                    recent_records.append(record)
            else:
                recent_records.append(record)

        print(f"Filtered to {len(recent_records)} recently modified computers")

        # Normalize events
        normalized = self.process_events(recent_records, 'ComputerCheckIn')

        # Write to S3
        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, 'computers', now)

            # Update checkpoint
            self.save_checkpoint(now.isoformat(), 'computers')

        return {
            'log_type': 'computers',
            'events_collected': len(recent_records),
            'events_normalized': len(normalized),
            'output_key': output_key
        }

    def collect_mobile_devices(self, modified_since_hours: int = 24) -> Dict[str, Any]:
        """
        Collect mobile device inventory for recently modified devices.

        Args:
            modified_since_hours: Only collect devices modified in this window

        Returns:
            Collection statistics
        """
        # Query mobile devices
        records = self.query_mobile_devices()
        print(f"Found {len(records)} mobile device records")

        if not records:
            return {
                'log_type': 'mobile_devices',
                'events_collected': 0,
                'events_normalized': 0
            }

        # Filter to recently modified
        cutoff = datetime.now(timezone.utc) - timedelta(hours=modified_since_hours)
        recent_records = []

        for record in records:
            last_update = record.get('lastInventoryUpdateDate', '')
            if last_update:
                try:
                    update_time = datetime.fromisoformat(last_update.replace('Z', '+00:00'))
                    if update_time >= cutoff:
                        recent_records.append(record)
                except ValueError:
                    recent_records.append(record)
            else:
                recent_records.append(record)

        print(f"Filtered to {len(recent_records)} recently modified mobile devices")

        # Normalize events
        normalized = self.process_events(recent_records, 'MobileDeviceCheckIn')

        # Write to S3
        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, 'mobile_devices', now)

            # Update checkpoint
            self.save_checkpoint(now.isoformat(), 'mobile_devices')

        return {
            'log_type': 'mobile_devices',
            'events_collected': len(recent_records),
            'events_normalized': len(normalized),
            'output_key': output_key
        }

    def collect_security_state(self) -> Dict[str, Any]:
        """
        Collect security state for all managed computers.

        Returns:
            Collection statistics
        """
        # Query computers with security section
        records = self.query_computers_detail(section='SECURITY')
        print(f"Found {len(records)} computer security records")

        if not records:
            return {
                'log_type': 'security',
                'events_collected': 0,
                'events_normalized': 0
            }

        # Generate security state events for each computer
        security_events = []
        for record in records:
            security = record.get('security', {})
            general = record.get('general', {})

            # Check FileVault status
            if security.get('filevaultEnabled') is not None:
                event = {
                    **record,
                    'eventType': 'FileVaultEnabled' if security.get('filevaultEnabled') else 'FileVaultDisabled'
                }
                security_events.append(event)

            # Check Firewall status
            if security.get('firewallEnabled') is not None:
                event = {
                    **record,
                    'eventType': 'FirewallEnabled' if security.get('firewallEnabled') else 'FirewallDisabled'
                }
                security_events.append(event)

            # Check Gatekeeper status
            if security.get('gatekeeperStatus'):
                event = {
                    **record,
                    'eventType': 'GatekeeperStatus'
                }
                security_events.append(event)

        # Normalize events
        normalized = self.process_events(security_events, 'SecurityState')

        # Write to S3
        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, 'security', now)

            # Update checkpoint
            self.save_checkpoint(now.isoformat(), 'security')

        return {
            'log_type': 'security',
            'events_collected': len(security_events),
            'events_normalized': len(normalized),
            'output_key': output_key
        }


def lambda_handler(event, context):
    """
    AWS Lambda handler for Jamf Pro log collection.

    Supports multiple collection modes:
    1. audit_logs: Collect audit logs (default)
    2. computers: Collect computer inventory
    3. mobile_devices: Collect mobile device inventory
    4. security: Collect security state
    5. all: Collect all log types

    Environment Variables:
        S3_BUCKET: S3 bucket for log storage
        OUTPUT_PREFIX: S3 prefix for output
        CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
        JAMF_URL: Jamf Pro server URL
        JAMF_CLIENT_ID: API client ID (for OAuth)
        JAMF_CLIENT_SECRET: API client secret (for OAuth)
        JAMF_USERNAME: Jamf Pro username (for basic auth)
        JAMF_PASSWORD: Jamf Pro password (for basic auth)
    """
    # Get configuration from environment
    s3_bucket = os.environ.get('S3_BUCKET', 'mantissa-log-data')
    output_prefix = os.environ.get('OUTPUT_PREFIX', 'jamf')
    checkpoint_table = os.environ.get('CHECKPOINT_TABLE', 'mantissa-log-checkpoints')

    # Jamf Pro configuration
    jamf_url = os.environ.get('JAMF_URL', '')
    client_id = os.environ.get('JAMF_CLIENT_ID', '')
    client_secret = os.environ.get('JAMF_CLIENT_SECRET', '')
    username = os.environ.get('JAMF_USERNAME', '')
    password = os.environ.get('JAMF_PASSWORD', '')

    # Validate configuration
    if not jamf_url:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': 'Missing JAMF_URL configuration'
            })
        }

    if not (client_id and client_secret) and not (username and password):
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': 'Missing Jamf Pro authentication credentials'
            })
        }

    # Initialize collector
    collector = JamfCollector(
        s3_bucket=s3_bucket,
        output_prefix=output_prefix,
        checkpoint_table=checkpoint_table,
        jamf_url=jamf_url,
        client_id=client_id,
        client_secret=client_secret,
        username=username,
        password=password
    )

    try:
        # Authenticate
        if not collector.authenticate():
            return {
                'statusCode': 401,
                'body': json.dumps({'error': 'Authentication failed'})
            }

        # Determine collection mode
        mode = event.get('mode', 'audit_logs')
        hours_back = event.get('hours_back', 24)
        results = {}

        if mode == 'audit_logs' or mode == 'all':
            results['audit_logs'] = collector.collect_audit_logs(hours_back)

        if mode == 'computers' or mode == 'all':
            results['computers'] = collector.collect_computer_inventory(hours_back)

        if mode == 'mobile_devices' or mode == 'all':
            results['mobile_devices'] = collector.collect_mobile_devices(hours_back)

        if mode == 'security' or mode == 'all':
            results['security'] = collector.collect_security_state()

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
