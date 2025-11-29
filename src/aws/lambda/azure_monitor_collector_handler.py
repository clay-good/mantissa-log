"""
Azure Monitor Logs Collector

Collects Azure Monitor logs via Azure Event Hub export to S3 or direct API.

Supports Azure log types:
- Activity Logs (Azure Resource Manager operations)
- Azure AD Sign-in Logs (authentication events)
- Azure AD Audit Logs (directory changes)
- Security Center Alerts
- Resource Logs (diagnostic logs)
- NSG Flow Logs

Data Flow:
1. Azure Monitor -> Event Hub -> Event Hub Capture -> S3 (preferred)
2. Azure Monitor -> Azure Storage -> S3 sync
3. Azure Log Analytics API (for historical data)

Authentication:
- Azure AD Service Principal (Client ID/Secret)
- Azure Managed Identity (when running in Azure)

Reference:
- https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/stream-monitoring-data-event-hubs
- https://docs.microsoft.com/en-us/azure/azure-monitor/logs/api/overview
"""

import json
import os
import boto3
import requests
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urlencode

from shared.parsers.azure_monitor import AzureMonitorParser


class AzureMonitorCollector:
    """Collects Azure Monitor logs via Azure APIs"""

    # Azure Management API endpoints
    AZURE_MANAGEMENT_URL = "https://management.azure.com"
    AZURE_LOGIN_URL = "https://login.microsoftonline.com"
    AZURE_LOG_ANALYTICS_URL = "https://api.loganalytics.io"

    # Log types available for collection
    LOG_TYPES = {
        'activity_logs': '/providers/Microsoft.Insights/eventtypes/management/values',
        'signin_logs': '/auditLogs/signIns',
        'audit_logs': '/auditLogs/directoryAudits',
        'security_alerts': '/providers/Microsoft.Security/alerts',
    }

    # Microsoft Graph API for Azure AD logs
    GRAPH_API_URL = "https://graph.microsoft.com/v1.0"
    GRAPH_BETA_URL = "https://graph.microsoft.com/beta"

    def __init__(
        self,
        s3_bucket: str,
        output_prefix: str,
        checkpoint_table: str,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscription_id: str = None,
        workspace_id: str = None,
        log_types: List[str] = None
    ):
        """
        Initialize Azure Monitor collector.

        Args:
            s3_bucket: S3 bucket for log storage
            output_prefix: S3 prefix for output
            checkpoint_table: DynamoDB table for checkpoint tracking
            tenant_id: Azure AD tenant ID
            client_id: Azure AD application (client) ID
            client_secret: Azure AD client secret
            subscription_id: Azure subscription ID (for activity logs)
            workspace_id: Log Analytics workspace ID (optional)
            log_types: List of log types to collect
        """
        self.s3_bucket = s3_bucket
        self.output_prefix = output_prefix
        self.checkpoint_table = checkpoint_table
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.subscription_id = subscription_id
        self.workspace_id = workspace_id
        self.log_types = log_types or ['activity_logs', 'signin_logs', 'audit_logs']

        self.s3 = boto3.client('s3')
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(checkpoint_table)

        self.parser = AzureMonitorParser()

        # Token cache
        self._management_token = None
        self._graph_token = None
        self._token_expiry = None

    def _get_access_token(self, resource: str) -> str:
        """
        Get Azure AD access token for specified resource.

        Args:
            resource: Azure resource URL (e.g., management.azure.com)

        Returns:
            Access token string
        """
        url = f"{self.AZURE_LOGIN_URL}/{self.tenant_id}/oauth2/v2.0/token"

        # Determine scope based on resource
        if 'graph.microsoft.com' in resource:
            scope = 'https://graph.microsoft.com/.default'
        elif 'management.azure.com' in resource:
            scope = 'https://management.azure.com/.default'
        elif 'api.loganalytics.io' in resource:
            scope = 'https://api.loganalytics.io/.default'
        else:
            scope = f'{resource}/.default'

        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': scope,
            'grant_type': 'client_credentials'
        }

        try:
            response = requests.post(url, data=data)
            response.raise_for_status()
            result = response.json()
            return result.get('access_token')

        except requests.exceptions.RequestException as e:
            print(f"Failed to get access token: {str(e)}")
            raise

    def _get_management_token(self) -> str:
        """Get Azure Management API token (cached)"""
        if self._management_token and self._token_expiry and datetime.now(timezone.utc) < self._token_expiry:
            return self._management_token

        self._management_token = self._get_access_token(self.AZURE_MANAGEMENT_URL)
        self._token_expiry = datetime.now(timezone.utc) + timedelta(minutes=50)
        return self._management_token

    def _get_graph_token(self) -> str:
        """Get Microsoft Graph API token (cached)"""
        if self._graph_token and self._token_expiry and datetime.now(timezone.utc) < self._token_expiry:
            return self._graph_token

        self._graph_token = self._get_access_token(self.GRAPH_API_URL)
        return self._graph_token

    def get_last_checkpoint(self, log_type: str) -> Optional[Dict[str, Any]]:
        """
        Get last processed timestamp/skip token from DynamoDB.

        Args:
            log_type: Type of logs being collected

        Returns:
            Checkpoint data or None
        """
        try:
            response = self.table.get_item(
                Key={'source': f'azure_monitor:{log_type}'}
            )
            if 'Item' in response:
                return {
                    'timestamp': response['Item'].get('timestamp'),
                    'skip_token': response['Item'].get('skip_token')
                }
        except Exception as e:
            print(f"Error getting checkpoint: {str(e)}")

        return None

    def save_checkpoint(
        self,
        log_type: str,
        timestamp: str = None,
        skip_token: str = None
    ) -> None:
        """
        Save checkpoint to DynamoDB.

        Args:
            log_type: Type of logs being collected
            timestamp: Last processed timestamp
            skip_token: Pagination token for next page
        """
        try:
            item = {
                'source': f'azure_monitor:{log_type}',
                'updated_at': datetime.now(timezone.utc).isoformat()
            }
            if timestamp:
                item['timestamp'] = timestamp
            if skip_token:
                item['skip_token'] = skip_token

            self.table.put_item(Item=item)
        except Exception as e:
            print(f"Error saving checkpoint: {str(e)}")

    def _api_request(
        self,
        url: str,
        token: str,
        params: Dict[str, str] = None
    ) -> Optional[Dict]:
        """Make authenticated API request"""
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"API request failed for {url}: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response: {e.response.text}")
            return None

    def query_activity_logs(
        self,
        start_time: str,
        end_time: str = None,
        skip_token: str = None
    ) -> Optional[Dict]:
        """
        Query Azure Activity Logs.

        Args:
            start_time: Start time for events (ISO 8601)
            end_time: End time for events (ISO 8601)
            skip_token: Pagination token

        Returns:
            API response with events
        """
        if not self.subscription_id:
            print("Subscription ID required for activity logs")
            return None

        if not end_time:
            end_time = datetime.now(timezone.utc).isoformat()

        token = self._get_management_token()

        # Build filter
        filter_str = f"eventTimestamp ge '{start_time}' and eventTimestamp le '{end_time}'"

        url = (
            f"{self.AZURE_MANAGEMENT_URL}/subscriptions/{self.subscription_id}"
            f"/providers/Microsoft.Insights/eventtypes/management/values"
        )

        params = {
            'api-version': '2015-04-01',
            '$filter': filter_str
        }

        if skip_token:
            params['$skiptoken'] = skip_token

        return self._api_request(url, token, params)

    def query_signin_logs(
        self,
        start_time: str,
        end_time: str = None,
        skip_token: str = None,
        top: int = 1000
    ) -> Optional[Dict]:
        """
        Query Azure AD Sign-in Logs via Microsoft Graph.

        Args:
            start_time: Start time for events (ISO 8601)
            end_time: End time for events (ISO 8601)
            skip_token: Pagination token (nextLink)
            top: Maximum events per page

        Returns:
            API response with events
        """
        if not end_time:
            end_time = datetime.now(timezone.utc).isoformat()

        token = self._get_graph_token()

        # If we have a skip_token (nextLink), use it directly
        if skip_token and skip_token.startswith('http'):
            return self._api_request(skip_token, token)

        # Build filter - Graph API uses different date format
        # Convert ISO to Graph API format
        start_dt = start_time.replace('+00:00', 'Z') if '+00:00' in start_time else start_time
        end_dt = end_time.replace('+00:00', 'Z') if '+00:00' in end_time else end_time

        filter_str = f"createdDateTime ge {start_dt} and createdDateTime le {end_dt}"

        url = f"{self.GRAPH_BETA_URL}/auditLogs/signIns"

        params = {
            '$filter': filter_str,
            '$top': str(top),
            '$orderby': 'createdDateTime asc'
        }

        return self._api_request(url, token, params)

    def query_audit_logs(
        self,
        start_time: str,
        end_time: str = None,
        skip_token: str = None,
        top: int = 1000
    ) -> Optional[Dict]:
        """
        Query Azure AD Audit Logs via Microsoft Graph.

        Args:
            start_time: Start time for events (ISO 8601)
            end_time: End time for events (ISO 8601)
            skip_token: Pagination token (nextLink)
            top: Maximum events per page

        Returns:
            API response with events
        """
        if not end_time:
            end_time = datetime.now(timezone.utc).isoformat()

        token = self._get_graph_token()

        # If we have a skip_token (nextLink), use it directly
        if skip_token and skip_token.startswith('http'):
            return self._api_request(skip_token, token)

        # Build filter
        start_dt = start_time.replace('+00:00', 'Z') if '+00:00' in start_time else start_time
        end_dt = end_time.replace('+00:00', 'Z') if '+00:00' in end_time else end_time

        filter_str = f"activityDateTime ge {start_dt} and activityDateTime le {end_dt}"

        url = f"{self.GRAPH_BETA_URL}/auditLogs/directoryAudits"

        params = {
            '$filter': filter_str,
            '$top': str(top),
            '$orderby': 'activityDateTime asc'
        }

        return self._api_request(url, token, params)

    def query_security_alerts(
        self,
        skip_token: str = None
    ) -> Optional[Dict]:
        """
        Query Azure Security Center Alerts.

        Args:
            skip_token: Pagination token

        Returns:
            API response with alerts
        """
        if not self.subscription_id:
            print("Subscription ID required for security alerts")
            return None

        token = self._get_management_token()

        url = (
            f"{self.AZURE_MANAGEMENT_URL}/subscriptions/{self.subscription_id}"
            f"/providers/Microsoft.Security/alerts"
        )

        params = {
            'api-version': '2022-01-01'
        }

        if skip_token:
            params['$skipToken'] = skip_token

        return self._api_request(url, token, params)

    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse and normalize Azure Monitor events.

        Args:
            events: Raw Azure Monitor events

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
        log_type: str,
        timestamp: datetime
    ) -> Optional[str]:
        """
        Write normalized events to S3.

        Args:
            events: Normalized events
            log_type: Azure log type
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
            f"{self.output_prefix}/normalized/{log_type}/"
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

    def collect_activity_logs(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Collect Azure Activity Logs.

        Args:
            hours_back: Hours of history to collect if no checkpoint

        Returns:
            Collection statistics
        """
        log_type = 'activity_logs'

        # Get last checkpoint or calculate start time
        checkpoint = self.get_last_checkpoint(log_type)
        skip_token = None

        if checkpoint and checkpoint.get('timestamp'):
            start_time = checkpoint['timestamp']
            skip_token = checkpoint.get('skip_token')
        else:
            start_time = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()

        all_events = []
        total_pages = 0
        max_pages = 100  # Safety limit
        last_timestamp = start_time

        while total_pages < max_pages:
            result = self.query_activity_logs(start_time=start_time, skip_token=skip_token)

            if not result:
                break

            events = result.get('value', [])
            all_events.extend(events)

            # Track last event timestamp
            if events:
                last_event = events[-1]
                last_timestamp = last_event.get('eventTimestamp', last_timestamp)

            # Check for next page
            next_link = result.get('nextLink', '')
            if next_link:
                # Extract skip token from nextLink
                if '$skiptoken=' in next_link:
                    skip_token = next_link.split('$skiptoken=')[1].split('&')[0]
                else:
                    skip_token = next_link
            else:
                skip_token = None
                break

            total_pages += 1

        print(f"Collected {len(all_events)} activity log events")

        if not all_events:
            return {
                'log_type': log_type,
                'events_collected': 0,
                'events_normalized': 0
            }

        # Normalize events
        normalized = self.process_events(all_events)

        # Write to S3
        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, log_type, now)

            # Save checkpoint
            self.save_checkpoint(log_type, timestamp=last_timestamp, skip_token=skip_token)

        return {
            'log_type': log_type,
            'events_collected': len(all_events),
            'events_normalized': len(normalized),
            'output_key': output_key
        }

    def collect_signin_logs(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Collect Azure AD Sign-in Logs.

        Args:
            hours_back: Hours of history to collect if no checkpoint

        Returns:
            Collection statistics
        """
        log_type = 'signin_logs'

        # Get last checkpoint or calculate start time
        checkpoint = self.get_last_checkpoint(log_type)
        skip_token = None

        if checkpoint and checkpoint.get('timestamp'):
            start_time = checkpoint['timestamp']
            skip_token = checkpoint.get('skip_token')
        else:
            start_time = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()

        all_events = []
        total_pages = 0
        max_pages = 100
        last_timestamp = start_time

        while total_pages < max_pages:
            result = self.query_signin_logs(start_time=start_time, skip_token=skip_token)

            if not result:
                break

            events = result.get('value', [])
            all_events.extend(events)

            # Track last event timestamp
            if events:
                last_event = events[-1]
                last_timestamp = last_event.get('createdDateTime', last_timestamp)

            # Check for next page (Graph API uses @odata.nextLink)
            next_link = result.get('@odata.nextLink', '')
            if next_link:
                skip_token = next_link
            else:
                skip_token = None
                break

            total_pages += 1

        print(f"Collected {len(all_events)} sign-in log events")

        if not all_events:
            return {
                'log_type': log_type,
                'events_collected': 0,
                'events_normalized': 0
            }

        # Normalize events
        normalized = self.process_events(all_events)

        # Write to S3
        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, log_type, now)

            # Save checkpoint
            self.save_checkpoint(log_type, timestamp=last_timestamp, skip_token=skip_token)

        return {
            'log_type': log_type,
            'events_collected': len(all_events),
            'events_normalized': len(normalized),
            'output_key': output_key
        }

    def collect_audit_logs(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Collect Azure AD Audit Logs.

        Args:
            hours_back: Hours of history to collect if no checkpoint

        Returns:
            Collection statistics
        """
        log_type = 'audit_logs'

        # Get last checkpoint or calculate start time
        checkpoint = self.get_last_checkpoint(log_type)
        skip_token = None

        if checkpoint and checkpoint.get('timestamp'):
            start_time = checkpoint['timestamp']
            skip_token = checkpoint.get('skip_token')
        else:
            start_time = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()

        all_events = []
        total_pages = 0
        max_pages = 100
        last_timestamp = start_time

        while total_pages < max_pages:
            result = self.query_audit_logs(start_time=start_time, skip_token=skip_token)

            if not result:
                break

            events = result.get('value', [])
            all_events.extend(events)

            # Track last event timestamp
            if events:
                last_event = events[-1]
                last_timestamp = last_event.get('activityDateTime', last_timestamp)

            # Check for next page
            next_link = result.get('@odata.nextLink', '')
            if next_link:
                skip_token = next_link
            else:
                skip_token = None
                break

            total_pages += 1

        print(f"Collected {len(all_events)} audit log events")

        if not all_events:
            return {
                'log_type': log_type,
                'events_collected': 0,
                'events_normalized': 0
            }

        # Normalize events
        normalized = self.process_events(all_events)

        # Write to S3
        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, log_type, now)

            # Save checkpoint
            self.save_checkpoint(log_type, timestamp=last_timestamp, skip_token=skip_token)

        return {
            'log_type': log_type,
            'events_collected': len(all_events),
            'events_normalized': len(normalized),
            'output_key': output_key
        }

    def collect_security_alerts(self) -> Dict[str, Any]:
        """
        Collect Azure Security Center Alerts.

        Returns:
            Collection statistics
        """
        log_type = 'security_alerts'

        # Get last checkpoint
        checkpoint = self.get_last_checkpoint(log_type)
        skip_token = checkpoint.get('skip_token') if checkpoint else None

        all_alerts = []
        total_pages = 0
        max_pages = 100

        while total_pages < max_pages:
            result = self.query_security_alerts(skip_token=skip_token)

            if not result:
                break

            alerts = result.get('value', [])
            all_alerts.extend(alerts)

            # Check for next page
            next_link = result.get('nextLink', '')
            if next_link:
                skip_token = next_link
            else:
                skip_token = None
                break

            total_pages += 1

        print(f"Collected {len(all_alerts)} security alerts")

        if not all_alerts:
            return {
                'log_type': log_type,
                'events_collected': 0,
                'events_normalized': 0
            }

        # Normalize events
        normalized = self.process_events(all_alerts)

        # Write to S3
        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, log_type, now)

            # Save checkpoint
            self.save_checkpoint(log_type, skip_token=skip_token)

        return {
            'log_type': log_type,
            'events_collected': len(all_alerts),
            'events_normalized': len(normalized),
            'output_key': output_key
        }


def lambda_handler(event, context):
    """
    AWS Lambda handler for Azure Monitor log collection.

    Supports collection modes:
    1. activity_logs: Azure Activity Logs
    2. signin_logs: Azure AD Sign-in Logs
    3. audit_logs: Azure AD Audit Logs
    4. security_alerts: Azure Security Center Alerts
    5. all: Collect all log types (default)

    Environment Variables:
        S3_BUCKET: S3 bucket for log storage
        OUTPUT_PREFIX: S3 prefix for output
        CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
        AZURE_TENANT_ID: Azure AD tenant ID
        AZURE_CLIENT_ID: Azure AD application (client) ID
        AZURE_CLIENT_SECRET: Azure AD client secret
        AZURE_SUBSCRIPTION_ID: Azure subscription ID
        AZURE_WORKSPACE_ID: Log Analytics workspace ID (optional)
    """
    # Get configuration from environment
    s3_bucket = os.environ.get('S3_BUCKET', 'mantissa-log-data')
    output_prefix = os.environ.get('OUTPUT_PREFIX', 'azure_monitor')
    checkpoint_table = os.environ.get('CHECKPOINT_TABLE', 'mantissa-log-checkpoints')

    # Azure configuration
    tenant_id = os.environ.get('AZURE_TENANT_ID', '')
    client_id = os.environ.get('AZURE_CLIENT_ID', '')
    client_secret = os.environ.get('AZURE_CLIENT_SECRET', '')
    subscription_id = os.environ.get('AZURE_SUBSCRIPTION_ID', '')
    workspace_id = os.environ.get('AZURE_WORKSPACE_ID', '')

    # Validate configuration
    if not tenant_id or not client_id or not client_secret:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': 'Missing Azure AD credentials (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)'
            })
        }

    # Determine what to collect
    mode = event.get('mode', 'all')
    hours_back = event.get('hours_back', 24)

    log_types = []
    if mode == 'all':
        log_types = ['activity_logs', 'signin_logs', 'audit_logs', 'security_alerts']
    elif mode in ['activity_logs', 'signin_logs', 'audit_logs', 'security_alerts']:
        log_types = [mode]
    else:
        log_types = event.get('log_types', ['activity_logs', 'signin_logs', 'audit_logs'])

    # Initialize collector
    collector = AzureMonitorCollector(
        s3_bucket=s3_bucket,
        output_prefix=output_prefix,
        checkpoint_table=checkpoint_table,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        subscription_id=subscription_id,
        workspace_id=workspace_id,
        log_types=log_types
    )

    try:
        results = {}

        if 'activity_logs' in log_types and subscription_id:
            results['activity_logs'] = collector.collect_activity_logs(hours_back)

        if 'signin_logs' in log_types:
            results['signin_logs'] = collector.collect_signin_logs(hours_back)

        if 'audit_logs' in log_types:
            results['audit_logs'] = collector.collect_audit_logs(hours_back)

        if 'security_alerts' in log_types and subscription_id:
            results['security_alerts'] = collector.collect_security_alerts()

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
