"""
GCP Cloud Logging Collector

Collects GCP Cloud Logging entries via Cloud Logging API or Pub/Sub export.

Supports GCP log types:
- Cloud Audit Logs (Admin Activity, Data Access, System Event)
- VPC Flow Logs
- Firewall Logs
- GKE Audit Logs
- Cloud Functions Logs
- Cloud Storage Access Logs
- Compute Engine Logs

Data Flow:
1. GCP Cloud Logging -> Pub/Sub -> S3 (via Pub/Sub to S3 connector)
2. GCP Cloud Logging -> Cloud Storage -> S3 (via Storage Transfer)
3. GCP Cloud Logging API (for historical/on-demand data)

Authentication:
- GCP Service Account JSON key
- Workload Identity Federation (recommended for production)

Reference:
- https://cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list
- https://cloud.google.com/logging/docs/export/configure_export_v2
"""

import json
import os
import boto3
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
import base64

try:
    from google.cloud import logging as gcp_logging
    from google.oauth2 import service_account
    GCP_SDK_AVAILABLE = True
except ImportError:
    GCP_SDK_AVAILABLE = False

from shared.parsers.gcp_logging import GCPLoggingParser


class GCPLoggingCollector:
    """Collects GCP Cloud Logging entries via API"""

    def __init__(
        self,
        s3_bucket: str,
        output_prefix: str,
        checkpoint_table: str,
        project_id: str,
        credentials_json: str = None,
        log_filters: List[str] = None
    ):
        """
        Initialize GCP Cloud Logging collector.

        Args:
            s3_bucket: S3 bucket for log storage
            output_prefix: S3 prefix for output
            checkpoint_table: DynamoDB table for checkpoint tracking
            project_id: GCP project ID
            credentials_json: GCP service account JSON key (base64 encoded or raw)
            log_filters: List of log filters to apply
        """
        self.s3_bucket = s3_bucket
        self.output_prefix = output_prefix
        self.checkpoint_table = checkpoint_table
        self.project_id = project_id
        self.credentials_json = credentials_json
        self.log_filters = log_filters or []

        self.s3 = boto3.client('s3')
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(checkpoint_table)

        self.parser = GCPLoggingParser()
        self.client = None

        if GCP_SDK_AVAILABLE and credentials_json:
            self._init_gcp_client()

    def _init_gcp_client(self):
        """Initialize GCP Cloud Logging client"""
        try:
            # Decode credentials if base64 encoded
            if self.credentials_json:
                try:
                    creds_data = base64.b64decode(self.credentials_json)
                    creds_json = json.loads(creds_data)
                except Exception:
                    # Try as raw JSON
                    creds_json = json.loads(self.credentials_json)

                credentials = service_account.Credentials.from_service_account_info(
                    creds_json,
                    scopes=['https://www.googleapis.com/auth/logging.read']
                )
                self.client = gcp_logging.Client(
                    project=self.project_id,
                    credentials=credentials
                )
            else:
                # Use application default credentials
                self.client = gcp_logging.Client(project=self.project_id)

        except Exception as e:
            print(f"Failed to initialize GCP client: {str(e)}")
            self.client = None

    def get_last_checkpoint(self, log_type: str) -> Optional[str]:
        """
        Get last processed timestamp from DynamoDB.

        Args:
            log_type: Type of logs being collected

        Returns:
            Last timestamp or None
        """
        try:
            response = self.table.get_item(
                Key={'source': f'gcp_logging:{log_type}'}
            )
            if 'Item' in response:
                return response['Item'].get('timestamp')
        except Exception as e:
            print(f"Error getting checkpoint: {str(e)}")

        return None

    def save_checkpoint(self, log_type: str, timestamp: str) -> None:
        """
        Save checkpoint to DynamoDB.

        Args:
            log_type: Type of logs being collected
            timestamp: Last processed timestamp
        """
        try:
            self.table.put_item(
                Item={
                    'source': f'gcp_logging:{log_type}',
                    'timestamp': timestamp,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
            )
        except Exception as e:
            print(f"Error saving checkpoint: {str(e)}")

    def build_filter(
        self,
        log_type: str,
        start_time: str,
        end_time: str = None,
        additional_filter: str = None
    ) -> str:
        """
        Build GCP Cloud Logging filter string.

        Args:
            log_type: Type of logs to query
            start_time: Start timestamp
            end_time: End timestamp
            additional_filter: Additional filter conditions

        Returns:
            Filter string for Cloud Logging API
        """
        filters = []

        # Add timestamp filter
        filters.append(f'timestamp >= "{start_time}"')
        if end_time:
            filters.append(f'timestamp <= "{end_time}"')

        # Add log type filter
        if log_type == 'audit_activity':
            filters.append('logName:"cloudaudit.googleapis.com%2Factivity"')
        elif log_type == 'audit_data_access':
            filters.append('logName:"cloudaudit.googleapis.com%2Fdata_access"')
        elif log_type == 'audit_system_event':
            filters.append('logName:"cloudaudit.googleapis.com%2Fsystem_event"')
        elif log_type == 'vpc_flows':
            filters.append('logName:"compute.googleapis.com%2Fvpc_flows"')
        elif log_type == 'firewall':
            filters.append('logName:"compute.googleapis.com%2Ffirewall"')
        elif log_type == 'gke':
            filters.append('resource.type="k8s_cluster" OR resource.type="gke_cluster"')

        # Add additional filter
        if additional_filter:
            filters.append(f'({additional_filter})')

        return ' AND '.join(filters)

    def query_logs(
        self,
        filter_str: str,
        page_size: int = 1000,
        page_token: str = None
    ) -> Dict[str, Any]:
        """
        Query logs from GCP Cloud Logging API.

        Args:
            filter_str: Filter string
            page_size: Maximum entries per page
            page_token: Pagination token

        Returns:
            Dict with entries and next page token
        """
        if not self.client:
            print("GCP client not initialized")
            return {'entries': [], 'next_page_token': None}

        try:
            entries = []
            iterator = self.client.list_entries(
                filter_=filter_str,
                page_size=page_size,
                page_token=page_token,
                order_by=gcp_logging.ASCENDING
            )

            # Get entries from current page
            page = next(iterator.pages, None)
            if page:
                for entry in page:
                    # Convert LogEntry to dict
                    entry_dict = self._log_entry_to_dict(entry)
                    entries.append(entry_dict)

                return {
                    'entries': entries,
                    'next_page_token': iterator.next_page_token
                }

            return {'entries': [], 'next_page_token': None}

        except Exception as e:
            print(f"Error querying logs: {str(e)}")
            return {'entries': [], 'next_page_token': None}

    def _log_entry_to_dict(self, entry) -> Dict[str, Any]:
        """Convert GCP LogEntry object to dictionary"""
        result = {
            'logName': entry.log_name,
            'timestamp': entry.timestamp.isoformat() if entry.timestamp else '',
            'receiveTimestamp': entry.received_timestamp.isoformat() if entry.received_timestamp else '',
            'severity': entry.severity if hasattr(entry, 'severity') else 'DEFAULT',
            'insertId': entry.insert_id if hasattr(entry, 'insert_id') else '',
            'trace': entry.trace if hasattr(entry, 'trace') else '',
            'spanId': entry.span_id if hasattr(entry, 'span_id') else '',
            'resource': {},
            'labels': entry.labels if hasattr(entry, 'labels') else {}
        }

        # Extract resource
        if hasattr(entry, 'resource') and entry.resource:
            result['resource'] = {
                'type': entry.resource.type,
                'labels': dict(entry.resource.labels) if entry.resource.labels else {}
            }

        # Extract payload based on type
        if hasattr(entry, 'payload') and entry.payload:
            if hasattr(entry.payload, 'items'):
                # Struct payload (jsonPayload)
                result['jsonPayload'] = dict(entry.payload)
            elif isinstance(entry.payload, str):
                # Text payload
                result['textPayload'] = entry.payload
            elif hasattr(entry.payload, 'type_url'):
                # Proto payload
                result['protoPayload'] = self._proto_to_dict(entry.payload)
            else:
                result['jsonPayload'] = entry.payload

        # Handle proto payload for audit logs
        if hasattr(entry, 'proto_payload') and entry.proto_payload:
            result['protoPayload'] = self._proto_to_dict(entry.proto_payload)

        return result

    def _proto_to_dict(self, proto) -> Dict[str, Any]:
        """Convert protobuf message to dictionary"""
        if hasattr(proto, 'to_dict'):
            return proto.to_dict()
        elif hasattr(proto, '__dict__'):
            return {k: v for k, v in proto.__dict__.items() if not k.startswith('_')}
        else:
            return {'value': str(proto)}

    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse and normalize GCP log entries.

        Args:
            events: Raw GCP log entries

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
            log_type: GCP log type
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

    def collect_audit_activity_logs(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Collect Cloud Audit Logs (Admin Activity).

        Args:
            hours_back: Hours of history to collect if no checkpoint

        Returns:
            Collection statistics
        """
        log_type = 'audit_activity'

        # Get last checkpoint or calculate start time
        checkpoint = self.get_last_checkpoint(log_type)

        if checkpoint:
            start_time = checkpoint
        else:
            start_time = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()

        end_time = datetime.now(timezone.utc).isoformat()

        # Build filter
        filter_str = self.build_filter(log_type, start_time, end_time)

        all_entries = []
        page_token = None
        max_pages = 100
        pages_fetched = 0
        last_timestamp = start_time

        while pages_fetched < max_pages:
            result = self.query_logs(filter_str, page_size=1000, page_token=page_token)

            entries = result.get('entries', [])
            all_entries.extend(entries)

            # Track last timestamp
            if entries:
                last_entry = entries[-1]
                last_timestamp = last_entry.get('timestamp', last_timestamp)

            page_token = result.get('next_page_token')
            if not page_token:
                break

            pages_fetched += 1

        print(f"Collected {len(all_entries)} audit activity log entries")

        if not all_entries:
            return {
                'log_type': log_type,
                'events_collected': 0,
                'events_normalized': 0
            }

        # Normalize events
        normalized = self.process_events(all_entries)

        # Write to S3
        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, log_type, now)

            # Save checkpoint
            self.save_checkpoint(log_type, last_timestamp)

        return {
            'log_type': log_type,
            'events_collected': len(all_entries),
            'events_normalized': len(normalized),
            'output_key': output_key
        }

    def collect_audit_data_access_logs(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Collect Cloud Audit Logs (Data Access).

        Args:
            hours_back: Hours of history to collect if no checkpoint

        Returns:
            Collection statistics
        """
        log_type = 'audit_data_access'

        checkpoint = self.get_last_checkpoint(log_type)

        if checkpoint:
            start_time = checkpoint
        else:
            start_time = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()

        end_time = datetime.now(timezone.utc).isoformat()

        filter_str = self.build_filter(log_type, start_time, end_time)

        all_entries = []
        page_token = None
        max_pages = 100
        pages_fetched = 0
        last_timestamp = start_time

        while pages_fetched < max_pages:
            result = self.query_logs(filter_str, page_size=1000, page_token=page_token)

            entries = result.get('entries', [])
            all_entries.extend(entries)

            if entries:
                last_entry = entries[-1]
                last_timestamp = last_entry.get('timestamp', last_timestamp)

            page_token = result.get('next_page_token')
            if not page_token:
                break

            pages_fetched += 1

        print(f"Collected {len(all_entries)} data access log entries")

        if not all_entries:
            return {
                'log_type': log_type,
                'events_collected': 0,
                'events_normalized': 0
            }

        normalized = self.process_events(all_entries)

        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, log_type, now)
            self.save_checkpoint(log_type, last_timestamp)

        return {
            'log_type': log_type,
            'events_collected': len(all_entries),
            'events_normalized': len(normalized),
            'output_key': output_key
        }

    def collect_vpc_flow_logs(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Collect VPC Flow Logs.

        Args:
            hours_back: Hours of history to collect if no checkpoint

        Returns:
            Collection statistics
        """
        log_type = 'vpc_flows'

        checkpoint = self.get_last_checkpoint(log_type)

        if checkpoint:
            start_time = checkpoint
        else:
            start_time = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()

        end_time = datetime.now(timezone.utc).isoformat()

        filter_str = self.build_filter(log_type, start_time, end_time)

        all_entries = []
        page_token = None
        max_pages = 100
        pages_fetched = 0
        last_timestamp = start_time

        while pages_fetched < max_pages:
            result = self.query_logs(filter_str, page_size=1000, page_token=page_token)

            entries = result.get('entries', [])
            all_entries.extend(entries)

            if entries:
                last_entry = entries[-1]
                last_timestamp = last_entry.get('timestamp', last_timestamp)

            page_token = result.get('next_page_token')
            if not page_token:
                break

            pages_fetched += 1

        print(f"Collected {len(all_entries)} VPC flow log entries")

        if not all_entries:
            return {
                'log_type': log_type,
                'events_collected': 0,
                'events_normalized': 0
            }

        normalized = self.process_events(all_entries)

        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, log_type, now)
            self.save_checkpoint(log_type, last_timestamp)

        return {
            'log_type': log_type,
            'events_collected': len(all_entries),
            'events_normalized': len(normalized),
            'output_key': output_key
        }

    def collect_firewall_logs(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Collect Firewall Logs.

        Args:
            hours_back: Hours of history to collect if no checkpoint

        Returns:
            Collection statistics
        """
        log_type = 'firewall'

        checkpoint = self.get_last_checkpoint(log_type)

        if checkpoint:
            start_time = checkpoint
        else:
            start_time = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()

        end_time = datetime.now(timezone.utc).isoformat()

        filter_str = self.build_filter(log_type, start_time, end_time)

        all_entries = []
        page_token = None
        max_pages = 100
        pages_fetched = 0
        last_timestamp = start_time

        while pages_fetched < max_pages:
            result = self.query_logs(filter_str, page_size=1000, page_token=page_token)

            entries = result.get('entries', [])
            all_entries.extend(entries)

            if entries:
                last_entry = entries[-1]
                last_timestamp = last_entry.get('timestamp', last_timestamp)

            page_token = result.get('next_page_token')
            if not page_token:
                break

            pages_fetched += 1

        print(f"Collected {len(all_entries)} firewall log entries")

        if not all_entries:
            return {
                'log_type': log_type,
                'events_collected': 0,
                'events_normalized': 0
            }

        normalized = self.process_events(all_entries)

        output_key = None
        if normalized:
            now = datetime.now(timezone.utc)
            output_key = self.write_normalized_events(normalized, log_type, now)
            self.save_checkpoint(log_type, last_timestamp)

        return {
            'log_type': log_type,
            'events_collected': len(all_entries),
            'events_normalized': len(normalized),
            'output_key': output_key
        }


def lambda_handler(event, context):
    """
    AWS Lambda handler for GCP Cloud Logging collection.

    Supports collection modes:
    1. audit_activity: Cloud Audit Logs (Admin Activity)
    2. audit_data_access: Cloud Audit Logs (Data Access)
    3. vpc_flows: VPC Flow Logs
    4. firewall: Firewall Logs
    5. all: Collect all log types (default)

    Environment Variables:
        S3_BUCKET: S3 bucket for log storage
        OUTPUT_PREFIX: S3 prefix for output
        CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
        GCP_PROJECT_ID: GCP project ID
        GCP_CREDENTIALS_JSON: GCP service account JSON key (base64 encoded)
    """
    # Get configuration from environment
    s3_bucket = os.environ.get('S3_BUCKET', 'mantissa-log-data')
    output_prefix = os.environ.get('OUTPUT_PREFIX', 'gcp_logging')
    checkpoint_table = os.environ.get('CHECKPOINT_TABLE', 'mantissa-log-checkpoints')

    # GCP configuration
    project_id = os.environ.get('GCP_PROJECT_ID', '')
    credentials_json = os.environ.get('GCP_CREDENTIALS_JSON', '')

    # Validate configuration
    if not project_id:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': 'Missing GCP_PROJECT_ID configuration'
            })
        }

    if not GCP_SDK_AVAILABLE:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': 'GCP SDK not available. Install google-cloud-logging package.'
            })
        }

    # Determine what to collect
    mode = event.get('mode', 'all')
    hours_back = event.get('hours_back', 24)

    log_types = []
    if mode == 'all':
        log_types = ['audit_activity', 'audit_data_access', 'vpc_flows', 'firewall']
    elif mode in ['audit_activity', 'audit_data_access', 'vpc_flows', 'firewall']:
        log_types = [mode]
    else:
        log_types = event.get('log_types', ['audit_activity'])

    # Initialize collector
    collector = GCPLoggingCollector(
        s3_bucket=s3_bucket,
        output_prefix=output_prefix,
        checkpoint_table=checkpoint_table,
        project_id=project_id,
        credentials_json=credentials_json
    )

    try:
        results = {}

        if 'audit_activity' in log_types:
            results['audit_activity'] = collector.collect_audit_activity_logs(hours_back)

        if 'audit_data_access' in log_types:
            results['audit_data_access'] = collector.collect_audit_data_access_logs(hours_back)

        if 'vpc_flows' in log_types:
            results['vpc_flows'] = collector.collect_vpc_flow_logs(hours_back)

        if 'firewall' in log_types:
            results['firewall'] = collector.collect_firewall_logs(hours_back)

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
