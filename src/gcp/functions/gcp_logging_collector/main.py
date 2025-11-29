"""
GCP Cloud Logging Collector - Cloud Function

Native GCP Cloud Function for collecting GCP Cloud Logging entries
and storing them in Cloud Storage for BigQuery analysis.

Deployment: GCP Cloud Functions (2nd gen)
Trigger: Cloud Scheduler (cron) or Pub/Sub
Runtime: Python 3.11
Memory: 512 MB
Timeout: 540s (9 minutes)

Environment Variables:
- GCP_PROJECT_ID: GCP project ID to collect logs from
- GCS_BUCKET: Cloud Storage bucket for log output
- LOG_TYPES: Comma-separated list (audit,vpc_flow,firewall,gke)
- COLLECTION_INTERVAL_HOURS: Hours of logs to collect (default: 1)
"""

import functions_framework
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any
from google.cloud import logging_v2
from google.cloud import storage
from google.cloud import firestore
import os
import sys

# Add shared parsers to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'shared'))
from parsers.gcp_logging import GCPLoggingParser


class GCPLoggingCollector:
    """GCP-native log collector using Cloud Logging API"""

    def __init__(self, project_id: str, gcs_bucket: str):
        """
        Initialize GCP Cloud Logging collector.

        Args:
            project_id: GCP project ID to collect logs from
            gcs_bucket: Cloud Storage bucket name for output
        """
        self.project_id = project_id
        self.gcs_bucket = gcs_bucket

        self.logging_client = logging_v2.Client(project=project_id)
        self.storage_client = storage.Client(project=project_id)
        self.firestore_client = firestore.Client(project=project_id)
        self.parser = GCPLoggingParser()

        self.bucket = self.storage_client.bucket(gcs_bucket)

    def get_checkpoint(self, log_type: str) -> datetime:
        """
        Get last collection timestamp from Firestore.

        Args:
            log_type: Type of logs (audit, vpc_flow, firewall, gke)

        Returns:
            Last collection timestamp or default (1 hour ago)
        """
        doc_ref = self.firestore_client.collection('checkpoints').document(f'gcp_logging_{log_type}')
        doc = doc_ref.get()

        if doc.exists:
            data = doc.to_dict()
            return datetime.fromisoformat(data['last_timestamp'])
        else:
            # Default to 1 hour ago for first run
            return datetime.now(timezone.utc) - timedelta(hours=1)

    def update_checkpoint(self, log_type: str, timestamp: datetime):
        """
        Update collection checkpoint in Firestore.

        Args:
            log_type: Type of logs
            timestamp: New checkpoint timestamp
        """
        doc_ref = self.firestore_client.collection('checkpoints').document(f'gcp_logging_{log_type}')
        doc_ref.set({
            'last_timestamp': timestamp.isoformat(),
            'updated_at': datetime.now(timezone.utc).isoformat(),
            'log_type': log_type,
            'project_id': self.project_id
        })

    def collect_audit_logs(self, hours_back: int = 1) -> Dict[str, int]:
        """
        Collect Cloud Audit Logs.

        Args:
            hours_back: Hours of logs to collect

        Returns:
            Collection statistics
        """
        log_type = 'audit'
        last_timestamp = self.get_checkpoint(log_type)

        # Build filter for audit logs
        filter_str = (
            f'logName=~"projects/{self.project_id}/logs/cloudaudit.googleapis.com" '
            f'AND timestamp>="{last_timestamp.isoformat()}"'
        )

        entries = []
        latest_timestamp = last_timestamp

        # List log entries
        for entry in self.logging_client.list_entries(filter_=filter_str, max_results=10000):
            entry_dict = {
                'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
                'severity': entry.severity,
                'logName': entry.log_name,
                'protoPayload': dict(entry.payload) if hasattr(entry, 'payload') else None,
                'resource': {
                    'type': entry.resource.type,
                    'labels': dict(entry.resource.labels) if entry.resource.labels else {}
                },
                'insertId': entry.insert_id,
                'labels': dict(entry.labels) if entry.labels else {}
            }

            entries.append(entry_dict)

            # Track latest timestamp
            if entry.timestamp and entry.timestamp.replace(tzinfo=timezone.utc) > latest_timestamp:
                latest_timestamp = entry.timestamp.replace(tzinfo=timezone.utc)

        # Store raw and normalized logs
        stats = self._process_and_store(entries, log_type, 'audit_logs')

        # Update checkpoint
        if entries:
            self.update_checkpoint(log_type, latest_timestamp)

        return stats

    def collect_vpc_flow_logs(self, hours_back: int = 1) -> Dict[str, int]:
        """
        Collect VPC Flow Logs.

        Args:
            hours_back: Hours of logs to collect

        Returns:
            Collection statistics
        """
        log_type = 'vpc_flow'
        last_timestamp = self.get_checkpoint(log_type)

        filter_str = (
            f'logName=~"projects/{self.project_id}/logs/compute.googleapis.com%2Fvpc_flows" '
            f'AND timestamp>="{last_timestamp.isoformat()}"'
        )

        entries = []
        latest_timestamp = last_timestamp

        for entry in self.logging_client.list_entries(filter_=filter_str, max_results=50000):
            entry_dict = {
                'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
                'jsonPayload': dict(entry.payload) if hasattr(entry, 'payload') else None,
                'resource': {
                    'type': entry.resource.type,
                    'labels': dict(entry.resource.labels) if entry.resource.labels else {}
                },
                'insertId': entry.insert_id
            }

            entries.append(entry_dict)

            if entry.timestamp and entry.timestamp.replace(tzinfo=timezone.utc) > latest_timestamp:
                latest_timestamp = entry.timestamp.replace(tzinfo=timezone.utc)

        stats = self._process_and_store(entries, log_type, 'vpc_flow_logs')

        if entries:
            self.update_checkpoint(log_type, latest_timestamp)

        return stats

    def collect_firewall_logs(self, hours_back: int = 1) -> Dict[str, int]:
        """
        Collect Firewall Logs.

        Args:
            hours_back: Hours of logs to collect

        Returns:
            Collection statistics
        """
        log_type = 'firewall'
        last_timestamp = self.get_checkpoint(log_type)

        filter_str = (
            f'logName=~"projects/{self.project_id}/logs/compute.googleapis.com%2Ffirewall" '
            f'AND timestamp>="{last_timestamp.isoformat()}"'
        )

        entries = []
        latest_timestamp = last_timestamp

        for entry in self.logging_client.list_entries(filter_=filter_str, max_results=50000):
            entry_dict = {
                'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
                'jsonPayload': dict(entry.payload) if hasattr(entry, 'payload') else None,
                'resource': {
                    'type': entry.resource.type,
                    'labels': dict(entry.resource.labels) if entry.resource.labels else {}
                },
                'insertId': entry.insert_id
            }

            entries.append(entry_dict)

            if entry.timestamp and entry.timestamp.replace(tzinfo=timezone.utc) > latest_timestamp:
                latest_timestamp = entry.timestamp.replace(tzinfo=timezone.utc)

        stats = self._process_and_store(entries, log_type, 'firewall_logs')

        if entries:
            self.update_checkpoint(log_type, latest_timestamp)

        return stats

    def collect_gke_audit_logs(self, hours_back: int = 1) -> Dict[str, int]:
        """
        Collect GKE Audit Logs.

        Args:
            hours_back: Hours of logs to collect

        Returns:
            Collection statistics
        """
        log_type = 'gke'
        last_timestamp = self.get_checkpoint(log_type)

        filter_str = (
            f'resource.type="k8s_cluster" '
            f'AND logName=~"projects/{self.project_id}/logs/cloudaudit.googleapis.com" '
            f'AND timestamp>="{last_timestamp.isoformat()}"'
        )

        entries = []
        latest_timestamp = last_timestamp

        for entry in self.logging_client.list_entries(filter_=filter_str, max_results=10000):
            entry_dict = {
                'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
                'severity': entry.severity,
                'logName': entry.log_name,
                'protoPayload': dict(entry.payload) if hasattr(entry, 'payload') else None,
                'resource': {
                    'type': entry.resource.type,
                    'labels': dict(entry.resource.labels) if entry.resource.labels else {}
                },
                'insertId': entry.insert_id
            }

            entries.append(entry_dict)

            if entry.timestamp and entry.timestamp.replace(tzinfo=timezone.utc) > latest_timestamp:
                latest_timestamp = entry.timestamp.replace(tzinfo=timezone.utc)

        stats = self._process_and_store(entries, log_type, 'gke_audit_logs')

        if entries:
            self.update_checkpoint(log_type, latest_timestamp)

        return stats

    def _process_and_store(self, entries: List[Dict], log_type: str, table_name: str) -> Dict[str, int]:
        """
        Process and store log entries.

        Args:
            entries: List of log entries
            log_type: Type of logs
            table_name: BigQuery table name

        Returns:
            Collection statistics
        """
        if not entries:
            return {'collected': 0, 'normalized': 0, 'errors': 0}

        now = datetime.now(timezone.utc)
        date_partition = now.strftime('%Y/%m/%d')
        hour_partition = now.strftime('%H')

        # Store raw logs
        raw_path = f'gcp_logging/{log_type}/raw/{date_partition}/{hour_partition}/logs_{now.strftime("%Y%m%d_%H%M%S")}.json'
        raw_blob = self.bucket.blob(raw_path)
        raw_blob.upload_from_string(
            '\n'.join([json.dumps(entry) for entry in entries]),
            content_type='application/x-ndjson'
        )

        # Parse and store normalized logs
        normalized_entries = []
        error_count = 0

        for entry in entries:
            try:
                normalized = self.parser.parse(entry)
                normalized_entries.append(normalized)
            except Exception as e:
                error_count += 1
                print(f"Error parsing entry: {e}")

        if normalized_entries:
            normalized_path = f'gcp_logging/{log_type}/normalized/{date_partition}/{hour_partition}/logs_{now.strftime("%Y%m%d_%H%M%S")}.json'
            normalized_blob = self.bucket.blob(normalized_path)
            normalized_blob.upload_from_string(
                '\n'.join([json.dumps(entry) for entry in normalized_entries]),
                content_type='application/x-ndjson'
            )

        return {
            'collected': len(entries),
            'normalized': len(normalized_entries),
            'errors': error_count
        }


@functions_framework.http
def collect_gcp_logs(request):
    """
    HTTP Cloud Function entry point.

    Args:
        request: Flask request object

    Returns:
        JSON response with collection statistics
    """
    # Get configuration from environment
    project_id = os.environ.get('GCP_PROJECT_ID')
    gcs_bucket = os.environ.get('GCS_BUCKET')
    log_types = os.environ.get('LOG_TYPES', 'audit,vpc_flow,firewall,gke').split(',')
    hours_back = int(os.environ.get('COLLECTION_INTERVAL_HOURS', '1'))

    if not project_id or not gcs_bucket:
        return {
            'error': 'Missing required environment variables: GCP_PROJECT_ID, GCS_BUCKET'
        }, 400

    collector = GCPLoggingCollector(project_id, gcs_bucket)

    results = {}

    try:
        # Collect requested log types
        if 'audit' in log_types:
            results['audit_logs'] = collector.collect_audit_logs(hours_back)

        if 'vpc_flow' in log_types:
            results['vpc_flow_logs'] = collector.collect_vpc_flow_logs(hours_back)

        if 'firewall' in log_types:
            results['firewall_logs'] = collector.collect_firewall_logs(hours_back)

        if 'gke' in log_types:
            results['gke_audit_logs'] = collector.collect_gke_audit_logs(hours_back)

        return {
            'status': 'success',
            'project_id': project_id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'results': results
        }, 200

    except Exception as e:
        print(f"Error collecting logs: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, 500


@functions_framework.cloud_event
def collect_gcp_logs_pubsub(cloud_event):
    """
    Pub/Sub-triggered Cloud Function entry point.

    Args:
        cloud_event: CloudEvent object
    """
    project_id = os.environ.get('GCP_PROJECT_ID')
    gcs_bucket = os.environ.get('GCS_BUCKET')
    log_types = os.environ.get('LOG_TYPES', 'audit,vpc_flow,firewall,gke').split(',')
    hours_back = int(os.environ.get('COLLECTION_INTERVAL_HOURS', '1'))

    collector = GCPLoggingCollector(project_id, gcs_bucket)

    results = {}

    if 'audit' in log_types:
        results['audit_logs'] = collector.collect_audit_logs(hours_back)

    if 'vpc_flow' in log_types:
        results['vpc_flow_logs'] = collector.collect_vpc_flow_logs(hours_back)

    if 'firewall' in log_types:
        results['firewall_logs'] = collector.collect_firewall_logs(hours_back)

    if 'gke' in log_types:
        results['gke_audit_logs'] = collector.collect_gke_audit_logs(hours_back)

    print(f"Collection complete: {json.dumps(results)}")
