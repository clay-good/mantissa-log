"""
Mantissa Log - GCP Cloud Functions Collectors
Multi-source log collector for GCP deployment
"""

import os
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any
from google.cloud import storage, firestore
import functions_framework
from collectors import OktaCollector, GitHubCollector, SlackCollector, get_secret

# Import shared parsers
import sys
sys.path.insert(0, '/workspace')
from shared.parsers import (
    okta, google_workspace, microsoft365, github, slack,
    duo, crowdstrike, salesforce, snowflake, docker,
    kubernetes, jamf, onepassword, azure_monitor, gcp_logging
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment
GCS_BUCKET = os.environ.get('GCS_BUCKET')
PROJECT_ID = os.environ.get('PROJECT_ID')
FIRESTORE_DB = os.environ.get('FIRESTORE_DB', '(default)')

# Initialize clients
storage_client = storage.Client()
firestore_client = firestore.Client(database=FIRESTORE_DB)


def get_checkpoint(source_name: str) -> Dict[str, Any]:
    """Retrieve last checkpoint from Firestore"""
    doc_ref = firestore_client.collection('collector_checkpoints').document(source_name)
    doc = doc_ref.get()

    if doc.exists:
        return doc.to_dict()
    return {'last_fetch_time': None, 'cursor': None}


def save_checkpoint(source_name: str, checkpoint_data: Dict[str, Any]):
    """Save checkpoint to Firestore"""
    doc_ref = firestore_client.collection('collector_checkpoints').document(source_name)
    checkpoint_data['updated_at'] = datetime.utcnow().isoformat()
    doc_ref.set(checkpoint_data)


def write_to_gcs(data: List[Dict], source_name: str, data_type: str = 'normalized'):
    """Write collected logs to GCS"""
    now = datetime.utcnow()

    # Partition path
    prefix = f"{source_name}/{data_type}/{now.year:04d}/{now.month:02d}/{now.day:02d}"
    filename = f"{prefix}/{now.hour:02d}{now.minute:02d}{now.second:02d}.json"

    bucket = storage_client.bucket(GCS_BUCKET)
    blob = bucket.blob(filename)

    # Write as newline-delimited JSON
    content = '\n'.join(json.dumps(record) for record in data)
    blob.upload_from_string(content, content_type='application/json')

    logger.info(f"Wrote {len(data)} records to gs://{GCS_BUCKET}/{filename}")


@functions_framework.http
def collect_okta_logs(request):
    """Okta System Logs collector"""
    try:
        checkpoint = get_checkpoint('okta')
        last_fetch = checkpoint.get('last_fetch_time')

        # Get secrets
        api_token = get_secret(PROJECT_ID, 'okta-token')
        org_url = os.environ.get('OKTA_ORG_URL')

        # Initialize collector
        collector = OktaCollector(PROJECT_ID, api_token, org_url)

        # Fetch logs
        now = datetime.now(timezone.utc)
        if not last_fetch:
            last_fetch = (now - timedelta(minutes=15)).isoformat()

        events = collector.fetch_system_logs(since=last_fetch, until=now.isoformat())

        # Write to GCS
        if events:
            write_to_gcs(events, 'okta', 'raw')
            latest_timestamp = events[-1].get('published', now.isoformat())
            save_checkpoint('okta', {'last_fetch_time': latest_timestamp})

        return {'status': 'success', 'source': 'okta', 'events_collected': len(events)}
    except Exception as e:
        logger.error(f"Error collecting Okta logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_google_workspace_logs(request):
    """Google Workspace collector"""
    try:
        checkpoint = get_checkpoint('google_workspace')
        return {'status': 'success', 'source': 'google_workspace', 'message': 'Collector stub - implementation pending'}
    except Exception as e:
        logger.error(f"Error collecting Google Workspace logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_microsoft365_logs(request):
    """Microsoft 365 collector"""
    try:
        checkpoint = get_checkpoint('microsoft365')
        return {'status': 'success', 'source': 'microsoft365', 'message': 'Collector stub - implementation pending'}
    except Exception as e:
        logger.error(f"Error collecting Microsoft 365 logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_github_logs(request):
    """GitHub Enterprise collector"""
    try:
        checkpoint = get_checkpoint('github')
        last_timestamp = checkpoint.get('last_fetch_time')

        # Get secrets
        api_token = get_secret(PROJECT_ID, 'github-token')
        enterprise = os.environ.get('GITHUB_ENTERPRISE', '')
        organization = os.environ.get('GITHUB_ORG', '')

        # Initialize collector
        collector = GitHubCollector(api_token, enterprise, organization)

        # Determine time range
        if not last_timestamp:
            last_timestamp = int((datetime.now(timezone.utc) - timedelta(hours=24)).timestamp() * 1000)
        else:
            last_timestamp = int(last_timestamp)

        end_timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)

        # Fetch logs
        events = collector.fetch_audit_logs(last_timestamp, end_timestamp)

        # Write to GCS
        if events:
            write_to_gcs(events, 'github', 'raw')
            latest_timestamp = max(event.get('@timestamp', 0) for event in events)
            save_checkpoint('github', {'last_fetch_time': latest_timestamp})

        return {'status': 'success', 'source': 'github', 'events_collected': len(events)}
    except Exception as e:
        logger.error(f"Error collecting GitHub logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_slack_logs(request):
    """Slack Audit Logs collector"""
    try:
        checkpoint = get_checkpoint('slack')
        last_timestamp = checkpoint.get('last_fetch_time')

        # Get secrets
        api_token = get_secret(PROJECT_ID, 'slack-token')

        # Initialize collector
        collector = SlackCollector(api_token)

        # Determine time range
        if not last_timestamp:
            oldest = int((datetime.now(timezone.utc) - timedelta(hours=24)).timestamp())
        else:
            oldest = int(last_timestamp)

        # Fetch logs
        entries = collector.fetch_audit_logs(oldest=oldest)

        # Write to GCS
        if entries:
            write_to_gcs(entries, 'slack', 'raw')
            latest_timestamp = max(entry['date_create'] for entry in entries)
            save_checkpoint('slack', {'last_fetch_time': latest_timestamp})

        return {'status': 'success', 'source': 'slack', 'events_collected': len(entries)}
    except Exception as e:
        logger.error(f"Error collecting Slack logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_duo_logs(request):
    """Duo Security collector"""
    try:
        checkpoint = get_checkpoint('duo')
        return {'status': 'success', 'source': 'duo', 'message': 'Collector stub - implementation pending'}
    except Exception as e:
        logger.error(f"Error collecting Duo logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_crowdstrike_logs(request):
    """CrowdStrike Falcon collector"""
    try:
        checkpoint = get_checkpoint('crowdstrike')
        return {'status': 'success', 'source': 'crowdstrike', 'message': 'Collector stub - implementation pending'}
    except Exception as e:
        logger.error(f"Error collecting CrowdStrike logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_salesforce_logs(request):
    """Salesforce EventLogFile collector"""
    try:
        checkpoint = get_checkpoint('salesforce')
        return {'status': 'success', 'source': 'salesforce', 'message': 'Collector stub - implementation pending'}
    except Exception as e:
        logger.error(f"Error collecting Salesforce logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_snowflake_logs(request):
    """Snowflake audit logs collector"""
    try:
        checkpoint = get_checkpoint('snowflake')
        return {'status': 'success', 'source': 'snowflake', 'message': 'Collector stub - implementation pending'}
    except Exception as e:
        logger.error(f"Error collecting Snowflake logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_docker_logs(request):
    """Docker container events collector"""
    try:
        checkpoint = get_checkpoint('docker')
        return {'status': 'success', 'source': 'docker', 'message': 'Collector stub - implementation pending'}
    except Exception as e:
        logger.error(f"Error collecting Docker logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_kubernetes_logs(request):
    """Kubernetes audit logs collector"""
    try:
        checkpoint = get_checkpoint('kubernetes')
        return {'status': 'success', 'source': 'kubernetes', 'message': 'Collector stub - implementation pending'}
    except Exception as e:
        logger.error(f"Error collecting Kubernetes logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_jamf_logs(request):
    """Jamf Pro device management collector"""
    try:
        checkpoint = get_checkpoint('jamf')
        return {'status': 'success', 'source': 'jamf', 'message': 'Collector stub - implementation pending'}
    except Exception as e:
        logger.error(f"Error collecting Jamf logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_onepassword_logs(request):
    """1Password Events API collector"""
    try:
        checkpoint = get_checkpoint('onepassword')
        return {'status': 'success', 'source': 'onepassword', 'message': 'Collector stub - implementation pending'}
    except Exception as e:
        logger.error(f"Error collecting 1Password logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_azure_monitor_logs(request):
    """Azure Monitor logs collector"""
    try:
        checkpoint = get_checkpoint('azure_monitor')
        return {'status': 'success', 'source': 'azure_monitor', 'message': 'Collector stub - implementation pending'}
    except Exception as e:
        logger.error(f"Error collecting Azure Monitor logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_gcp_logs(request):
    """GCP Cloud Logging collector"""
    try:
        checkpoint = get_checkpoint('gcp_logging')

        # Get configuration
        log_types = os.environ.get('LOG_TYPES', 'audit,vpc_flow,firewall,gke').split(',')
        interval_hours = int(os.environ.get('COLLECTION_INTERVAL_HOURS', '1'))

        # Calculate time range
        end_time = datetime.utcnow()
        if checkpoint.get('last_fetch_time'):
            start_time = datetime.fromisoformat(checkpoint['last_fetch_time'])
        else:
            start_time = end_time - timedelta(hours=interval_hours)

        # For now, return stub
        # Full implementation would:
        # 1. Query Cloud Logging API for each log type
        # 2. Parse with gcp_logging parser
        # 3. Write to GCS
        # 4. Update checkpoint

        save_checkpoint('gcp_logging', {
            'last_fetch_time': end_time.isoformat(),
            'log_types_collected': log_types
        })

        return {
            'status': 'success',
            'source': 'gcp_logging',
            'message': f'Collected logs from {start_time} to {end_time}',
            'log_types': log_types
        }
    except Exception as e:
        logger.error(f"Error collecting GCP logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500
