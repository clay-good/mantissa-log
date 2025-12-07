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
from collectors import (
    OktaCollector, GitHubCollector, SlackCollector,
    Microsoft365Collector, CrowdStrikeCollector, DuoCollector,
    GoogleWorkspaceCollector, SalesforceCollector, SnowflakeCollector,
    JamfCollector, OnePasswordCollector, AzureMonitorCollector,
    get_secret
)

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
        last_fetch = checkpoint.get('last_fetch_time')

        # Get secrets
        credentials_json = get_secret(PROJECT_ID, 'google-workspace-credentials')
        customer_id = os.environ.get('GOOGLE_WORKSPACE_CUSTOMER_ID', 'my_customer')

        # Initialize collector
        collector = GoogleWorkspaceCollector(credentials_json, customer_id)

        # Determine time range
        now = datetime.now(timezone.utc)
        if last_fetch:
            start_time = datetime.fromisoformat(last_fetch.replace('Z', '+00:00'))
        else:
            start_time = now - timedelta(hours=24)

        # Fetch logs
        events = collector.fetch_audit_logs(start_time=start_time, end_time=now)

        # Write to GCS
        if events:
            write_to_gcs(events, 'google_workspace', 'raw')
            save_checkpoint('google_workspace', {'last_fetch_time': now.isoformat()})

        return {'status': 'success', 'source': 'google_workspace', 'events_collected': len(events)}
    except Exception as e:
        logger.error(f"Error collecting Google Workspace logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_microsoft365_logs(request):
    """Microsoft 365 collector"""
    try:
        checkpoint = get_checkpoint('microsoft365')
        last_fetch = checkpoint.get('last_fetch_time')

        # Get secrets
        tenant_id = get_secret(PROJECT_ID, 'microsoft365-tenant-id')
        client_id = get_secret(PROJECT_ID, 'microsoft365-client-id')
        client_secret = get_secret(PROJECT_ID, 'microsoft365-client-secret')

        # Initialize collector
        collector = Microsoft365Collector(tenant_id, client_id, client_secret)

        # Determine time range
        now = datetime.now(timezone.utc)
        if last_fetch:
            start_time = datetime.fromisoformat(last_fetch.replace('Z', '+00:00'))
        else:
            start_time = now - timedelta(hours=24)

        # Fetch logs
        events = collector.fetch_audit_logs(start_time=start_time, end_time=now)

        # Write to GCS
        if events:
            write_to_gcs(events, 'microsoft365', 'raw')
            save_checkpoint('microsoft365', {'last_fetch_time': now.isoformat()})

        return {'status': 'success', 'source': 'microsoft365', 'events_collected': len(events)}
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
        last_fetch = checkpoint.get('last_fetch_time')

        # Get secrets
        integration_key = get_secret(PROJECT_ID, 'duo-integration-key')
        secret_key = get_secret(PROJECT_ID, 'duo-secret-key')
        api_hostname = get_secret(PROJECT_ID, 'duo-api-hostname')

        # Initialize collector
        collector = DuoCollector(integration_key, secret_key, api_hostname)

        # Determine time range
        now = datetime.now(timezone.utc)
        maxtime = int(now.timestamp() * 1000)
        if last_fetch:
            mintime = int(last_fetch)
        else:
            mintime = maxtime - (24 * 60 * 60 * 1000)

        # Fetch logs
        events = collector.fetch_authentication_logs(mintime=mintime, maxtime=maxtime)

        # Write to GCS
        if events:
            write_to_gcs(events, 'duo', 'raw')
            save_checkpoint('duo', {'last_fetch_time': maxtime})

        return {'status': 'success', 'source': 'duo', 'events_collected': len(events)}
    except Exception as e:
        logger.error(f"Error collecting Duo logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_crowdstrike_logs(request):
    """CrowdStrike Falcon collector"""
    try:
        checkpoint = get_checkpoint('crowdstrike')
        last_fetch = checkpoint.get('last_fetch_time')

        # Get secrets
        client_id = get_secret(PROJECT_ID, 'crowdstrike-client-id')
        client_secret = get_secret(PROJECT_ID, 'crowdstrike-client-secret')
        cloud = os.environ.get('CROWDSTRIKE_CLOUD', 'us-1')

        # Initialize collector
        collector = CrowdStrikeCollector(client_id, client_secret, cloud)

        # Determine time range
        now = datetime.now(timezone.utc)
        if last_fetch:
            start_time = datetime.fromisoformat(last_fetch.replace('Z', '+00:00'))
        else:
            start_time = now - timedelta(hours=24)

        # Fetch detections
        events = collector.fetch_detections(start_time=start_time, end_time=now)

        # Write to GCS
        if events:
            write_to_gcs(events, 'crowdstrike', 'raw')
            save_checkpoint('crowdstrike', {'last_fetch_time': now.isoformat()})

        return {'status': 'success', 'source': 'crowdstrike', 'events_collected': len(events)}
    except Exception as e:
        logger.error(f"Error collecting CrowdStrike logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_salesforce_logs(request):
    """Salesforce EventLogFile collector"""
    try:
        checkpoint = get_checkpoint('salesforce')
        last_fetch = checkpoint.get('last_fetch_time')

        # Get secrets
        instance_url = get_secret(PROJECT_ID, 'salesforce-instance-url')
        client_id = get_secret(PROJECT_ID, 'salesforce-client-id')
        client_secret = get_secret(PROJECT_ID, 'salesforce-client-secret')
        username = get_secret(PROJECT_ID, 'salesforce-username')
        password = get_secret(PROJECT_ID, 'salesforce-password')
        security_token = get_secret(PROJECT_ID, 'salesforce-security-token')

        # Initialize collector
        collector = SalesforceCollector(
            instance_url=instance_url,
            client_id=client_id,
            client_secret=client_secret,
            username=username,
            password=password,
            security_token=security_token
        )

        # Determine time range
        now = datetime.now(timezone.utc)
        if last_fetch:
            start_time = datetime.fromisoformat(last_fetch.replace('Z', '+00:00'))
        else:
            start_time = now - timedelta(days=1)

        # Fetch logs
        events = collector.fetch_event_log_files(start_date=start_time, end_date=now)

        # Write to GCS
        if events:
            write_to_gcs(events, 'salesforce', 'raw')
            save_checkpoint('salesforce', {'last_fetch_time': now.isoformat()})

        return {'status': 'success', 'source': 'salesforce', 'events_collected': len(events)}
    except Exception as e:
        logger.error(f"Error collecting Salesforce logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_snowflake_logs(request):
    """Snowflake audit logs collector"""
    try:
        checkpoint = get_checkpoint('snowflake')
        last_fetch = checkpoint.get('last_fetch_time')

        # Get secrets
        account = get_secret(PROJECT_ID, 'snowflake-account')
        user = get_secret(PROJECT_ID, 'snowflake-user')
        password = get_secret(PROJECT_ID, 'snowflake-password')
        warehouse = os.environ.get('SNOWFLAKE_WAREHOUSE', 'COMPUTE_WH')

        # Initialize collector
        collector = SnowflakeCollector(account=account, user=user, password=password, warehouse=warehouse)

        # Determine time range
        now = datetime.now(timezone.utc)
        if last_fetch:
            start_time = datetime.fromisoformat(last_fetch.replace('Z', '+00:00'))
        else:
            start_time = now - timedelta(hours=24)

        # Fetch logs
        query_history = collector.fetch_query_history(start_time=start_time, end_time=now)
        login_history = collector.fetch_login_history(start_time=start_time, end_time=now)

        all_events = [{'_type': 'query', **e} for e in query_history] + [{'_type': 'login', **e} for e in login_history]

        # Write to GCS
        if all_events:
            write_to_gcs(all_events, 'snowflake', 'raw')
            save_checkpoint('snowflake', {'last_fetch_time': now.isoformat()})

        return {'status': 'success', 'source': 'snowflake', 'events_collected': len(all_events)}
    except Exception as e:
        logger.error(f"Error collecting Snowflake logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_docker_logs(request):
    """Docker container events collector via GCP Cloud Logging"""
    try:
        checkpoint = get_checkpoint('docker')
        last_fetch = checkpoint.get('last_fetch_time')

        from google.cloud import logging as cloud_logging
        client = cloud_logging.Client(project=PROJECT_ID)

        # Determine time range
        now = datetime.now(timezone.utc)
        if last_fetch:
            start_time = datetime.fromisoformat(last_fetch.replace('Z', '+00:00'))
        else:
            start_time = now - timedelta(hours=24)

        # Query for Docker/container logs from GKE or Cloud Run
        filter_str = f'''
            (resource.type="k8s_container" OR resource.type="cloud_run_revision")
            AND timestamp >= "{start_time.isoformat()}"
            AND timestamp <= "{now.isoformat()}"
        '''

        entries = list(client.list_entries(filter_=filter_str, max_results=10000))
        events = [{'timestamp': e.timestamp.isoformat(), 'payload': e.payload, 'resource': dict(e.resource.labels)} for e in entries]

        # Write to GCS
        if events:
            write_to_gcs(events, 'docker', 'raw')
            save_checkpoint('docker', {'last_fetch_time': now.isoformat()})

        return {'status': 'success', 'source': 'docker', 'events_collected': len(events)}
    except Exception as e:
        logger.error(f"Error collecting Docker logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_kubernetes_logs(request):
    """Kubernetes audit logs collector via GCP Cloud Logging"""
    try:
        checkpoint = get_checkpoint('kubernetes')
        last_fetch = checkpoint.get('last_fetch_time')

        from google.cloud import logging as cloud_logging
        client = cloud_logging.Client(project=PROJECT_ID)

        # Determine time range
        now = datetime.now(timezone.utc)
        if last_fetch:
            start_time = datetime.fromisoformat(last_fetch.replace('Z', '+00:00'))
        else:
            start_time = now - timedelta(hours=24)

        # Query for GKE audit logs
        filter_str = f'''
            (resource.type="k8s_cluster" OR resource.type="gke_cluster")
            AND protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
            AND timestamp >= "{start_time.isoformat()}"
            AND timestamp <= "{now.isoformat()}"
        '''

        entries = list(client.list_entries(filter_=filter_str, max_results=10000))
        events = [{'timestamp': e.timestamp.isoformat(), 'payload': e.payload, 'resource': dict(e.resource.labels)} for e in entries]

        # Write to GCS
        if events:
            write_to_gcs(events, 'kubernetes', 'raw')
            save_checkpoint('kubernetes', {'last_fetch_time': now.isoformat()})

        return {'status': 'success', 'source': 'kubernetes', 'events_collected': len(events)}
    except Exception as e:
        logger.error(f"Error collecting Kubernetes logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_jamf_logs(request):
    """Jamf Pro device management collector"""
    try:
        checkpoint = get_checkpoint('jamf')
        last_fetch = checkpoint.get('last_fetch_time')

        # Get secrets
        server_url = get_secret(PROJECT_ID, 'jamf-server-url')
        username = get_secret(PROJECT_ID, 'jamf-username')
        password = get_secret(PROJECT_ID, 'jamf-password')

        # Initialize collector
        collector = JamfCollector(server_url=server_url, username=username, password=password)

        # Determine time range
        now = datetime.now(timezone.utc)
        if last_fetch:
            start_time = datetime.fromisoformat(last_fetch.replace('Z', '+00:00'))
        else:
            start_time = now - timedelta(hours=24)

        # Fetch logs
        events = collector.fetch_audit_logs(start_date=start_time, end_date=now)

        # Write to GCS
        if events:
            write_to_gcs(events, 'jamf', 'raw')
            save_checkpoint('jamf', {'last_fetch_time': now.isoformat()})

        return {'status': 'success', 'source': 'jamf', 'events_collected': len(events)}
    except Exception as e:
        logger.error(f"Error collecting Jamf logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_onepassword_logs(request):
    """1Password Events API collector"""
    try:
        checkpoint = get_checkpoint('onepassword')
        last_fetch = checkpoint.get('last_fetch_time')

        # Get secrets
        api_token = get_secret(PROJECT_ID, 'onepassword-token')

        # Initialize collector
        collector = OnePasswordCollector(api_token=api_token)

        # Determine time range
        now = datetime.now(timezone.utc)
        if last_fetch:
            start_time = datetime.fromisoformat(last_fetch.replace('Z', '+00:00'))
        else:
            start_time = now - timedelta(hours=24)

        # Fetch logs
        signin_events = collector.fetch_sign_in_attempts(start_time=start_time, end_time=now)
        item_usages = collector.fetch_item_usages(start_time=start_time, end_time=now)

        all_events = [{'_type': 'signin', **e} for e in signin_events] + [{'_type': 'item_usage', **e} for e in item_usages]

        # Write to GCS
        if all_events:
            write_to_gcs(all_events, 'onepassword', 'raw')
            save_checkpoint('onepassword', {'last_fetch_time': now.isoformat()})

        return {'status': 'success', 'source': 'onepassword', 'events_collected': len(all_events)}
    except Exception as e:
        logger.error(f"Error collecting 1Password logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_azure_monitor_logs(request):
    """Azure Monitor logs collector"""
    try:
        checkpoint = get_checkpoint('azure_monitor')

        # Get secrets
        tenant_id = get_secret(PROJECT_ID, 'azure-tenant-id')
        client_id = get_secret(PROJECT_ID, 'azure-client-id')
        client_secret = get_secret(PROJECT_ID, 'azure-client-secret')
        workspace_id = get_secret(PROJECT_ID, 'azure-workspace-id')

        # Initialize collector
        collector = AzureMonitorCollector(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            workspace_id=workspace_id
        )

        # Fetch logs (last 24 hours)
        signin_logs = collector.fetch_signin_logs(timespan="PT24H")
        audit_logs = collector.fetch_audit_logs(timespan="PT24H")

        all_events = [{'_type': 'signin', **e} for e in signin_logs] + [{'_type': 'audit', **e} for e in audit_logs]

        # Write to GCS
        if all_events:
            write_to_gcs(all_events, 'azure_monitor', 'raw')
            save_checkpoint('azure_monitor', {'last_fetch_time': datetime.now(timezone.utc).isoformat()})

        return {'status': 'success', 'source': 'azure_monitor', 'events_collected': len(all_events)}
    except Exception as e:
        logger.error(f"Error collecting Azure Monitor logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500


@functions_framework.http
def collect_gcp_logs(request):
    """GCP Cloud Logging collector - collects audit, VPC flow, firewall, and GKE logs"""
    try:
        from google.cloud import logging_v2
        from google.cloud import storage

        # Get configuration
        project_id = os.environ.get('GCP_PROJECT_ID')
        gcs_bucket = os.environ.get('GCS_BUCKET')
        log_types = os.environ.get('LOG_TYPES', 'audit,vpc_flow,firewall,gke').split(',')
        interval_hours = int(os.environ.get('COLLECTION_INTERVAL_HOURS', '1'))

        checkpoint = get_checkpoint('gcp_logging')

        # Calculate time range
        end_time = datetime.utcnow()
        if checkpoint.get('last_fetch_time'):
            start_time = datetime.fromisoformat(checkpoint['last_fetch_time'])
        else:
            start_time = end_time - timedelta(hours=interval_hours)

        # Initialize clients
        logging_client = logging_v2.Client(project=project_id)
        storage_client = storage.Client(project=project_id)
        bucket = storage_client.bucket(gcs_bucket)

        total_events = 0
        collected_types = []

        # Log type to filter mapping
        log_filters = {
            'audit': 'logName:"cloudaudit.googleapis.com"',
            'vpc_flow': 'logName:"compute.googleapis.com/vpc_flows"',
            'firewall': 'logName:"compute.googleapis.com/firewall"',
            'gke': 'resource.type="k8s_cluster" OR resource.type="k8s_container"'
        }

        for log_type in log_types:
            log_type = log_type.strip()
            if log_type not in log_filters:
                continue

            try:
                # Build filter with time range
                time_filter = f'timestamp>="{start_time.isoformat()}Z" AND timestamp<"{end_time.isoformat()}Z"'
                full_filter = f'{log_filters[log_type]} AND {time_filter}'

                # Query logs
                entries = list(logging_client.list_entries(
                    resource_names=[f'projects/{project_id}'],
                    filter_=full_filter,
                    page_size=1000
                ))

                if entries:
                    # Parse and format entries
                    events = []
                    for entry in entries:
                        event = {
                            'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
                            'severity': entry.severity if hasattr(entry, 'severity') else None,
                            'log_name': entry.log_name,
                            'resource': {
                                'type': entry.resource.type if entry.resource else None,
                                'labels': dict(entry.resource.labels) if entry.resource and entry.resource.labels else {}
                            },
                            'payload': entry.payload if hasattr(entry, 'payload') else {},
                            '_log_type': log_type,
                            '_collected_at': datetime.utcnow().isoformat()
                        }
                        events.append(event)

                    # Write to GCS with partitioning
                    blob_path = (
                        f"gcp_logging/{log_type}/{end_time.year}/{end_time.month:02d}/"
                        f"{end_time.day:02d}/{end_time.hour:02d}/"
                        f"{end_time.strftime('%Y%m%d_%H%M%S')}.json"
                    )

                    blob = bucket.blob(blob_path)
                    content = '\n'.join(json.dumps(event) for event in events)
                    blob.upload_from_string(content, content_type='application/json')

                    total_events += len(events)
                    collected_types.append(log_type)
                    logger.info(f"Collected {len(events)} {log_type} events")

            except Exception as e:
                logger.error(f"Error collecting {log_type} logs: {e}")
                continue

        # Update checkpoint
        save_checkpoint('gcp_logging', {
            'last_fetch_time': end_time.isoformat(),
            'log_types_collected': collected_types,
            'events_collected': total_events
        })

        return {
            'status': 'success',
            'source': 'gcp_logging',
            'events_collected': total_events,
            'log_types': collected_types,
            'time_range': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            }
        }
    except Exception as e:
        logger.error(f"Error collecting GCP logs: {e}")
        return {'status': 'error', 'error': str(e)}, 500
