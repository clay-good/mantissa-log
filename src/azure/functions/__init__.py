"""
Mantissa Log - Azure Function Apps for SaaS Log Collection
"""

import os
import json
import logging
import azure.functions as func
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any
from azure.storage.blob import BlobServiceClient
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential
from collectors import OktaCollector, GitHubCollector, SlackCollector, get_secret

logger = logging.getLogger(__name__)

# Configuration from environment
STORAGE_ACCOUNT_NAME = os.environ.get('STORAGE_ACCOUNT_NAME')
COSMOS_ENDPOINT = os.environ.get('COSMOS_ENDPOINT')
COSMOS_DATABASE = os.environ.get('COSMOS_DATABASE')
KEY_VAULT_URI = os.environ.get('KEY_VAULT_URI')

# Initialize clients
credential = DefaultAzureCredential()
blob_service_client = BlobServiceClient(
    account_url=f"https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net",
    credential=credential
)
cosmos_client = CosmosClient(url=COSMOS_ENDPOINT, credential=credential)
database = cosmos_client.get_database_client(COSMOS_DATABASE)
checkpoint_container = database.get_container_client('collector_checkpoints')


def get_checkpoint(source_name: str) -> Dict[str, Any]:
    """Retrieve last checkpoint from Cosmos DB"""
    try:
        item = checkpoint_container.read_item(
            item=source_name,
            partition_key=source_name
        )
        return item
    except Exception:
        return {'id': source_name, 'last_fetch_time': None, 'cursor': None}


def save_checkpoint(source_name: str, checkpoint_data: Dict[str, Any]):
    """Save checkpoint to Cosmos DB"""
    checkpoint_data['id'] = source_name
    checkpoint_data['updated_at'] = datetime.utcnow().isoformat()
    checkpoint_container.upsert_item(checkpoint_data)


def write_to_blob_storage(data: List[Dict], source_name: str, data_type: str = 'normalized'):
    """Write collected logs to Azure Blob Storage"""
    now = datetime.utcnow()

    # Partition path
    container_name = 'logs-hot'
    blob_path = f"{source_name}/{data_type}/{now.year:04d}/{now.month:02d}/{now.day:02d}/{now.hour:02d}{now.minute:02d}{now.second:02d}.json"

    container_client = blob_service_client.get_container_client(container_name)
    blob_client = container_client.get_blob_client(blob_path)

    # Write as newline-delimited JSON
    content = '\n'.join(json.dumps(record) for record in data)
    blob_client.upload_blob(content, overwrite=True)

    logger.info(f"Wrote {len(data)} records to {container_name}/{blob_path}")


app = func.FunctionApp()


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False)
def okta_collector(timer: func.TimerRequest) -> None:
    """Okta System Logs collector"""
    try:
        checkpoint = get_checkpoint('okta')
        last_fetch = checkpoint.get('last_fetch_time')

        # Get secrets
        api_token = get_secret(KEY_VAULT_URI, 'okta-token')
        org_url = os.environ.get('OKTA_ORG_URL')

        # Initialize collector
        collector = OktaCollector(api_token, org_url)

        # Fetch logs
        now = datetime.now(timezone.utc)
        if not last_fetch:
            last_fetch = (now - timedelta(minutes=15)).isoformat()

        events = collector.fetch_system_logs(since=last_fetch, until=now.isoformat())

        # Write to Blob Storage
        if events:
            write_to_blob_storage(events, 'okta', 'raw')
            latest_timestamp = events[-1].get('published', now.isoformat())
            save_checkpoint('okta', {'last_fetch_time': latest_timestamp})

        logger.info(f"Okta collector completed: {len(events)} events collected")
    except Exception as e:
        logger.error(f"Error collecting Okta logs: {e}")
        raise


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False)
def google_workspace_collector(timer: func.TimerRequest) -> None:
    """Google Workspace collector"""
    try:
        checkpoint = get_checkpoint('google_workspace')
        logger.info(f"Google Workspace collector triggered at {datetime.utcnow()}")
        logger.info("Google Workspace collector stub - implementation pending")
    except Exception as e:
        logger.error(f"Error collecting Google Workspace logs: {e}")
        raise


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False)
def microsoft365_collector(timer: func.TimerRequest) -> None:
    """Microsoft 365 collector"""
    try:
        checkpoint = get_checkpoint('microsoft365')
        logger.info(f"Microsoft 365 collector triggered at {datetime.utcnow()}")
        logger.info("Microsoft 365 collector stub - implementation pending")
    except Exception as e:
        logger.error(f"Error collecting Microsoft 365 logs: {e}")
        raise


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False)
def github_collector(timer: func.TimerRequest) -> None:
    """GitHub Enterprise collector"""
    try:
        checkpoint = get_checkpoint('github')
        last_timestamp = checkpoint.get('last_fetch_time')

        # Get secrets
        api_token = get_secret(KEY_VAULT_URI, 'github-token')
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

        # Write to Blob Storage
        if events:
            write_to_blob_storage(events, 'github', 'raw')
            latest_timestamp = max(event.get('@timestamp', 0) for event in events)
            save_checkpoint('github', {'last_fetch_time': latest_timestamp})

        logger.info(f"GitHub collector completed: {len(events)} events collected")
    except Exception as e:
        logger.error(f"Error collecting GitHub logs: {e}")
        raise


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False)
def slack_collector(timer: func.TimerRequest) -> None:
    """Slack Audit Logs collector"""
    try:
        checkpoint = get_checkpoint('slack')
        last_timestamp = checkpoint.get('last_fetch_time')

        # Get secrets
        api_token = get_secret(KEY_VAULT_URI, 'slack-token')

        # Initialize collector
        collector = SlackCollector(api_token)

        # Determine time range
        if not last_timestamp:
            oldest = int((datetime.now(timezone.utc) - timedelta(hours=24)).timestamp())
        else:
            oldest = int(last_timestamp)

        # Fetch logs
        entries = collector.fetch_audit_logs(oldest=oldest)

        # Write to Blob Storage
        if entries:
            write_to_blob_storage(entries, 'slack', 'raw')
            latest_timestamp = max(entry['date_create'] for entry in entries)
            save_checkpoint('slack', {'last_fetch_time': latest_timestamp})

        logger.info(f"Slack collector completed: {len(entries)} entries collected")
    except Exception as e:
        logger.error(f"Error collecting Slack logs: {e}")
        raise


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False)
def duo_collector(timer: func.TimerRequest) -> None:
    """Duo Security collector"""
    try:
        checkpoint = get_checkpoint('duo')
        logger.info(f"Duo collector triggered at {datetime.utcnow()}")
        logger.info("Duo collector stub - implementation pending")
    except Exception as e:
        logger.error(f"Error collecting Duo logs: {e}")
        raise


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False)
def crowdstrike_collector(timer: func.TimerRequest) -> None:
    """CrowdStrike Falcon collector"""
    try:
        checkpoint = get_checkpoint('crowdstrike')
        logger.info(f"CrowdStrike collector triggered at {datetime.utcnow()}")
        logger.info("CrowdStrike collector stub - implementation pending")
    except Exception as e:
        logger.error(f"Error collecting CrowdStrike logs: {e}")
        raise


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False)
def salesforce_collector(timer: func.TimerRequest) -> None:
    """Salesforce EventLogFile collector"""
    try:
        checkpoint = get_checkpoint('salesforce')
        logger.info(f"Salesforce collector triggered at {datetime.utcnow()}")
        logger.info("Salesforce collector stub - implementation pending")
    except Exception as e:
        logger.error(f"Error collecting Salesforce logs: {e}")
        raise


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False)
def snowflake_collector(timer: func.TimerRequest) -> None:
    """Snowflake audit logs collector"""
    try:
        checkpoint = get_checkpoint('snowflake')
        logger.info(f"Snowflake collector triggered at {datetime.utcnow()}")
        logger.info("Snowflake collector stub - implementation pending")
    except Exception as e:
        logger.error(f"Error collecting Snowflake logs: {e}")
        raise


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False)
def docker_collector(timer: func.TimerRequest) -> None:
    """Docker container events collector"""
    try:
        checkpoint = get_checkpoint('docker')
        logger.info(f"Docker collector triggered at {datetime.utcnow()}")
        logger.info("Docker collector stub - implementation pending")
    except Exception as e:
        logger.error(f"Error collecting Docker logs: {e}")
        raise


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False)
def kubernetes_collector(timer: func.TimerRequest) -> None:
    """Kubernetes audit logs collector"""
    try:
        checkpoint = get_checkpoint('kubernetes')
        logger.info(f"Kubernetes collector triggered at {datetime.utcnow()}")
        logger.info("Kubernetes collector stub - implementation pending")
    except Exception as e:
        logger.error(f"Error collecting Kubernetes logs: {e}")
        raise


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False)
def jamf_collector(timer: func.TimerRequest) -> None:
    """Jamf Pro device management collector"""
    try:
        checkpoint = get_checkpoint('jamf')
        logger.info(f"Jamf collector triggered at {datetime.utcnow()}")
        logger.info("Jamf collector stub - implementation pending")
    except Exception as e:
        logger.error(f"Error collecting Jamf logs: {e}")
        raise


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False)
def onepassword_collector(timer: func.TimerRequest) -> None:
    """1Password Events API collector"""
    try:
        checkpoint = get_checkpoint('onepassword')
        logger.info(f"1Password collector triggered at {datetime.utcnow()}")
        logger.info("1Password collector stub - implementation pending")
    except Exception as e:
        logger.error(f"Error collecting 1Password logs: {e}")
        raise


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False)
def azure_monitor_collector(timer: func.TimerRequest) -> None:
    """Azure Monitor logs collector"""
    try:
        checkpoint = get_checkpoint('azure_monitor')
        logger.info(f"Azure Monitor collector triggered at {datetime.utcnow()}")
        logger.info("Azure Monitor collector stub - implementation pending")
    except Exception as e:
        logger.error(f"Error collecting Azure Monitor logs: {e}")
        raise


@app.timer_trigger(schedule="%COLLECTION_SCHEDULE%", arg_name="timer", run_on_startup=False)
def gcp_logging_collector(timer: func.TimerRequest) -> None:
    """GCP Cloud Logging collector"""
    try:
        checkpoint = get_checkpoint('gcp_logging')
        logger.info(f"GCP Cloud Logging collector triggered at {datetime.utcnow()}")
        logger.info("GCP Cloud Logging collector stub - implementation pending")
    except Exception as e:
        logger.error(f"Error collecting GCP logs: {e}")
        raise
