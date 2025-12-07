"""Azure Function handler for Azure Monitor log collection."""

import azure.functions as func
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

logger = logging.getLogger(__name__)


def get_secret(key_vault_url: str, secret_name: str) -> str:
    """Retrieve secret from Azure Key Vault."""
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=key_vault_url, credential=credential)
    secret = client.get_secret(secret_name)
    return secret.value


def upload_to_blob(
    connection_string: str,
    container_name: str,
    events: List[Dict],
    timestamp: datetime,
    source: str = "azure_monitor"
) -> str:
    """Upload events to Azure Blob Storage."""
    blob_service = BlobServiceClient.from_connection_string(connection_string)
    container = blob_service.get_container_client(container_name)

    blob_path = (
        f"{source}/{timestamp.year}/{timestamp.month:02d}/{timestamp.day:02d}/"
        f"{timestamp.hour:02d}/{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
    )

    content = "\n".join(json.dumps(event) for event in events)
    blob_client = container.get_blob_client(blob_path)
    blob_client.upload_blob(content, overwrite=True)

    return blob_path


class AzureMonitorCollector:
    """Collector for Azure Monitor Logs (Log Analytics)."""

    def __init__(self, workspace_id: str, credential=None):
        """Initialize with Log Analytics workspace ID."""
        self.workspace_id = workspace_id
        self.credential = credential or DefaultAzureCredential()
        self.client = LogsQueryClient(self.credential)

    def query_logs(self, query: str, timespan: timedelta = None) -> List[Dict]:
        """Execute a KQL query against Log Analytics."""
        if not timespan:
            timespan = timedelta(hours=1)

        response = self.client.query_workspace(
            workspace_id=self.workspace_id,
            query=query,
            timespan=timespan
        )

        events = []
        if response.status == LogsQueryStatus.SUCCESS:
            for table in response.tables:
                for row in table.rows:
                    event = dict(zip([col.name for col in table.columns], row))
                    # Convert datetime objects to ISO format
                    for key, value in event.items():
                        if isinstance(value, datetime):
                            event[key] = value.isoformat()
                    events.append(event)
        elif response.status == LogsQueryStatus.PARTIAL:
            logger.warning(f"Partial query results: {response.partial_error}")
            for table in response.partial_data:
                for row in table.rows:
                    event = dict(zip([col.name for col in table.columns], row))
                    for key, value in event.items():
                        if isinstance(value, datetime):
                            event[key] = value.isoformat()
                    events.append(event)

        return events

    def fetch_signin_logs(self, timespan: timedelta = None) -> List[Dict]:
        """Fetch Azure AD Sign-in logs."""
        query = """
        SigninLogs
        | project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,
                  Location, Status, ClientAppUsed, DeviceDetail,
                  ConditionalAccessStatus, RiskLevelAggregated, RiskState,
                  AuthenticationRequirement, MfaDetail
        | order by TimeGenerated desc
        """
        events = self.query_logs(query, timespan)
        for event in events:
            event["_event_type"] = "signin_log"
        return events

    def fetch_audit_logs(self, timespan: timedelta = None) -> List[Dict]:
        """Fetch Azure AD Audit logs."""
        query = """
        AuditLogs
        | project TimeGenerated, OperationName, Result, ResultDescription,
                  Category, LoggedByService, InitiatedBy, TargetResources,
                  AdditionalDetails, CorrelationId
        | order by TimeGenerated desc
        """
        events = self.query_logs(query, timespan)
        for event in events:
            event["_event_type"] = "audit_log"
        return events

    def fetch_activity_logs(self, timespan: timedelta = None) -> List[Dict]:
        """Fetch Azure Activity logs."""
        query = """
        AzureActivity
        | project TimeGenerated, OperationNameValue, CategoryValue,
                  ResourceGroup, ResourceProviderValue, ResourceId,
                  Caller, CallerIpAddress, Level, ActivityStatusValue,
                  Properties, CorrelationId
        | order by TimeGenerated desc
        """
        events = self.query_logs(query, timespan)
        for event in events:
            event["_event_type"] = "activity_log"
        return events

    def fetch_security_alerts(self, timespan: timedelta = None) -> List[Dict]:
        """Fetch Security Center alerts."""
        query = """
        SecurityAlert
        | project TimeGenerated, AlertName, AlertSeverity, Description,
                  ProviderName, ProductName, Tactics, Techniques,
                  Entities, Status, CompromisedEntity, ConfidenceLevel
        | order by TimeGenerated desc
        """
        events = self.query_logs(query, timespan)
        for event in events:
            event["_event_type"] = "security_alert"
        return events

    def fetch_security_events(self, timespan: timedelta = None) -> List[Dict]:
        """Fetch Windows Security Events."""
        query = """
        SecurityEvent
        | project TimeGenerated, EventID, Activity, Computer, Account,
                  AccountType, LogonType, IpAddress, Process, ProcessId,
                  SubjectUserName, TargetUserName, Status
        | order by TimeGenerated desc
        | take 10000
        """
        events = self.query_logs(query, timespan)
        for event in events:
            event["_event_type"] = "security_event"
        return events

    def fetch_defender_incidents(self, timespan: timedelta = None) -> List[Dict]:
        """Fetch Microsoft Defender incidents."""
        query = """
        SecurityIncident
        | project TimeGenerated, IncidentNumber, Title, Severity, Status,
                  Classification, ClassificationComment, Owner, Labels,
                  ProviderName, AlertsCount, BookmarksCount, CommentsCount
        | order by TimeGenerated desc
        """
        events = self.query_logs(query, timespan)
        for event in events:
            event["_event_type"] = "security_incident"
        return events


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function handler for Azure Monitor log collection."""
    logger.info("Processing Azure Monitor log collection request")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    workspace_id = os.environ.get("LOG_ANALYTICS_WORKSPACE_ID")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    try:
        body = req.get_json() if req.get_body() else {}
        hours_back = body.get("hours_back", 1)
        event_types = body.get("event_types", [
            "signin_logs", "audit_logs", "activity_logs",
            "security_alerts", "security_events"
        ])
    except ValueError:
        hours_back = 1
        event_types = [
            "signin_logs", "audit_logs", "activity_logs",
            "security_alerts", "security_events"
        ]

    try:
        # Use workspace ID from environment or request
        if not workspace_id:
            workspace_config = get_secret(key_vault_url, "log-analytics-workspace-id")
            workspace_id = workspace_config

        collector = AzureMonitorCollector(workspace_id=workspace_id)
        timespan = timedelta(hours=hours_back)

        all_events = []

        if "signin_logs" in event_types:
            signin_events = collector.fetch_signin_logs(timespan)
            all_events.extend(signin_events)
            logger.info(f"Fetched {len(signin_events)} sign-in log events")

        if "audit_logs" in event_types:
            audit_events = collector.fetch_audit_logs(timespan)
            all_events.extend(audit_events)
            logger.info(f"Fetched {len(audit_events)} audit log events")

        if "activity_logs" in event_types:
            activity_events = collector.fetch_activity_logs(timespan)
            all_events.extend(activity_events)
            logger.info(f"Fetched {len(activity_events)} activity log events")

        if "security_alerts" in event_types:
            alert_events = collector.fetch_security_alerts(timespan)
            all_events.extend(alert_events)
            logger.info(f"Fetched {len(alert_events)} security alert events")

        if "security_events" in event_types:
            security_events = collector.fetch_security_events(timespan)
            all_events.extend(security_events)
            logger.info(f"Fetched {len(security_events)} security events")

        if "security_incidents" in event_types:
            incident_events = collector.fetch_defender_incidents(timespan)
            all_events.extend(incident_events)
            logger.info(f"Fetched {len(incident_events)} security incidents")

        if all_events:
            blob_path = upload_to_blob(
                connection_string=storage_connection_string,
                container_name=container_name,
                events=all_events,
                timestamp=datetime.now(timezone.utc)
            )
        else:
            blob_path = None

        return func.HttpResponse(
            json.dumps({
                "success": True,
                "events_collected": len(all_events),
                "blob_path": blob_path
            }),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logger.error(f"Error collecting Azure Monitor logs: {e}")
        return func.HttpResponse(
            json.dumps({"success": False, "error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )


def timer_trigger(timer: func.TimerRequest) -> None:
    """Timer trigger for scheduled Azure Monitor log collection."""
    logger.info("Timer trigger fired for Azure Monitor collector")

    workspace_id = os.environ.get("LOG_ANALYTICS_WORKSPACE_ID")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    try:
        collector = AzureMonitorCollector(workspace_id=workspace_id)
        timespan = timedelta(hours=1)

        all_events = []
        all_events.extend(collector.fetch_signin_logs(timespan))
        all_events.extend(collector.fetch_audit_logs(timespan))
        all_events.extend(collector.fetch_activity_logs(timespan))
        all_events.extend(collector.fetch_security_alerts(timespan))
        all_events.extend(collector.fetch_security_events(timespan))

        if all_events:
            upload_to_blob(
                connection_string=storage_connection_string,
                container_name=container_name,
                events=all_events,
                timestamp=datetime.now(timezone.utc)
            )
            logger.info(f"Collected and uploaded {len(all_events)} Azure Monitor events")

    except Exception as e:
        logger.error(f"Error in timer trigger: {e}")
        raise
