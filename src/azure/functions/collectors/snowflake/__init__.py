"""Azure Function handler for Snowflake log collection."""

import azure.functions as func
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient

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
    source: str = "snowflake"
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


class SnowflakeCollector:
    """Collector for Snowflake Query History and Access History."""

    def __init__(self, account: str, user: str, password: str, warehouse: str, database: str = None):
        """Initialize with Snowflake credentials."""
        self.account = account
        self.user = user
        self.password = password
        self.warehouse = warehouse
        self.database = database or "SNOWFLAKE"
        self.connection = None

    def connect(self) -> None:
        """Connect to Snowflake."""
        try:
            import snowflake.connector
            self.connection = snowflake.connector.connect(
                account=self.account,
                user=self.user,
                password=self.password,
                warehouse=self.warehouse,
                database=self.database,
                schema="ACCOUNT_USAGE"
            )
        except ImportError:
            raise ImportError("snowflake-connector-python is required")

    def close(self) -> None:
        """Close the Snowflake connection."""
        if self.connection:
            self.connection.close()
            self.connection = None

    def fetch_query_history(self, start_time: datetime = None, end_time: datetime = None) -> List[Dict]:
        """Fetch query history from Snowflake."""
        if not self.connection:
            self.connect()

        if not end_time:
            end_time = datetime.now(timezone.utc)
        if not start_time:
            start_time = end_time - timedelta(hours=1)

        query = """
        SELECT
            QUERY_ID,
            QUERY_TEXT,
            DATABASE_NAME,
            SCHEMA_NAME,
            QUERY_TYPE,
            SESSION_ID,
            USER_NAME,
            ROLE_NAME,
            WAREHOUSE_NAME,
            WAREHOUSE_SIZE,
            WAREHOUSE_TYPE,
            CLUSTER_NUMBER,
            QUERY_TAG,
            EXECUTION_STATUS,
            ERROR_CODE,
            ERROR_MESSAGE,
            START_TIME,
            END_TIME,
            TOTAL_ELAPSED_TIME,
            BYTES_SCANNED,
            ROWS_PRODUCED,
            COMPILATION_TIME,
            EXECUTION_TIME,
            QUEUED_PROVISIONING_TIME,
            QUEUED_OVERLOAD_TIME,
            TRANSACTION_BLOCKED_TIME,
            CREDITS_USED_CLOUD_SERVICES
        FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
        WHERE START_TIME >= %s AND START_TIME < %s
        ORDER BY START_TIME DESC
        """

        cursor = self.connection.cursor()
        cursor.execute(query, (start_time, end_time))

        columns = [desc[0] for desc in cursor.description]
        events = []
        for row in cursor.fetchall():
            event = dict(zip(columns, row))
            # Convert datetime objects to ISO format
            for key, value in event.items():
                if isinstance(value, datetime):
                    event[key] = value.isoformat()
            event["_event_type"] = "query_history"
            events.append(event)

        cursor.close()
        return events

    def fetch_login_history(self, start_time: datetime = None, end_time: datetime = None) -> List[Dict]:
        """Fetch login history from Snowflake."""
        if not self.connection:
            self.connect()

        if not end_time:
            end_time = datetime.now(timezone.utc)
        if not start_time:
            start_time = end_time - timedelta(hours=1)

        query = """
        SELECT
            EVENT_ID,
            EVENT_TIMESTAMP,
            EVENT_TYPE,
            USER_NAME,
            CLIENT_IP,
            REPORTED_CLIENT_TYPE,
            REPORTED_CLIENT_VERSION,
            FIRST_AUTHENTICATION_FACTOR,
            SECOND_AUTHENTICATION_FACTOR,
            IS_SUCCESS,
            ERROR_CODE,
            ERROR_MESSAGE
        FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
        WHERE EVENT_TIMESTAMP >= %s AND EVENT_TIMESTAMP < %s
        ORDER BY EVENT_TIMESTAMP DESC
        """

        cursor = self.connection.cursor()
        cursor.execute(query, (start_time, end_time))

        columns = [desc[0] for desc in cursor.description]
        events = []
        for row in cursor.fetchall():
            event = dict(zip(columns, row))
            for key, value in event.items():
                if isinstance(value, datetime):
                    event[key] = value.isoformat()
            event["_event_type"] = "login_history"
            events.append(event)

        cursor.close()
        return events

    def fetch_access_history(self, start_time: datetime = None, end_time: datetime = None) -> List[Dict]:
        """Fetch access history (data access events) from Snowflake."""
        if not self.connection:
            self.connect()

        if not end_time:
            end_time = datetime.now(timezone.utc)
        if not start_time:
            start_time = end_time - timedelta(hours=1)

        query = """
        SELECT
            QUERY_ID,
            QUERY_START_TIME,
            USER_NAME,
            DIRECT_OBJECTS_ACCESSED,
            BASE_OBJECTS_ACCESSED,
            OBJECTS_MODIFIED,
            OBJECT_MODIFIED_BY_DDL,
            POLICIES_REFERENCED
        FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY
        WHERE QUERY_START_TIME >= %s AND QUERY_START_TIME < %s
        ORDER BY QUERY_START_TIME DESC
        """

        cursor = self.connection.cursor()
        cursor.execute(query, (start_time, end_time))

        columns = [desc[0] for desc in cursor.description]
        events = []
        for row in cursor.fetchall():
            event = dict(zip(columns, row))
            for key, value in event.items():
                if isinstance(value, datetime):
                    event[key] = value.isoformat()
                elif isinstance(value, (list, dict)):
                    event[key] = json.dumps(value)
            event["_event_type"] = "access_history"
            events.append(event)

        cursor.close()
        return events


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function handler for Snowflake log collection."""
    logger.info("Processing Snowflake log collection request")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    sf_creds_secret = os.environ.get("SNOWFLAKE_CREDS_SECRET", "snowflake-credentials")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    try:
        body = req.get_json() if req.get_body() else {}
        hours_back = body.get("hours_back", 1)
        event_types = body.get("event_types", ["query_history", "login_history", "access_history"])
    except ValueError:
        hours_back = 1
        event_types = ["query_history", "login_history", "access_history"]

    try:
        # Get credentials from Key Vault
        creds_json = get_secret(key_vault_url, sf_creds_secret)
        creds = json.loads(creds_json)

        collector = SnowflakeCollector(
            account=creds["account"],
            user=creds["user"],
            password=creds["password"],
            warehouse=creds.get("warehouse", "COMPUTE_WH"),
            database=creds.get("database", "SNOWFLAKE")
        )

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)

        all_events = []

        if "query_history" in event_types:
            query_events = collector.fetch_query_history(start_time, end_time)
            all_events.extend(query_events)
            logger.info(f"Fetched {len(query_events)} query history events")

        if "login_history" in event_types:
            login_events = collector.fetch_login_history(start_time, end_time)
            all_events.extend(login_events)
            logger.info(f"Fetched {len(login_events)} login history events")

        if "access_history" in event_types:
            access_events = collector.fetch_access_history(start_time, end_time)
            all_events.extend(access_events)
            logger.info(f"Fetched {len(access_events)} access history events")

        collector.close()

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
        logger.error(f"Error collecting Snowflake logs: {e}")
        return func.HttpResponse(
            json.dumps({"success": False, "error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )


def timer_trigger(timer: func.TimerRequest) -> None:
    """Timer trigger for scheduled Snowflake log collection."""
    logger.info("Timer trigger fired for Snowflake collector")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    sf_creds_secret = os.environ.get("SNOWFLAKE_CREDS_SECRET", "snowflake-credentials")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    try:
        creds_json = get_secret(key_vault_url, sf_creds_secret)
        creds = json.loads(creds_json)

        collector = SnowflakeCollector(
            account=creds["account"],
            user=creds["user"],
            password=creds["password"],
            warehouse=creds.get("warehouse", "COMPUTE_WH"),
            database=creds.get("database", "SNOWFLAKE")
        )

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=1)

        all_events = []
        all_events.extend(collector.fetch_query_history(start_time, end_time))
        all_events.extend(collector.fetch_login_history(start_time, end_time))
        all_events.extend(collector.fetch_access_history(start_time, end_time))

        collector.close()

        if all_events:
            upload_to_blob(
                connection_string=storage_connection_string,
                container_name=container_name,
                events=all_events,
                timestamp=datetime.now(timezone.utc)
            )
            logger.info(f"Collected and uploaded {len(all_events)} Snowflake events")

    except Exception as e:
        logger.error(f"Error in timer trigger: {e}")
        raise
