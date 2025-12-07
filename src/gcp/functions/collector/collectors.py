"""
GCP Collector Implementations
Port of AWS Lambda collectors adapted for GCP Cloud Functions
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from google.cloud import secretmanager

logger = logging.getLogger(__name__)


def get_secret(project_id: str, secret_name: str) -> str:
    """Retrieve secret from Secret Manager"""
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode('UTF-8')


def create_session_with_retry() -> requests.Session:
    """Create requests session with retry logic"""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    return session


class OktaCollector:
    """Okta System Log API collector for GCP"""

    def __init__(self, project_id: str, api_token: str, org_url: str):
        self.api_token = api_token
        self.org_url = org_url.rstrip('/')
        self.session = create_session_with_retry()
        self.session.headers.update({
            'Authorization': f'SSWS {self.api_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })

    def fetch_system_logs(
        self,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: int = 1000
    ) -> List[Dict]:
        """Fetch system logs from Okta API"""
        if not since:
            since = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
        if not until:
            until = datetime.now(timezone.utc).isoformat()

        url = f"{self.org_url}/api/v1/logs"
        params = {
            'since': since,
            'until': until,
            'limit': limit,
            'sortOrder': 'ASCENDING'
        }

        all_events = []

        while url:
            try:
                response = self.session.get(url, params=params if params else None)
                response.raise_for_status()

                events = response.json()
                all_events.extend(events)

                # Check for next page
                next_link = response.links.get('next')
                if next_link:
                    url = next_link['url']
                    params = None
                else:
                    url = None

                logger.info(f"Fetched {len(events)} events (total: {len(all_events)})")

            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    retry_after = int(e.response.headers.get('X-Rate-Limit-Reset', 60))
                    logger.warning(f"Rate limit exceeded. Retry after {retry_after} seconds")
                    raise
                else:
                    logger.error(f"HTTP error: {str(e)}")
                    raise

        return all_events


class GitHubCollector:
    """GitHub Enterprise Audit Log collector for GCP"""

    def __init__(self, api_token: str, enterprise: str = None, organization: str = None):
        self.api_token = api_token
        self.enterprise = enterprise
        self.organization = organization
        self.session = create_session_with_retry()

        api_base = 'https://api.github.com'
        if self.enterprise:
            self.audit_endpoint = f'{api_base}/enterprises/{self.enterprise}/audit-log'
            self.source_key = f'github_enterprise_{self.enterprise}'
        elif self.organization:
            self.audit_endpoint = f'{api_base}/orgs/{self.organization}/audit-log'
            self.source_key = f'github_org_{self.organization}'
        else:
            raise ValueError("Either enterprise or organization must be specified")

    def fetch_audit_logs(
        self,
        start_timestamp: int,
        end_timestamp: Optional[int] = None
    ) -> List[Dict]:
        """Fetch audit logs within timestamp range"""
        if end_timestamp is None:
            end_timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)

        start_dt = datetime.fromtimestamp(start_timestamp / 1000, tz=timezone.utc)
        end_dt = datetime.fromtimestamp(end_timestamp / 1000, tz=timezone.utc)

        phrase = f"created:>={start_dt.strftime('%Y-%m-%d')} created:<={end_dt.strftime('%Y-%m-%d')}"

        headers = {
            'Authorization': f'Bearer {self.api_token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }

        params = {
            'phrase': phrase,
            'include': 'all',
            'order': 'asc',
            'per_page': 100
        }

        all_events = []
        page = 1

        try:
            while True:
                params['page'] = page
                response = self.session.get(
                    self.audit_endpoint,
                    headers=headers,
                    params=params
                )

                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    logger.warning(f"Rate limited, waiting {retry_after} seconds")
                    import time
                    time.sleep(retry_after)
                    continue

                response.raise_for_status()
                events = response.json()

                if not events:
                    break

                all_events.extend(events)
                logger.info(f"Fetched {len(events)} audit log events (page {page}, total: {len(all_events)})")

                link_header = response.headers.get('Link', '')
                if 'rel="next"' not in link_header:
                    break

                page += 1

            # Filter by exact timestamp
            filtered_events = [
                event for event in all_events
                if start_timestamp <= event.get('@timestamp', 0) <= end_timestamp
            ]

            return filtered_events

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch audit logs: {e}")
            raise


class SlackCollector:
    """Slack Audit Logs collector for GCP"""

    def __init__(self, api_token: str):
        self.api_token = api_token
        self.session = create_session_with_retry()
        self.endpoint = 'https://api.slack.com/api/audit/v1/logs'

    def fetch_audit_logs(
        self,
        oldest: Optional[int] = None,
        latest: Optional[int] = None,
        limit: int = 1000
    ) -> List[Dict]:
        """Fetch audit logs from Slack API"""
        if oldest is None:
            oldest = int((datetime.now(timezone.utc) - timedelta(minutes=30)).timestamp())

        headers = {
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json'
        }

        params = {
            'oldest': oldest,
            'limit': limit
        }

        if latest:
            params['latest'] = latest

        all_entries = []
        cursor = None

        try:
            while True:
                if cursor:
                    params['cursor'] = cursor

                response = self.session.get(
                    self.endpoint,
                    headers=headers,
                    params=params
                )

                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    logger.warning(f"Rate limited, waiting {retry_after} seconds")
                    import time
                    time.sleep(retry_after)
                    continue

                response.raise_for_status()
                data = response.json()

                if not data.get('ok'):
                    logger.error(f"Slack API error: {data.get('error')}")
                    break

                entries = data.get('entries', [])
                all_entries.extend(entries)

                logger.info(f"Fetched {len(entries)} audit log entries (total: {len(all_entries)})")

                response_metadata = data.get('response_metadata', {})
                cursor = response_metadata.get('next_cursor')

                if not cursor:
                    break

            return all_entries

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch audit logs: {e}")
            raise


class Microsoft365Collector:
    """Microsoft 365 Management Activity API collector for GCP"""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.session = create_session_with_retry()
        self.access_token = None
        self.token_expiry = None

    def _get_access_token(self) -> str:
        """Get OAuth2 access token for Microsoft Graph API."""
        if self.access_token and self.token_expiry and datetime.now(timezone.utc) < self.token_expiry:
            return self.access_token

        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"

        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://manage.office.com/.default"
        }

        response = self.session.post(token_url, data=data)
        response.raise_for_status()

        token_data = response.json()
        self.access_token = token_data["access_token"]
        expires_in = token_data.get("expires_in", 3600)
        self.token_expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 60)

        return self.access_token

    def fetch_audit_logs(
        self,
        content_types: List[str] = None,
        start_time: datetime = None,
        end_time: datetime = None
    ) -> List[Dict]:
        """Fetch audit logs from Microsoft 365 Management Activity API."""
        if content_types is None:
            content_types = [
                "Audit.AzureActiveDirectory",
                "Audit.Exchange",
                "Audit.SharePoint",
                "Audit.General"
            ]

        if end_time is None:
            end_time = datetime.now(timezone.utc)
        if start_time is None:
            start_time = end_time - timedelta(hours=24)

        token = self._get_access_token()
        headers = {"Authorization": f"Bearer {token}"}

        all_events = []

        for content_type in content_types:
            content_url = f"https://manage.office.com/api/v1.0/{self.tenant_id}/activity/feed/subscriptions/content"
            params = {
                "contentType": content_type,
                "startTime": start_time.strftime("%Y-%m-%dT%H:%M:%S"),
                "endTime": end_time.strftime("%Y-%m-%dT%H:%M:%S")
            }

            try:
                response = self.session.get(content_url, headers=headers, params=params)
                if response.status_code == 429:
                    continue
                response.raise_for_status()
                content_blobs = response.json()

                for blob in content_blobs:
                    content_uri = blob.get("contentUri")
                    if content_uri:
                        blob_response = self.session.get(content_uri, headers=headers)
                        if blob_response.status_code == 200:
                            events = blob_response.json()
                            for event in events:
                                event["_content_type"] = content_type
                            all_events.extend(events)

                logger.info(f"Fetched {len(content_blobs)} content blobs for {content_type}")

            except Exception as e:
                logger.error(f"Error fetching {content_type}: {e}")
                continue

        return all_events


class CrowdStrikeCollector:
    """CrowdStrike Falcon API collector for GCP"""

    CLOUD_URLS = {
        "us-1": "https://api.crowdstrike.com",
        "us-2": "https://api.us-2.crowdstrike.com",
        "eu-1": "https://api.eu-1.crowdstrike.com",
        "us-gov-1": "https://api.laggar.gcw.crowdstrike.com"
    }

    def __init__(self, client_id: str, client_secret: str, cloud: str = "us-1"):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = self.CLOUD_URLS.get(cloud, self.CLOUD_URLS["us-1"])
        self.session = create_session_with_retry()
        self.access_token = None
        self.token_expiry = None

    def _get_access_token(self) -> str:
        """Get OAuth2 access token for CrowdStrike API."""
        if self.access_token and self.token_expiry and datetime.now(timezone.utc) < self.token_expiry:
            return self.access_token

        token_url = f"{self.base_url}/oauth2/token"
        data = {"client_id": self.client_id, "client_secret": self.client_secret}

        response = self.session.post(token_url, data=data)
        response.raise_for_status()

        token_data = response.json()
        self.access_token = token_data["access_token"]
        expires_in = token_data.get("expires_in", 1800)
        self.token_expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 60)

        return self.access_token

    def fetch_detections(
        self,
        start_time: datetime = None,
        end_time: datetime = None,
        limit: int = 500
    ) -> List[Dict]:
        """Fetch detections from CrowdStrike Falcon API."""
        if end_time is None:
            end_time = datetime.now(timezone.utc)
        if start_time is None:
            start_time = end_time - timedelta(hours=24)

        token = self._get_access_token()
        headers = {"Authorization": f"Bearer {token}"}

        query_url = f"{self.base_url}/detects/queries/detects/v1"
        filter_str = f"last_behavior:>='{start_time.isoformat()}'+last_behavior:<='{end_time.isoformat()}'"

        params = {"filter": filter_str, "limit": limit, "sort": "last_behavior|asc"}

        all_detections = []
        offset = None

        while True:
            if offset:
                params["offset"] = offset

            response = self.session.get(query_url, headers=headers, params=params)
            if response.status_code == 429:
                import time
                time.sleep(60)
                continue

            response.raise_for_status()
            data = response.json()

            detection_ids = data.get("resources", [])
            if not detection_ids:
                break

            details_url = f"{self.base_url}/detects/entities/summaries/GET/v1"
            details_response = self.session.post(
                details_url, headers=headers, json={"ids": detection_ids}
            )
            details_response.raise_for_status()

            detections = details_response.json().get("resources", [])
            all_detections.extend(detections)

            logger.info(f"Fetched {len(detections)} detections (total: {len(all_detections)})")

            meta = data.get("meta", {}).get("pagination", {})
            offset = meta.get("offset")
            total = meta.get("total", 0)

            if not offset or len(all_detections) >= total:
                break

        return all_detections


class DuoCollector:
    """Duo Security Admin API collector for GCP"""

    def __init__(self, integration_key: str, secret_key: str, api_hostname: str):
        import hmac
        import hashlib
        import base64
        import email.utils
        from urllib.parse import urlencode

        self.integration_key = integration_key
        self.secret_key = secret_key
        self.api_hostname = api_hostname
        self.session = create_session_with_retry()
        self._hmac = hmac
        self._hashlib = hashlib
        self._base64 = base64
        self._email = email
        self._urlencode = urlencode

    def _sign_request(self, method: str, path: str, params: dict) -> Dict[str, str]:
        """Sign request using Duo's authentication scheme."""
        now = self._email.utils.formatdate()
        canon_params = self._urlencode(sorted(params.items()))

        canon = [now, method.upper(), self.api_hostname.lower(), path, canon_params]
        signature_string = "\n".join(canon)

        sig = self._hmac.new(
            self.secret_key.encode("utf-8"),
            signature_string.encode("utf-8"),
            self._hashlib.sha1
        )
        auth = f"{self.integration_key}:{sig.hexdigest()}"
        auth_header = f"Basic {self._base64.b64encode(auth.encode('utf-8')).decode('utf-8')}"

        return {"Date": now, "Authorization": auth_header}

    def fetch_authentication_logs(
        self,
        mintime: int = None,
        maxtime: int = None
    ) -> List[Dict]:
        """Fetch authentication logs from Duo Admin API."""
        if maxtime is None:
            maxtime = int(datetime.now(timezone.utc).timestamp() * 1000)
        if mintime is None:
            mintime = maxtime - (24 * 60 * 60 * 1000)

        path = "/admin/v2/logs/authentication"
        url = f"https://{self.api_hostname}{path}"

        all_logs = []
        next_offset = None

        while True:
            params = {"mintime": str(mintime), "maxtime": str(maxtime), "limit": "1000"}
            if next_offset:
                params["next_offset"] = next_offset

            headers = self._sign_request("GET", path, params)
            response = self.session.get(url, headers=headers, params=params)

            if response.status_code == 429:
                import time
                time.sleep(60)
                continue

            response.raise_for_status()
            data = response.json()

            if data.get("stat") != "OK":
                raise Exception(f"Duo API error: {data.get('message')}")

            logs = data.get("response", {}).get("authlogs", [])
            all_logs.extend(logs)

            logger.info(f"Fetched {len(logs)} authentication logs (total: {len(all_logs)})")

            metadata = data.get("response", {}).get("metadata", {})
            next_offset = metadata.get("next_offset")

            if not next_offset:
                break

        return all_logs


class GoogleWorkspaceCollector:
    """Google Workspace Admin Reports API collector"""

    def __init__(self, credentials_json: str, customer_id: str = "my_customer"):
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        self.customer_id = customer_id
        creds_dict = json.loads(credentials_json)
        credentials = service_account.Credentials.from_service_account_info(
            creds_dict,
            scopes=["https://www.googleapis.com/auth/admin.reports.audit.readonly"]
        )
        self.service = build("admin", "reports_v1", credentials=credentials)

    def fetch_audit_logs(
        self,
        application_names: List[str] = None,
        start_time: datetime = None,
        end_time: datetime = None
    ) -> List[Dict]:
        """Fetch audit logs from Google Workspace Admin Reports API."""
        if application_names is None:
            application_names = ["login", "admin", "drive", "token", "groups"]

        if end_time is None:
            end_time = datetime.now(timezone.utc)
        if start_time is None:
            start_time = end_time - timedelta(hours=24)

        all_events = []

        for app_name in application_names:
            try:
                page_token = None
                while True:
                    results = self.service.activities().list(
                        userKey="all",
                        applicationName=app_name,
                        customerId=self.customer_id,
                        startTime=start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        endTime=end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        maxResults=1000,
                        pageToken=page_token
                    ).execute()

                    items = results.get("items", [])
                    for item in items:
                        item["_application"] = app_name
                    all_events.extend(items)

                    logger.info(f"Fetched {len(items)} events for {app_name} (total: {len(all_events)})")

                    page_token = results.get("nextPageToken")
                    if not page_token:
                        break

            except Exception as e:
                logger.error(f"Error fetching {app_name} logs: {e}")
                continue

        return all_events


class SalesforceCollector:
    """Salesforce EventLogFile API collector"""

    def __init__(self, instance_url: str, access_token: str = None,
                 client_id: str = None, client_secret: str = None,
                 username: str = None, password: str = None, security_token: str = None):
        self.instance_url = instance_url.rstrip("/")
        self.session = create_session_with_retry()
        self.access_token = access_token

        if not access_token and client_id and client_secret:
            self._authenticate(client_id, client_secret, username, password, security_token)

    def _authenticate(self, client_id: str, client_secret: str,
                     username: str, password: str, security_token: str):
        """Authenticate using OAuth2 password flow."""
        token_url = f"{self.instance_url}/services/oauth2/token"
        data = {
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": client_secret,
            "username": username,
            "password": f"{password}{security_token}"
        }

        response = self.session.post(token_url, data=data)
        response.raise_for_status()
        token_data = response.json()
        self.access_token = token_data["access_token"]
        self.instance_url = token_data.get("instance_url", self.instance_url)

    def fetch_event_log_files(
        self,
        start_date: datetime = None,
        end_date: datetime = None,
        event_types: List[str] = None
    ) -> List[Dict]:
        """Fetch EventLogFile records from Salesforce."""
        if end_date is None:
            end_date = datetime.now(timezone.utc)
        if start_date is None:
            start_date = end_date - timedelta(days=1)

        headers = {"Authorization": f"Bearer {self.access_token}"}

        query = f"SELECT Id, EventType, LogDate, LogFileLength FROM EventLogFile WHERE LogDate >= {start_date.strftime('%Y-%m-%dT%H:%M:%SZ')} AND LogDate <= {end_date.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        if event_types:
            types_str = ",".join(f"'{t}'" for t in event_types)
            query += f" AND EventType IN ({types_str})"

        query_url = f"{self.instance_url}/services/data/v59.0/query"
        response = self.session.get(query_url, headers=headers, params={"q": query})
        response.raise_for_status()

        all_events = []
        records = response.json().get("records", [])

        for record in records:
            log_id = record["Id"]
            log_url = f"{self.instance_url}/services/data/v59.0/sobjects/EventLogFile/{log_id}/LogFile"

            log_response = self.session.get(log_url, headers=headers)
            if log_response.status_code == 200:
                import csv
                import io
                reader = csv.DictReader(io.StringIO(log_response.text))
                for row in reader:
                    row["_event_type"] = record["EventType"]
                    row["_log_date"] = record["LogDate"]
                    all_events.append(row)

            logger.info(f"Fetched log file {log_id} ({record['EventType']})")

        return all_events


class SnowflakeCollector:
    """Snowflake ACCOUNT_USAGE audit log collector"""

    def __init__(self, account: str, user: str, password: str,
                 warehouse: str = "COMPUTE_WH", database: str = "SNOWFLAKE"):
        import snowflake.connector
        self.conn = snowflake.connector.connect(
            account=account,
            user=user,
            password=password,
            warehouse=warehouse,
            database=database,
            schema="ACCOUNT_USAGE"
        )

    def fetch_query_history(
        self,
        start_time: datetime = None,
        end_time: datetime = None
    ) -> List[Dict]:
        """Fetch query history from ACCOUNT_USAGE."""
        if end_time is None:
            end_time = datetime.now(timezone.utc)
        if start_time is None:
            start_time = end_time - timedelta(hours=24)

        cursor = self.conn.cursor()
        query = f"""
        SELECT
            QUERY_ID, QUERY_TEXT, DATABASE_NAME, SCHEMA_NAME,
            USER_NAME, ROLE_NAME, WAREHOUSE_NAME,
            START_TIME, END_TIME, TOTAL_ELAPSED_TIME,
            BYTES_SCANNED, ROWS_PRODUCED, EXECUTION_STATUS, ERROR_MESSAGE
        FROM QUERY_HISTORY
        WHERE START_TIME >= '{start_time.isoformat()}'
          AND START_TIME <= '{end_time.isoformat()}'
        ORDER BY START_TIME
        """

        cursor.execute(query)
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        cursor.close()

        logger.info(f"Fetched {len(results)} query history records")
        return results

    def fetch_login_history(
        self,
        start_time: datetime = None,
        end_time: datetime = None
    ) -> List[Dict]:
        """Fetch login history from ACCOUNT_USAGE."""
        if end_time is None:
            end_time = datetime.now(timezone.utc)
        if start_time is None:
            start_time = end_time - timedelta(hours=24)

        cursor = self.conn.cursor()
        query = f"""
        SELECT
            EVENT_ID, EVENT_TIMESTAMP, EVENT_TYPE, USER_NAME,
            CLIENT_IP, REPORTED_CLIENT_TYPE, REPORTED_CLIENT_VERSION,
            FIRST_AUTHENTICATION_FACTOR, SECOND_AUTHENTICATION_FACTOR,
            IS_SUCCESS, ERROR_CODE, ERROR_MESSAGE
        FROM LOGIN_HISTORY
        WHERE EVENT_TIMESTAMP >= '{start_time.isoformat()}'
          AND EVENT_TIMESTAMP <= '{end_time.isoformat()}'
        ORDER BY EVENT_TIMESTAMP
        """

        cursor.execute(query)
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        cursor.close()

        logger.info(f"Fetched {len(results)} login history records")
        return results


class JamfCollector:
    """Jamf Pro API collector"""

    def __init__(self, server_url: str, username: str, password: str):
        self.server_url = server_url.rstrip("/")
        self.session = create_session_with_retry()
        self._authenticate(username, password)

    def _authenticate(self, username: str, password: str):
        """Authenticate to Jamf Pro API."""
        auth_url = f"{self.server_url}/api/v1/auth/token"
        response = self.session.post(auth_url, auth=(username, password))
        response.raise_for_status()
        self.access_token = response.json()["token"]
        self.session.headers.update({"Authorization": f"Bearer {self.access_token}"})

    def fetch_audit_logs(
        self,
        start_date: datetime = None,
        end_date: datetime = None
    ) -> List[Dict]:
        """Fetch audit logs from Jamf Pro."""
        if end_date is None:
            end_date = datetime.now(timezone.utc)
        if start_date is None:
            start_date = end_date - timedelta(hours=24)

        url = f"{self.server_url}/api/v1/jamf-pro-server-logs"
        params = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "sort": "date:asc"
        }

        response = self.session.get(url, params=params)
        response.raise_for_status()

        logs = response.json().get("results", [])
        logger.info(f"Fetched {len(logs)} Jamf audit logs")
        return logs

    def fetch_computer_inventory(self) -> List[Dict]:
        """Fetch computer inventory for context enrichment."""
        url = f"{self.server_url}/api/v1/computers-inventory"
        response = self.session.get(url)
        response.raise_for_status()

        computers = response.json().get("results", [])
        logger.info(f"Fetched {len(computers)} computer inventory records")
        return computers


class OnePasswordCollector:
    """1Password Events API collector"""

    def __init__(self, api_token: str, domain: str = "events.1password.com"):
        self.api_token = api_token
        self.domain = domain
        self.session = create_session_with_retry()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        })

    def fetch_sign_in_attempts(
        self,
        start_time: datetime = None,
        end_time: datetime = None
    ) -> List[Dict]:
        """Fetch sign-in attempt events."""
        if end_time is None:
            end_time = datetime.now(timezone.utc)
        if start_time is None:
            start_time = end_time - timedelta(hours=24)

        url = f"https://{self.domain}/api/v1/signinattempts"
        all_events = []
        cursor = None

        while True:
            payload = {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "limit": 1000
            }
            if cursor:
                payload["cursor"] = cursor

            response = self.session.post(url, json=payload)
            response.raise_for_status()
            data = response.json()

            items = data.get("items", [])
            all_events.extend(items)

            cursor = data.get("cursor")
            if not cursor or not items:
                break

        logger.info(f"Fetched {len(all_events)} 1Password sign-in events")
        return all_events

    def fetch_item_usages(
        self,
        start_time: datetime = None,
        end_time: datetime = None
    ) -> List[Dict]:
        """Fetch item usage events."""
        if end_time is None:
            end_time = datetime.now(timezone.utc)
        if start_time is None:
            start_time = end_time - timedelta(hours=24)

        url = f"https://{self.domain}/api/v1/itemusages"
        all_events = []
        cursor = None

        while True:
            payload = {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "limit": 1000
            }
            if cursor:
                payload["cursor"] = cursor

            response = self.session.post(url, json=payload)
            response.raise_for_status()
            data = response.json()

            items = data.get("items", [])
            all_events.extend(items)

            cursor = data.get("cursor")
            if not cursor or not items:
                break

        logger.info(f"Fetched {len(all_events)} 1Password item usage events")
        return all_events


class AzureMonitorCollector:
    """Azure Monitor Logs collector via Log Analytics API"""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str,
                 workspace_id: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.workspace_id = workspace_id
        self.session = create_session_with_retry()
        self.access_token = None
        self.token_expiry = None

    def _get_access_token(self) -> str:
        """Get OAuth2 access token for Azure Log Analytics."""
        if self.access_token and self.token_expiry and datetime.now(timezone.utc) < self.token_expiry:
            return self.access_token

        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://api.loganalytics.io/.default"
        }

        response = self.session.post(token_url, data=data)
        response.raise_for_status()

        token_data = response.json()
        self.access_token = token_data["access_token"]
        expires_in = token_data.get("expires_in", 3600)
        self.token_expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 60)

        return self.access_token

    def fetch_logs(
        self,
        query: str,
        timespan: str = "PT24H"
    ) -> List[Dict]:
        """Execute KQL query against Log Analytics workspace."""
        token = self._get_access_token()

        url = f"https://api.loganalytics.io/v1/workspaces/{self.workspace_id}/query"
        headers = {"Authorization": f"Bearer {token}"}
        payload = {"query": query, "timespan": timespan}

        response = self.session.post(url, headers=headers, json=payload)
        response.raise_for_status()

        data = response.json()
        tables = data.get("tables", [])

        all_records = []
        for table in tables:
            columns = [col["name"] for col in table.get("columns", [])]
            for row in table.get("rows", []):
                record = dict(zip(columns, row))
                all_records.append(record)

        logger.info(f"Fetched {len(all_records)} Azure Monitor records")
        return all_records

    def fetch_signin_logs(self, timespan: str = "PT24H") -> List[Dict]:
        """Fetch Azure AD sign-in logs."""
        query = """
        SigninLogs
        | project TimeGenerated, UserPrincipalName, AppDisplayName,
                  IPAddress, Location, Status, ConditionalAccessStatus,
                  DeviceDetail, RiskLevelAggregated
        | order by TimeGenerated desc
        """
        return self.fetch_logs(query, timespan)

    def fetch_audit_logs(self, timespan: str = "PT24H") -> List[Dict]:
        """Fetch Azure AD audit logs."""
        query = """
        AuditLogs
        | project TimeGenerated, OperationName, Category, Result,
                  InitiatedBy, TargetResources, AdditionalDetails
        | order by TimeGenerated desc
        """
        return self.fetch_logs(query, timespan)
