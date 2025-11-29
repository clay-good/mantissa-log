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
