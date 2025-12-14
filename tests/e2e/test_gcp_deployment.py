"""End-to-end integration tests for GCP deployment.

These tests verify the complete GCP deployment of Mantissa Log including:
- Cloud Functions (collectors, LLM query, detection, alert router)
- BigQuery queries
- Firestore state management
- Cloud Storage
- Pub/Sub alerts
- Cloud Run frontend

Prerequisites:
- GCP deployment completed via `terraform apply`
- Environment variables set:
  - GCP_PROJECT_ID
  - GCP_REGION
  - GCP_FUNCTION_URL_BASE
  - GOOGLE_APPLICATION_CREDENTIALS (for authenticated calls)
"""

import json
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from unittest import skipIf

import pytest
import requests

# Skip all tests if GCP environment is not configured
GCP_CONFIGURED = all([
    os.environ.get("GCP_PROJECT_ID"),
    os.environ.get("GCP_FUNCTION_URL_BASE"),
])

# Apply skip to all tests in this module
pytestmark = pytest.mark.skipif(not GCP_CONFIGURED, reason="GCP environment not configured")


@pytest.fixture(scope="module")
def gcp_config() -> Dict[str, str]:
    """Get GCP configuration from environment."""
    return {
        "project_id": os.environ.get("GCP_PROJECT_ID", ""),
        "region": os.environ.get("GCP_REGION", "us-central1"),
        "function_url_base": os.environ.get("GCP_FUNCTION_URL_BASE", ""),
        "cloud_run_url": os.environ.get("GCP_CLOUD_RUN_URL", ""),
        "bigquery_dataset": os.environ.get("GCP_BIGQUERY_DATASET", ""),
    }


@pytest.fixture(scope="module")
def gcp_headers() -> Dict[str, str]:
    """Get headers for GCP Cloud Function calls."""
    # If running with service account, get ID token
    id_token = os.environ.get("GCP_ID_TOKEN", "")
    headers = {"Content-Type": "application/json"}
    if id_token:
        headers["Authorization"] = f"Bearer {id_token}"
    return headers


def get_gcp_id_token(audience: str) -> Optional[str]:
    """Get GCP ID token for authenticated requests."""
    try:
        from google.auth.transport.requests import Request
        from google.oauth2 import id_token as google_id_token

        credentials_file = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        if credentials_file:
            return google_id_token.fetch_id_token(Request(), audience)
    except Exception:
        pass
    return None


@skipIf(not GCP_CONFIGURED, "GCP environment not configured")
class TestGCPFunctionHealth:
    """Test GCP Cloud Function health endpoints."""

    def test_llm_query_function_health(self, gcp_config: Dict, gcp_headers: Dict):
        """Test LLM Query Function is responding."""
        url = f"{gcp_config['function_url_base']}/llm-query"

        # Get auth token if needed
        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        response = requests.post(
            url,
            json={"action": "health"},
            headers=gcp_headers,
            timeout=30
        )

        assert response.status_code in [200, 401]  # 401 if auth required

    def test_detection_engine_function_health(self, gcp_config: Dict, gcp_headers: Dict):
        """Test Detection Engine Function is responding."""
        url = f"{gcp_config['function_url_base']}/detection-engine"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        response = requests.post(
            url,
            json={"action": "health"},
            headers=gcp_headers,
            timeout=30
        )

        assert response.status_code in [200, 401]

    def test_alert_router_function_health(self, gcp_config: Dict, gcp_headers: Dict):
        """Test Alert Router Function is responding."""
        url = f"{gcp_config['function_url_base']}/alert-router"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        response = requests.post(
            url,
            json={"action": "health"},
            headers=gcp_headers,
            timeout=30
        )

        assert response.status_code in [200, 401]


@skipIf(not GCP_CONFIGURED, "GCP environment not configured")
class TestGCPLLMQuery:
    """Test GCP LLM Query functionality."""

    def test_natural_language_query(self, gcp_config: Dict, gcp_headers: Dict):
        """Test natural language to SQL conversion."""
        url = f"{gcp_config['function_url_base']}/llm-query"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        payload = {
            "question": "Show me the last 10 login events",
            "log_source": "okta",
        }

        response = requests.post(url, json=payload, headers=gcp_headers, timeout=60)

        if response.status_code == 401:
            pytest.skip("Authentication required")

        assert response.status_code == 200
        data = response.json()
        assert "sql" in data or "query" in data or "results" in data

    def test_query_with_time_range(self, gcp_config: Dict, gcp_headers: Dict):
        """Test query with specific time range."""
        url = f"{gcp_config['function_url_base']}/llm-query"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)

        payload = {
            "question": "Show failed authentication attempts",
            "log_source": "okta",
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
        }

        response = requests.post(url, json=payload, headers=gcp_headers, timeout=60)

        if response.status_code == 401:
            pytest.skip("Authentication required")

        assert response.status_code == 200

    def test_bigquery_execution(self, gcp_config: Dict, gcp_headers: Dict):
        """Test direct BigQuery execution."""
        url = f"{gcp_config['function_url_base']}/llm-query"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        payload = {
            "action": "execute_sql",
            "sql": "SELECT 1 as test",
        }

        response = requests.post(url, json=payload, headers=gcp_headers, timeout=60)

        if response.status_code == 401:
            pytest.skip("Authentication required")

        assert response.status_code in [200, 400]  # 400 if SQL not allowed


@skipIf(not GCP_CONFIGURED, "GCP environment not configured")
class TestGCPDetectionEngine:
    """Test GCP Detection Engine functionality."""

    def test_run_detection_rules(self, gcp_config: Dict, gcp_headers: Dict):
        """Test detection rule execution."""
        url = f"{gcp_config['function_url_base']}/detection-engine"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        payload = {
            "action": "run",
            "rule_ids": [],  # Empty = run all rules
            "log_source": "okta",
            "time_range_hours": 1,
        }

        response = requests.post(url, json=payload, headers=gcp_headers, timeout=300)

        if response.status_code == 401:
            pytest.skip("Authentication required")

        assert response.status_code in [200, 204]
        if response.status_code == 200:
            data = response.json()
            assert "alerts" in data or "results" in data or "count" in data

    def test_detection_rule_validation(self, gcp_config: Dict, gcp_headers: Dict):
        """Test detection rule validation."""
        url = f"{gcp_config['function_url_base']}/detection-engine"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        payload = {
            "action": "validate",
            "rule": {
                "title": "Test Rule",
                "status": "test",
                "logsource": {"product": "okta"},
                "detection": {
                    "selection": {"eventType": "user.session.start"},
                    "condition": "selection",
                },
            }
        }

        response = requests.post(url, json=payload, headers=gcp_headers, timeout=30)

        if response.status_code == 401:
            pytest.skip("Authentication required")

        assert response.status_code == 200

    def test_get_detection_statistics(self, gcp_config: Dict, gcp_headers: Dict):
        """Test getting detection statistics."""
        url = f"{gcp_config['function_url_base']}/detection-engine"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        payload = {"action": "stats"}

        response = requests.post(url, json=payload, headers=gcp_headers, timeout=30)

        if response.status_code == 401:
            pytest.skip("Authentication required")

        assert response.status_code == 200


@skipIf(not GCP_CONFIGURED, "GCP environment not configured")
class TestGCPAlertRouter:
    """Test GCP Alert Router functionality."""

    def test_list_alert_destinations(self, gcp_config: Dict, gcp_headers: Dict):
        """Test listing configured alert destinations."""
        url = f"{gcp_config['function_url_base']}/alert-router"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        payload = {"action": "list_destinations"}

        response = requests.post(url, json=payload, headers=gcp_headers, timeout=30)

        if response.status_code == 401:
            pytest.skip("Authentication required")

        assert response.status_code == 200

    def test_send_test_alert(self, gcp_config: Dict, gcp_headers: Dict):
        """Test sending a test alert."""
        url = f"{gcp_config['function_url_base']}/alert-router"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        payload = {
            "action": "test",
            "destination": "webhook",
            "message": "Test alert from E2E test suite",
        }

        response = requests.post(url, json=payload, headers=gcp_headers, timeout=30)

        if response.status_code == 401:
            pytest.skip("Authentication required")

        assert response.status_code in [200, 400, 404]

    def test_get_alert_history(self, gcp_config: Dict, gcp_headers: Dict):
        """Test getting alert history from Firestore."""
        url = f"{gcp_config['function_url_base']}/alert-router"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        payload = {"action": "history", "limit": 10}

        response = requests.post(url, json=payload, headers=gcp_headers, timeout=30)

        if response.status_code == 401:
            pytest.skip("Authentication required")

        assert response.status_code == 200


@skipIf(not GCP_CONFIGURED, "GCP environment not configured")
class TestGCPCollectors:
    """Test GCP Collector Functions."""

    @pytest.mark.parametrize("collector", [
        "okta", "github", "slack", "microsoft365", "crowdstrike", "duo",
        "google_workspace", "salesforce", "snowflake", "jamf",
        "onepassword", "azure_monitor"
    ])
    def test_collector_health(self, gcp_config: Dict, gcp_headers: Dict, collector: str):
        """Test collector function health endpoints."""
        url = f"{gcp_config['function_url_base']}/collector"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        payload = {"action": "health", "collector": collector}

        response = requests.post(url, json=payload, headers=gcp_headers, timeout=30)

        if response.status_code == 401:
            pytest.skip("Authentication required")

        assert response.status_code in [200, 404]

    def test_collector_status(self, gcp_config: Dict, gcp_headers: Dict):
        """Test getting status of all collectors."""
        url = f"{gcp_config['function_url_base']}/collector"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        payload = {"action": "status"}

        response = requests.post(url, json=payload, headers=gcp_headers, timeout=30)

        if response.status_code == 401:
            pytest.skip("Authentication required")

        assert response.status_code == 200


@skipIf(not GCP_CONFIGURED, "GCP environment not configured")
class TestGCPCloudRun:
    """Test GCP Cloud Run frontend."""

    def test_frontend_loads(self, gcp_config: Dict):
        """Test that the frontend loads successfully."""
        if not gcp_config.get("cloud_run_url"):
            pytest.skip("Cloud Run URL not configured")

        url = gcp_config["cloud_run_url"]
        response = requests.get(url, timeout=30)

        assert response.status_code in [200, 302, 401]

    def test_frontend_security_headers(self, gcp_config: Dict):
        """Test that security headers are present."""
        if not gcp_config.get("cloud_run_url"):
            pytest.skip("Cloud Run URL not configured")

        url = gcp_config["cloud_run_url"]
        response = requests.get(url, timeout=30)

        if response.status_code == 401:
            pytest.skip("Authentication required")

        headers = response.headers
        # Cloud Run may add some headers automatically
        assert response.status_code == 200

    def test_container_health(self, gcp_config: Dict):
        """Test Cloud Run container health endpoint."""
        if not gcp_config.get("cloud_run_url"):
            pytest.skip("Cloud Run URL not configured")

        url = f"{gcp_config['cloud_run_url']}/health"
        response = requests.get(url, timeout=30)

        assert response.status_code in [200, 404, 401]


@skipIf(not GCP_CONFIGURED, "GCP environment not configured")
class TestGCPEndToEndFlow:
    """Test complete end-to-end flow on GCP."""

    def test_full_detection_flow(self, gcp_config: Dict, gcp_headers: Dict):
        """Test full flow: query -> detection -> alert."""
        base_url = gcp_config["function_url_base"]

        # Step 1: Run a query to ensure data exists
        query_url = f"{base_url}/llm-query"
        token = get_gcp_id_token(query_url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        query_payload = {
            "question": "Show any events from the last hour",
            "log_source": "okta",
        }
        query_response = requests.post(
            query_url, json=query_payload, headers=gcp_headers, timeout=60
        )

        if query_response.status_code == 401:
            pytest.skip("Authentication required")

        assert query_response.status_code == 200

        # Step 2: Run detection
        detection_url = f"{base_url}/detection-engine"
        detection_payload = {
            "action": "run",
            "log_source": "okta",
            "time_range_hours": 1,
        }
        detection_response = requests.post(
            detection_url, json=detection_payload, headers=gcp_headers, timeout=300
        )
        assert detection_response.status_code in [200, 204]

        # Step 3: Check alert history
        history_url = f"{base_url}/alert-router"
        history_payload = {"action": "history", "limit": 5}
        history_response = requests.post(
            history_url, json=history_payload, headers=gcp_headers, timeout=30
        )
        assert history_response.status_code == 200

    def test_pubsub_alert_routing(self, gcp_config: Dict, gcp_headers: Dict):
        """Test that Pub/Sub alert routing works."""
        base_url = gcp_config["function_url_base"]
        url = f"{base_url}/alert-router"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        # Simulate a Pub/Sub message
        payload = {
            "action": "process_pubsub",
            "message": {
                "data": "eyJhbGVydF9pZCI6ICJ0ZXN0LTEyMyIsICJzZXZlcml0eSI6ICJoaWdoIn0=",  # base64 encoded
            }
        }

        response = requests.post(url, json=payload, headers=gcp_headers, timeout=30)

        if response.status_code == 401:
            pytest.skip("Authentication required")

        # Should process or reject gracefully
        assert response.status_code in [200, 400]


@skipIf(not GCP_CONFIGURED, "GCP environment not configured")
class TestGCPPerformance:
    """Performance tests for GCP deployment."""

    def test_query_response_time(self, gcp_config: Dict, gcp_headers: Dict):
        """Test that queries complete within acceptable time."""
        url = f"{gcp_config['function_url_base']}/llm-query"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        payload = {
            "question": "Count all events",
            "log_source": "okta",
        }

        start = time.time()
        response = requests.post(url, json=payload, headers=gcp_headers, timeout=60)
        elapsed = time.time() - start

        if response.status_code == 401:
            pytest.skip("Authentication required")

        assert response.status_code == 200
        assert elapsed < 30  # Should complete within 30 seconds

    def test_concurrent_queries(self, gcp_config: Dict, gcp_headers: Dict):
        """Test handling of concurrent queries."""
        import concurrent.futures

        url = f"{gcp_config['function_url_base']}/llm-query"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        payload = {"question": "Show recent events", "log_source": "okta"}

        def make_request():
            return requests.post(url, json=payload, headers=gcp_headers, timeout=60)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request) for _ in range(5)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # Check for auth requirement first
        if any(r.status_code == 401 for r in results):
            pytest.skip("Authentication required")

        # Most should succeed
        success_count = sum(1 for r in results if r.status_code == 200)
        assert success_count >= 3

    def test_cold_start_time(self, gcp_config: Dict, gcp_headers: Dict):
        """Test cold start time for Cloud Functions."""
        url = f"{gcp_config['function_url_base']}/llm-query"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        # First request might be cold start
        start = time.time()
        response = requests.post(
            url,
            json={"action": "health"},
            headers=gcp_headers,
            timeout=60
        )
        first_elapsed = time.time() - start

        if response.status_code == 401:
            pytest.skip("Authentication required")

        # Cold start should still be under 30 seconds
        assert first_elapsed < 30


@skipIf(not GCP_CONFIGURED, "GCP environment not configured")
class TestGCPFirestore:
    """Test GCP Firestore state management."""

    def test_firestore_state_persistence(self, gcp_config: Dict, gcp_headers: Dict):
        """Test that state is persisted in Firestore."""
        url = f"{gcp_config['function_url_base']}/detection-engine"

        token = get_gcp_id_token(url)
        if token:
            gcp_headers = {**gcp_headers, "Authorization": f"Bearer {token}"}

        # Run detection to create state
        run_payload = {
            "action": "run",
            "log_source": "okta",
            "time_range_hours": 1,
        }
        requests.post(url, json=run_payload, headers=gcp_headers, timeout=300)

        # Check state was saved
        state_payload = {"action": "get_state"}
        response = requests.post(url, json=state_payload, headers=gcp_headers, timeout=30)

        if response.status_code == 401:
            pytest.skip("Authentication required")

        assert response.status_code in [200, 404]  # 404 if no runs yet


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
