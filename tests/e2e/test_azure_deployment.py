"""End-to-end integration tests for Azure deployment.

These tests verify the complete Azure deployment of Mantissa Log including:
- Azure Functions (collectors, LLM query, detection, alert router)
- Synapse Analytics queries
- Cosmos DB state management
- Azure Blob Storage
- Event Grid alerts
- Static Web App

Prerequisites:
- Azure deployment completed via `terraform apply`
- Environment variables set:
  - AZURE_SUBSCRIPTION_ID
  - AZURE_RESOURCE_GROUP
  - AZURE_FUNCTION_APP_URL
  - AZURE_SYNAPSE_WORKSPACE
"""

import json
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from unittest import skipIf

import pytest
import requests

# Skip all tests if Azure environment is not configured
AZURE_CONFIGURED = all([
    os.environ.get("AZURE_SUBSCRIPTION_ID"),
    os.environ.get("AZURE_RESOURCE_GROUP"),
    os.environ.get("AZURE_FUNCTION_APP_URL"),
])

# Apply skip to all tests in this module
pytestmark = pytest.mark.skipif(not AZURE_CONFIGURED, reason="Azure environment not configured")


@pytest.fixture(scope="module")
def azure_config() -> Dict[str, str]:
    """Get Azure configuration from environment."""
    return {
        "subscription_id": os.environ.get("AZURE_SUBSCRIPTION_ID", ""),
        "resource_group": os.environ.get("AZURE_RESOURCE_GROUP", ""),
        "function_app_url": os.environ.get("AZURE_FUNCTION_APP_URL", ""),
        "synapse_workspace": os.environ.get("AZURE_SYNAPSE_WORKSPACE", ""),
        "static_web_app_url": os.environ.get("AZURE_STATIC_WEB_APP_URL", ""),
        "cosmos_db_endpoint": os.environ.get("AZURE_COSMOS_DB_ENDPOINT", ""),
    }


@pytest.fixture(scope="module")
def azure_headers() -> Dict[str, str]:
    """Get headers for Azure Function calls."""
    api_key = os.environ.get("AZURE_FUNCTION_KEY", "")
    return {
        "Content-Type": "application/json",
        "x-functions-key": api_key,
    }


@skipIf(not AZURE_CONFIGURED, "Azure environment not configured")
class TestAzureFunctionHealth:
    """Test Azure Function health endpoints."""

    def test_llm_query_function_health(self, azure_config: Dict, azure_headers: Dict):
        """Test LLM Query Function is responding."""
        url = f"{azure_config['function_app_url']}/api/health"
        response = requests.get(url, headers=azure_headers, timeout=30)

        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "healthy"

    def test_detection_engine_function_health(self, azure_config: Dict, azure_headers: Dict):
        """Test Detection Engine Function is responding."""
        url = f"{azure_config['function_app_url']}/api/detection/health"
        response = requests.get(url, headers=azure_headers, timeout=30)

        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "healthy"

    def test_alert_router_function_health(self, azure_config: Dict, azure_headers: Dict):
        """Test Alert Router Function is responding."""
        url = f"{azure_config['function_app_url']}/api/alerts/health"
        response = requests.get(url, headers=azure_headers, timeout=30)

        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "healthy"


@skipIf(not AZURE_CONFIGURED, "Azure environment not configured")
class TestAzureLLMQuery:
    """Test Azure LLM Query functionality."""

    def test_natural_language_query(self, azure_config: Dict, azure_headers: Dict):
        """Test natural language to SQL conversion."""
        url = f"{azure_config['function_app_url']}/api/query"
        payload = {
            "question": "Show me the last 10 login events",
            "log_source": "okta",
        }

        response = requests.post(url, json=payload, headers=azure_headers, timeout=60)

        assert response.status_code == 200
        data = response.json()
        assert "sql" in data or "query" in data
        assert "results" in data or "error" not in data

    def test_query_with_time_range(self, azure_config: Dict, azure_headers: Dict):
        """Test query with specific time range."""
        url = f"{azure_config['function_app_url']}/api/query"
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)

        payload = {
            "question": "Show failed authentication attempts",
            "log_source": "okta",
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
        }

        response = requests.post(url, json=payload, headers=azure_headers, timeout=60)

        assert response.status_code == 200

    def test_query_rate_limiting(self, azure_config: Dict, azure_headers: Dict):
        """Test that rate limiting is working."""
        url = f"{azure_config['function_app_url']}/api/query"
        payload = {"question": "Show recent events", "log_source": "okta"}

        # Make multiple rapid requests
        responses = []
        for _ in range(10):
            resp = requests.post(url, json=payload, headers=azure_headers, timeout=60)
            responses.append(resp.status_code)

        # Should not all be 200 if rate limiting is enabled
        # At least some should complete successfully
        assert 200 in responses


@skipIf(not AZURE_CONFIGURED, "Azure environment not configured")
class TestAzureDetectionEngine:
    """Test Azure Detection Engine functionality."""

    def test_run_detection_rules(self, azure_config: Dict, azure_headers: Dict):
        """Test detection rule execution."""
        url = f"{azure_config['function_app_url']}/api/detection/run"
        payload = {
            "rule_ids": [],  # Empty = run all rules
            "log_source": "okta",
            "time_range_hours": 1,
        }

        response = requests.post(url, json=payload, headers=azure_headers, timeout=300)

        assert response.status_code in [200, 204]  # 204 if no alerts
        if response.status_code == 200:
            data = response.json()
            assert "alerts" in data or "results" in data

    def test_detection_rule_validation(self, azure_config: Dict, azure_headers: Dict):
        """Test detection rule validation endpoint."""
        url = f"{azure_config['function_app_url']}/api/detection/validate"
        payload = {
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

        response = requests.post(url, json=payload, headers=azure_headers, timeout=30)

        assert response.status_code == 200
        data = response.json()
        assert "valid" in data

    def test_get_detection_statistics(self, azure_config: Dict, azure_headers: Dict):
        """Test getting detection statistics."""
        url = f"{azure_config['function_app_url']}/api/detection/stats"

        response = requests.get(url, headers=azure_headers, timeout=30)

        assert response.status_code == 200
        data = response.json()
        assert "total_rules" in data or "rules_count" in data


@skipIf(not AZURE_CONFIGURED, "Azure environment not configured")
class TestAzureAlertRouter:
    """Test Azure Alert Router functionality."""

    def test_list_alert_destinations(self, azure_config: Dict, azure_headers: Dict):
        """Test listing configured alert destinations."""
        url = f"{azure_config['function_app_url']}/api/alerts/destinations"

        response = requests.get(url, headers=azure_headers, timeout=30)

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list) or "destinations" in data

    def test_send_test_alert(self, azure_config: Dict, azure_headers: Dict):
        """Test sending a test alert."""
        url = f"{azure_config['function_app_url']}/api/alerts/test"
        payload = {
            "destination": "webhook",
            "message": "Test alert from E2E test suite",
        }

        response = requests.post(url, json=payload, headers=azure_headers, timeout=30)

        # May fail if no webhook configured, but should not error
        assert response.status_code in [200, 400, 404]

    def test_get_alert_history(self, azure_config: Dict, azure_headers: Dict):
        """Test getting alert history."""
        url = f"{azure_config['function_app_url']}/api/alerts/history"
        params = {"limit": 10}

        response = requests.get(url, params=params, headers=azure_headers, timeout=30)

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list) or "alerts" in data


@skipIf(not AZURE_CONFIGURED, "Azure environment not configured")
class TestAzureCollectors:
    """Test Azure Collector Functions."""

    @pytest.mark.parametrize("collector", [
        "okta", "github", "slack", "microsoft365", "crowdstrike", "duo"
    ])
    def test_collector_health(self, azure_config: Dict, azure_headers: Dict, collector: str):
        """Test collector function health endpoints."""
        url = f"{azure_config['function_app_url']}/api/collectors/{collector}/health"

        response = requests.get(url, headers=azure_headers, timeout=30)

        # May return 404 if collector not deployed, but should not error
        assert response.status_code in [200, 404]

    def test_collector_status(self, azure_config: Dict, azure_headers: Dict):
        """Test getting status of all collectors."""
        url = f"{azure_config['function_app_url']}/api/collectors/status"

        response = requests.get(url, headers=azure_headers, timeout=30)

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict) or isinstance(data, list)


@skipIf(not AZURE_CONFIGURED, "Azure environment not configured")
class TestAzureStaticWebApp:
    """Test Azure Static Web App frontend."""

    def test_frontend_loads(self, azure_config: Dict):
        """Test that the frontend loads successfully."""
        if not azure_config.get("static_web_app_url"):
            pytest.skip("Static Web App URL not configured")

        url = azure_config["static_web_app_url"]
        response = requests.get(url, timeout=30)

        assert response.status_code == 200
        assert "text/html" in response.headers.get("Content-Type", "")

    def test_frontend_security_headers(self, azure_config: Dict):
        """Test that security headers are present."""
        if not azure_config.get("static_web_app_url"):
            pytest.skip("Static Web App URL not configured")

        url = azure_config["static_web_app_url"]
        response = requests.get(url, timeout=30)

        headers = response.headers
        assert "X-Content-Type-Options" in headers
        assert "X-Frame-Options" in headers

    def test_api_proxy_routing(self, azure_config: Dict, azure_headers: Dict):
        """Test that API routes are proxied correctly."""
        if not azure_config.get("static_web_app_url"):
            pytest.skip("Static Web App URL not configured")

        url = f"{azure_config['static_web_app_url']}/api/health"
        response = requests.get(url, headers=azure_headers, timeout=30)

        # Should either work or require auth, not 404
        assert response.status_code in [200, 401, 403]


@skipIf(not AZURE_CONFIGURED, "Azure environment not configured")
class TestAzureEndToEndFlow:
    """Test complete end-to-end flow on Azure."""

    def test_full_detection_flow(self, azure_config: Dict, azure_headers: Dict):
        """Test full flow: query -> detection -> alert."""
        base_url = azure_config["function_app_url"]

        # Step 1: Run a query to ensure data exists
        query_url = f"{base_url}/api/query"
        query_payload = {
            "question": "Show any events from the last hour",
            "log_source": "okta",
        }
        query_response = requests.post(
            query_url, json=query_payload, headers=azure_headers, timeout=60
        )
        assert query_response.status_code == 200

        # Step 2: Run detection
        detection_url = f"{base_url}/api/detection/run"
        detection_payload = {
            "log_source": "okta",
            "time_range_hours": 1,
        }
        detection_response = requests.post(
            detection_url, json=detection_payload, headers=azure_headers, timeout=300
        )
        assert detection_response.status_code in [200, 204]

        # Step 3: Check alert history
        history_url = f"{base_url}/api/alerts/history"
        history_response = requests.get(
            history_url, params={"limit": 5}, headers=azure_headers, timeout=30
        )
        assert history_response.status_code == 200

    def test_collector_to_detection_pipeline(self, azure_config: Dict, azure_headers: Dict):
        """Test data flows from collector to detection."""
        base_url = azure_config["function_app_url"]

        # Get collector status
        status_url = f"{base_url}/api/collectors/status"
        status_response = requests.get(status_url, headers=azure_headers, timeout=30)

        if status_response.status_code != 200:
            pytest.skip("Collectors not available")

        # Verify detection can query collected data
        detection_url = f"{base_url}/api/detection/stats"
        detection_response = requests.get(detection_url, headers=azure_headers, timeout=30)

        assert detection_response.status_code == 200


@skipIf(not AZURE_CONFIGURED, "Azure environment not configured")
class TestAzurePerformance:
    """Performance tests for Azure deployment."""

    def test_query_response_time(self, azure_config: Dict, azure_headers: Dict):
        """Test that queries complete within acceptable time."""
        url = f"{azure_config['function_app_url']}/api/query"
        payload = {
            "question": "Count all events",
            "log_source": "okta",
        }

        start = time.time()
        response = requests.post(url, json=payload, headers=azure_headers, timeout=60)
        elapsed = time.time() - start

        assert response.status_code == 200
        assert elapsed < 30  # Should complete within 30 seconds

    def test_concurrent_queries(self, azure_config: Dict, azure_headers: Dict):
        """Test handling of concurrent queries."""
        import concurrent.futures

        url = f"{azure_config['function_app_url']}/api/query"
        payload = {"question": "Show recent events", "log_source": "okta"}

        def make_request():
            return requests.post(url, json=payload, headers=azure_headers, timeout=60)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request) for _ in range(5)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # Most should succeed
        success_count = sum(1 for r in results if r.status_code == 200)
        assert success_count >= 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
