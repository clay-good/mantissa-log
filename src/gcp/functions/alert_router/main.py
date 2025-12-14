"""GCP Cloud Function handler for alert routing and enrichment."""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict

import functions_framework
from flask import Request
from google.cloud import secretmanager

from src.shared.alerting import AlertRouter, RouterConfig
from src.shared.alerting.enrichment import AlertEnricher
from src.shared.llm.providers import get_provider
from src.shared.auth.gcp import verify_firebase_token, get_cors_headers, AuthenticationError

logger = logging.getLogger(__name__)


def get_secret(project_id: str, secret_name: str) -> str:
    """Retrieve secret from Google Secret Manager."""
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("UTF-8")


@functions_framework.http
def alert_router(request: Request):
    """Cloud Function handler for alert routing.

    Routes alerts to configured destinations (Slack, PagerDuty, Email, Jira, Webhooks)
    with optional LLM-powered enrichment.
    """
    cors_headers = get_cors_headers(request)

    # Handle CORS
    if request.method == "OPTIONS":
        return ("", 204, {
            **cors_headers,
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "3600"
        })

    # Authenticate user from Firebase/Identity Platform token
    try:
        user_id = verify_firebase_token(request)
    except AuthenticationError as e:
        return (
            json.dumps({"error": "Authentication required", "details": str(e)}),
            401,
            {"Content-Type": "application/json", **cors_headers}
        )

    logger.info(f"Processing alert routing request for user: {user_id}")

    # Load configuration
    project_id = os.environ.get("GCP_PROJECT_ID")
    llm_provider_name = os.environ.get("LLM_PROVIDER", "google")
    enable_enrichment = os.environ.get("ENABLE_ENRICHMENT", "true").lower() == "true"

    try:
        body = request.get_json(silent=True) or {}

        alert_data = body.get("alert")
        destinations = body.get("destinations", [])
        enrich = body.get("enrich", enable_enrichment)

        if not alert_data:
            return (
                json.dumps({"error": "Missing 'alert' field in request"}),
                400,
                {"Content-Type": "application/json", **cors_headers}
            )

    except Exception as e:
        return (
            json.dumps({"error": f"Invalid JSON: {str(e)}"}),
            400,
            {"Content-Type": "application/json", **cors_headers}
        )

    try:
        # Enrich alert if requested
        enriched_alert = alert_data
        if enrich:
            try:
                llm_provider = get_provider(llm_provider_name)
                enricher = AlertEnricher(llm_provider=llm_provider)
                enriched_alert = enricher.enrich_alert(alert_data)
                logger.info("Alert enriched with LLM context")
            except Exception as e:
                logger.warning(f"Failed to enrich alert: {e}")
                enriched_alert = alert_data

        # Build router configuration from destinations
        router_configs = []
        for dest in destinations:
            dest_type = dest.get("type")
            config = dest.get("config", {})

            # Get credentials from Secret Manager if specified
            if config.get("secret_name"):
                config["api_key"] = get_secret(project_id, config["secret_name"])

            router_configs.append(RouterConfig(
                destination_type=dest_type,
                config=config,
                enabled=dest.get("enabled", True)
            ))

        # Initialize router
        router = AlertRouter(configs=router_configs)

        # Route alert
        results = router.route_alert(enriched_alert)

        # Build response
        response = {
            "success": True,
            "alert_id": alert_data.get("id", "unknown"),
            "enriched": enrich,
            "routing_results": [
                {
                    "destination": r.destination,
                    "success": r.success,
                    "message": r.message
                }
                for r in results
            ],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        return (
            json.dumps(response),
            200,
            {"Content-Type": "application/json", **cors_headers}
        )

    except Exception as e:
        logger.error(f"Error routing alert: {e}")
        import traceback
        traceback.print_exc()

        return (
            json.dumps({"success": False, "error": str(e)}),
            500,
            {"Content-Type": "application/json", **cors_headers}
        )


@functions_framework.cloud_event
def alert_pubsub_trigger(cloud_event):
    """Pub/Sub trigger handler for automatic alert routing.

    Listens to detection alerts from Pub/Sub and routes them automatically.
    """
    import base64

    logger.info(f"Processing Pub/Sub alert event")

    project_id = os.environ.get("GCP_PROJECT_ID")
    llm_provider_name = os.environ.get("LLM_PROVIDER", "google")
    enable_enrichment = os.environ.get("ENABLE_ENRICHMENT", "true").lower() == "true"

    try:
        # Decode alert data from Pub/Sub message
        message_data = base64.b64decode(cloud_event.data["message"]["data"]).decode("utf-8")
        alert_data = json.loads(message_data)

        # Get default routing configuration from environment
        default_destinations = json.loads(os.environ.get("DEFAULT_DESTINATIONS", "[]"))

        if not default_destinations:
            logger.warning("No default destinations configured")
            return

        # Enrich alert
        enriched_alert = alert_data
        if enable_enrichment:
            try:
                llm_provider = get_provider(llm_provider_name)
                enricher = AlertEnricher(llm_provider=llm_provider)
                enriched_alert = enricher.enrich_alert(alert_data)
            except Exception as e:
                logger.warning(f"Failed to enrich alert: {e}")

        # Build router configs
        router_configs = []
        for dest in default_destinations:
            dest_type = dest.get("type")
            config = dest.get("config", {})

            if config.get("secret_name"):
                config["api_key"] = get_secret(project_id, config["secret_name"])

            router_configs.append(RouterConfig(
                destination_type=dest_type,
                config=config,
                enabled=True
            ))

        # Route alert
        router = AlertRouter(configs=router_configs)
        results = router.route_alert(enriched_alert)

        success_count = len([r for r in results if r.success])
        logger.info(f"Alert routed to {success_count}/{len(results)} destinations")

    except Exception as e:
        logger.error(f"Error processing Pub/Sub event: {e}")
        raise
