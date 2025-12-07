"""Azure Function handler for alert routing and enrichment."""

import azure.functions as func
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from src.shared.alerting import AlertRouter, RouterConfig
from src.shared.alerting.enrichment import AlertEnricher
from src.shared.llm.providers import get_provider

logger = logging.getLogger(__name__)


def get_key_vault_secret(vault_url: str, secret_name: str) -> str:
    """Retrieve secret from Azure Key Vault."""
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient

    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=vault_url, credential=credential)
    secret = client.get_secret(secret_name)
    return secret.value


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function handler for alert routing.

    Routes alerts to configured destinations (Slack, PagerDuty, Email, Jira, Webhooks)
    with optional LLM-powered enrichment.
    """
    logger.info("Processing alert routing request")

    # Load configuration
    key_vault_url = os.environ.get("KEY_VAULT_URL")
    llm_provider_name = os.environ.get("LLM_PROVIDER", "openai")
    enable_enrichment = os.environ.get("ENABLE_ENRICHMENT", "true").lower() == "true"

    try:
        body = req.get_json()

        alert_data = body.get("alert")
        destinations = body.get("destinations", [])
        enrich = body.get("enrich", enable_enrichment)

        if not alert_data:
            return func.HttpResponse(
                json.dumps({"error": "Missing 'alert' field in request"}),
                status_code=400,
                mimetype="application/json"
            )

    except ValueError as e:
        return func.HttpResponse(
            json.dumps({"error": f"Invalid JSON: {str(e)}"}),
            status_code=400,
            mimetype="application/json"
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

            # Get credentials from Key Vault if specified
            if key_vault_url and config.get("secret_name"):
                config["api_key"] = get_key_vault_secret(key_vault_url, config["secret_name"])

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

        return func.HttpResponse(
            json.dumps(response),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logger.error(f"Error routing alert: {e}")
        import traceback
        traceback.print_exc()

        return func.HttpResponse(
            json.dumps({
                "success": False,
                "error": str(e)
            }),
            status_code=500,
            mimetype="application/json"
        )


def event_grid_trigger(event: func.EventGridEvent) -> None:
    """Event Grid trigger handler for automatic alert routing.

    Listens to detection alerts from Event Grid and routes them automatically.
    """
    logger.info(f"Processing Event Grid event: {event.id}")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    llm_provider_name = os.environ.get("LLM_PROVIDER", "openai")
    enable_enrichment = os.environ.get("ENABLE_ENRICHMENT", "true").lower() == "true"

    try:
        # Parse alert data from event
        alert_data = event.get_json()

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

            if key_vault_url and config.get("secret_name"):
                config["api_key"] = get_key_vault_secret(key_vault_url, config["secret_name"])

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
        logger.error(f"Error processing Event Grid event: {e}")
        raise
