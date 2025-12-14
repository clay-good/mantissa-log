"""Azure Function handler for query-to-rule conversion.

Converts natural language descriptions to Sigma detection rules.
Uses LLM to generate complete Sigma YAML with MITRE ATT&CK mapping.
"""

import azure.functions as func
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict

import yaml

from src.shared.detection.nl_to_sigma import NLToSigmaConverter
from src.shared.llm.providers import get_provider
from src.shared.auth.azure import verify_azure_ad_token, get_cors_headers, AuthenticationError

logger = logging.getLogger(__name__)


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function handler for converting natural language to Sigma rules.

    Supports two modes:
    1. Natural Language mode: Provide a description and let LLM generate Sigma rule
    2. Direct mode: Provide structured input for rule generation without LLM

    Expected input (Natural Language mode - preferred):
    {
        "description": "Detect when Azure AD sign-in from suspicious location",
        "logSource": "azure",
        "severity": "high",
        "schedule": "*/15 * * * *",
        "alertDestinations": ["slack", "email"],
        "mode": "natural_language"
    }

    Expected input (Direct mode - no LLM):
    {
        "title": "Azure AD Suspicious Sign-In",
        "description": "Detects sign-ins from suspicious locations",
        "eventFields": {"ResultType": "50074"},
        "logSource": "azure",
        "severity": "high",
        "mode": "direct"
    }
    """
    cors_headers = get_cors_headers(req)

    # Handle CORS preflight
    if req.method == "OPTIONS":
        return func.HttpResponse(
            "",
            status_code=204,
            headers={
                **cors_headers,
                "Access-Control-Allow-Methods": "POST,OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type,Authorization",
                "Access-Control-Max-Age": "3600"
            }
        )

    # Authenticate user from Azure AD token
    try:
        user_id = verify_azure_ad_token(req)
    except AuthenticationError as e:
        return func.HttpResponse(
            json.dumps({"error": "Authentication required", "details": str(e)}),
            status_code=401,
            mimetype="application/json",
            headers=cors_headers
        )

    logger.info(f"Processing query-to-rule request for user: {user_id}")

    try:
        body = req.get_json()

        # Determine mode
        mode = body.get("mode", "natural_language")

        if mode == "natural_language":
            return handle_natural_language_mode(req, user_id, body)
        else:
            return handle_direct_mode(req, user_id, body)

    except ValueError as e:
        return func.HttpResponse(
            json.dumps({"error": f"Invalid JSON in request body: {str(e)}"}),
            status_code=400,
            mimetype="application/json",
            headers=cors_headers
        )
    except Exception as e:
        logger.error(f"Error creating detection rule: {str(e)}")
        return error_response(req, str(e), 500)


def handle_natural_language_mode(req: func.HttpRequest, user_id: str, body: Dict[str, Any]) -> func.HttpResponse:
    """Handle natural language to Sigma conversion."""
    cors_headers = get_cors_headers(req)

    # Validate required fields
    if "description" not in body:
        return error_response(req, "Missing required field: description", 400)

    # Get LLM provider
    llm_provider = get_llm_provider()

    converter = NLToSigmaConverter(
        llm_provider=llm_provider,
        default_author=body.get("author", "Mantissa Security")
    )

    # Convert natural language to Sigma
    result = converter.convert(
        natural_language=body["description"],
        log_source_hint=body.get("logSource"),
        severity_hint=body.get("severity"),
        additional_context=body.get("additionalContext")
    )

    if not result.success:
        return error_response(req, f"Failed to generate Sigma rule: {result.error}", 400)

    # Add alert destinations to the rule
    sigma_dict = result.sigma_dict
    if body.get("alertDestinations"):
        sigma_dict["x-mantissa"] = {
            "schedule": body.get("schedule", "*/15 * * * *"),
            "alert_destinations": body["alertDestinations"],
            "threshold": body.get("threshold", 1),
            "enabled": True
        }

    # Generate final YAML
    final_yaml = yaml.dump(sigma_dict, default_flow_style=False, sort_keys=False)

    # Save rule to Blob Storage
    rule_name = sigma_dict.get("title", "unnamed_rule")
    rule_key = save_sigma_rule_to_blob(
        sigma_yaml=final_yaml,
        rule_id=result.rule_id,
        user_id=user_id
    )

    # Save rule metadata to Cosmos DB
    save_sigma_rule_metadata(
        user_id=user_id,
        rule_id=result.rule_id,
        rule_name=rule_name,
        blob_key=rule_key,
        schedule=body.get("schedule", "*/15 * * * *"),
        severity=sigma_dict.get("level", "medium"),
        mitre_techniques=result.mitre_techniques,
        mitre_tactics=result.mitre_tactics,
        confidence_score=result.confidence_score
    )

    return func.HttpResponse(
        json.dumps({
            "success": True,
            "message": "Sigma detection rule created successfully",
            "ruleId": result.rule_id,
            "ruleKey": rule_key,
            "sigmaYaml": final_yaml,
            "mitreAttack": {
                "tactics": result.mitre_tactics,
                "techniques": result.mitre_techniques
            },
            "confidenceScore": result.confidence_score,
            "warnings": result.warnings
        }),
        status_code=200,
        mimetype="application/json",
        headers=cors_headers
    )


def handle_direct_mode(req: func.HttpRequest, user_id: str, body: Dict[str, Any]) -> func.HttpResponse:
    """Handle direct mode - creates Sigma rule without LLM."""
    cors_headers = get_cors_headers(req)

    # Validate required fields
    required_fields = ["title", "description", "eventFields", "logSource"]
    for field in required_fields:
        if field not in body:
            return error_response(req, f"Missing required field: {field}", 400)

    converter = NLToSigmaConverter(
        llm_provider=None,
        default_author=body.get("author", "Mantissa Security")
    )

    # Convert using direct method (no LLM)
    result = converter.convert_without_llm(
        title=body["title"],
        description=body["description"],
        event_fields=body["eventFields"],
        log_source=body["logSource"],
        severity=body.get("severity", "medium")
    )

    if not result.success:
        return error_response(req, f"Failed to generate Sigma rule: {result.error}", 400)

    # Add alert destinations
    sigma_dict = result.sigma_dict
    if body.get("alertDestinations"):
        sigma_dict["x-mantissa"] = {
            "schedule": body.get("schedule", "*/15 * * * *"),
            "alert_destinations": body["alertDestinations"],
            "threshold": body.get("threshold", 1),
            "enabled": True
        }

    final_yaml = yaml.dump(sigma_dict, default_flow_style=False, sort_keys=False)

    # Save rule
    rule_key = save_sigma_rule_to_blob(
        sigma_yaml=final_yaml,
        rule_id=result.rule_id,
        user_id=user_id
    )

    save_sigma_rule_metadata(
        user_id=user_id,
        rule_id=result.rule_id,
        rule_name=body["title"],
        blob_key=rule_key,
        schedule=body.get("schedule", "*/15 * * * *"),
        severity=body.get("severity", "medium"),
        mitre_techniques=result.mitre_techniques,
        mitre_tactics=result.mitre_tactics,
        confidence_score=result.confidence_score
    )

    return func.HttpResponse(
        json.dumps({
            "success": True,
            "message": "Sigma detection rule created successfully (direct mode)",
            "ruleId": result.rule_id,
            "ruleKey": rule_key,
            "sigmaYaml": final_yaml,
            "mitreAttack": {
                "tactics": result.mitre_tactics,
                "techniques": result.mitre_techniques
            },
            "confidenceScore": result.confidence_score,
            "warnings": result.warnings
        }),
        status_code=200,
        mimetype="application/json",
        headers=cors_headers
    )


def get_llm_provider():
    """Get the configured LLM provider."""
    provider_type = os.environ.get("LLM_PROVIDER", "azure_openai")

    if provider_type == "azure_openai":
        from src.shared.llm.providers import AzureOpenAIProvider
        return AzureOpenAIProvider()
    elif provider_type == "openai":
        from src.shared.llm.providers import OpenAIProvider
        api_key = os.environ.get("OPENAI_API_KEY")
        return OpenAIProvider(api_key=api_key)
    elif provider_type == "anthropic":
        from src.shared.llm.providers import AnthropicProvider
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        return AnthropicProvider(api_key=api_key)
    else:
        # Default to Azure OpenAI for Azure Functions
        from src.shared.llm.providers import AzureOpenAIProvider
        return AzureOpenAIProvider()


def save_sigma_rule_to_blob(
    sigma_yaml: str,
    rule_id: str,
    user_id: str
) -> str:
    """Save Sigma rule to Azure Blob Storage."""
    from azure.storage.blob import BlobServiceClient

    connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("RULES_CONTAINER", "sigma-rules")

    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    container_client = blob_service_client.get_container_client(container_name)

    # Create safe filename
    safe_id = rule_id.replace("/", "_").replace("\\", "_")
    blob_name = f"sigma_rules/{user_id}/{safe_id}.yml"

    blob_client = container_client.get_blob_client(blob_name)
    blob_client.upload_blob(
        sigma_yaml,
        content_type="application/x-yaml",
        overwrite=True
    )

    logger.info(f"Saved Sigma rule to {container_name}/{blob_name}")
    return blob_name


def save_sigma_rule_metadata(
    user_id: str,
    rule_id: str,
    rule_name: str,
    blob_key: str,
    schedule: str,
    severity: str,
    mitre_techniques: list,
    mitre_tactics: list,
    confidence_score: float
) -> None:
    """Save Sigma rule metadata to Cosmos DB."""
    from azure.cosmos import CosmosClient

    connection_string = os.environ.get("COSMOS_CONNECTION_STRING")
    database_name = os.environ.get("COSMOS_DATABASE", "mantissa")
    container_name = os.environ.get("COSMOS_RULES_CONTAINER", "sigma_rules")

    client = CosmosClient.from_connection_string(connection_string)
    database = client.get_database_client(database_name)
    container = database.get_container_client(container_name)

    item = {
        "id": rule_id,
        "user_id": user_id,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "blob_key": blob_key,
        "format": "sigma",
        "schedule": schedule,
        "severity": severity,
        "mitre_techniques": mitre_techniques,
        "mitre_tactics": mitre_tactics,
        "confidence_score": confidence_score,
        "enabled": True,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
        "executions": 0,
        "last_execution": None,
        "last_alert": None,
        "false_positive_count": 0,
        "true_positive_count": 0
    }

    container.upsert_item(item)
    logger.info(f"Saved Sigma rule metadata for {rule_id}")


def error_response(req: func.HttpRequest, message: str, status_code: int) -> func.HttpResponse:
    """Return an error response with secure CORS headers."""
    cors_headers = get_cors_headers(req)
    return func.HttpResponse(
        json.dumps({"error": message}),
        status_code=status_code,
        mimetype="application/json",
        headers=cors_headers
    )
