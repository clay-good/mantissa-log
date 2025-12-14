"""GCP Cloud Function handler for query-to-rule conversion.

Converts natural language descriptions to Sigma detection rules.
Uses LLM to generate complete Sigma YAML with MITRE ATT&CK mapping.
"""

import json
import logging
import os
from typing import Any, Dict

import functions_framework
from flask import Request
from google.cloud import storage, firestore
import yaml

from src.shared.detection.nl_to_sigma import NLToSigmaConverter
from src.shared.llm.providers import get_provider
from src.shared.auth.gcp import verify_firebase_token, get_cors_headers, AuthenticationError

logger = logging.getLogger(__name__)


@functions_framework.http
def query_to_rule(request: Request):
    """Cloud Function handler for converting natural language to Sigma rules.

    Supports two modes:
    1. Natural Language mode: Provide a description and let LLM generate Sigma rule
    2. Direct mode: Provide structured input for rule generation without LLM

    Expected input (Natural Language mode - preferred):
    {
        "description": "Detect when CloudTrail logging is disabled",
        "logSource": "gcp",  # optional hint
        "severity": "high",
        "schedule": "*/15 * * * *",
        "alertDestinations": ["slack", "email"],
        "mode": "natural_language"
    }

    Expected input (Direct mode - no LLM):
    {
        "title": "GCP Audit Log Disabled",
        "description": "Detects when audit logging is disabled",
        "eventFields": {"methodName": "SetIamPolicy"},
        "logSource": "gcp",
        "severity": "high",
        "mode": "direct"
    }
    """
    cors_headers = get_cors_headers(request)

    # Handle CORS preflight
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

    logger.info(f"Processing query-to-rule request for user: {user_id}")

    try:
        body = request.get_json(silent=True) or {}

        # Determine mode
        mode = body.get("mode", "natural_language")

        if mode == "natural_language":
            return handle_natural_language_mode(request, user_id, body)
        else:
            return handle_direct_mode(request, user_id, body)

    except Exception as e:
        logger.error(f"Error creating detection rule: {str(e)}")
        return error_response(request, str(e), 500)


def handle_natural_language_mode(request: Request, user_id: str, body: Dict[str, Any]):
    """Handle natural language to Sigma conversion."""
    cors_headers = get_cors_headers(request)

    # Validate required fields
    if "description" not in body:
        return error_response(request, "Missing required field: description", 400)

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
        return error_response(request, f"Failed to generate Sigma rule: {result.error}", 400)

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

    # Save rule to Cloud Storage
    rule_name = sigma_dict.get("title", "unnamed_rule")
    rule_key = save_sigma_rule_to_gcs(
        sigma_yaml=final_yaml,
        rule_id=result.rule_id,
        user_id=user_id
    )

    # Save rule metadata to Firestore
    save_sigma_rule_metadata(
        user_id=user_id,
        rule_id=result.rule_id,
        rule_name=rule_name,
        gcs_key=rule_key,
        schedule=body.get("schedule", "*/15 * * * *"),
        severity=sigma_dict.get("level", "medium"),
        mitre_techniques=result.mitre_techniques,
        mitre_tactics=result.mitre_tactics,
        confidence_score=result.confidence_score
    )

    return (
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
        200,
        {"Content-Type": "application/json", **cors_headers}
    )


def handle_direct_mode(request: Request, user_id: str, body: Dict[str, Any]):
    """Handle direct mode - creates Sigma rule without LLM."""
    cors_headers = get_cors_headers(request)

    # Validate required fields
    required_fields = ["title", "description", "eventFields", "logSource"]
    for field in required_fields:
        if field not in body:
            return error_response(request, f"Missing required field: {field}", 400)

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
        return error_response(request, f"Failed to generate Sigma rule: {result.error}", 400)

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
    rule_key = save_sigma_rule_to_gcs(
        sigma_yaml=final_yaml,
        rule_id=result.rule_id,
        user_id=user_id
    )

    save_sigma_rule_metadata(
        user_id=user_id,
        rule_id=result.rule_id,
        rule_name=body["title"],
        gcs_key=rule_key,
        schedule=body.get("schedule", "*/15 * * * *"),
        severity=body.get("severity", "medium"),
        mitre_techniques=result.mitre_techniques,
        mitre_tactics=result.mitre_tactics,
        confidence_score=result.confidence_score
    )

    return (
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
        200,
        {"Content-Type": "application/json", **cors_headers}
    )


def get_llm_provider():
    """Get the configured LLM provider."""
    provider_type = os.environ.get("LLM_PROVIDER", "google")

    if provider_type == "google":
        from src.shared.llm.providers import GoogleProvider
        return GoogleProvider()
    elif provider_type == "vertex":
        from src.shared.llm.providers import VertexAIProvider
        project_id = os.environ.get("GCP_PROJECT_ID")
        return VertexAIProvider(project_id=project_id)
    elif provider_type == "anthropic":
        from src.shared.llm.providers import AnthropicProvider
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        return AnthropicProvider(api_key=api_key)
    elif provider_type == "openai":
        from src.shared.llm.providers import OpenAIProvider
        api_key = os.environ.get("OPENAI_API_KEY")
        return OpenAIProvider(api_key=api_key)
    else:
        # Default to Google for GCP
        from src.shared.llm.providers import GoogleProvider
        return GoogleProvider()


def save_sigma_rule_to_gcs(
    sigma_yaml: str,
    rule_id: str,
    user_id: str
) -> str:
    """Save Sigma rule to Google Cloud Storage."""
    bucket_name = os.environ.get("RULES_BUCKET", "mantissa-log-rules")

    client = storage.Client()
    bucket = client.bucket(bucket_name)

    # Create safe filename
    safe_id = rule_id.replace("/", "_").replace("\\", "_")
    rule_key = f"sigma_rules/{user_id}/{safe_id}.yml"

    blob = bucket.blob(rule_key)
    blob.upload_from_string(
        sigma_yaml,
        content_type="application/x-yaml"
    )

    logger.info(f"Saved Sigma rule to gs://{bucket_name}/{rule_key}")
    return rule_key


def save_sigma_rule_metadata(
    user_id: str,
    rule_id: str,
    rule_name: str,
    gcs_key: str,
    schedule: str,
    severity: str,
    mitre_techniques: list,
    mitre_tactics: list,
    confidence_score: float
) -> None:
    """Save Sigma rule metadata to Firestore."""
    from datetime import datetime

    project_id = os.environ.get("GCP_PROJECT_ID")
    client = firestore.Client(project=project_id)

    doc_ref = client.collection("sigma_rules").document(rule_id)
    doc_ref.set({
        "user_id": user_id,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "gcs_key": gcs_key,
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
    })

    logger.info(f"Saved Sigma rule metadata for {rule_id}")


def error_response(request: Request, message: str, status_code: int):
    """Return an error response with secure CORS headers."""
    cors_headers = get_cors_headers(request)
    return (
        json.dumps({"error": message}),
        status_code,
        {"Content-Type": "application/json", **cors_headers}
    )
