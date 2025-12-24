"""Action code templates for playbook code generation.

This module provides parameterized Python code templates for each ActionType.
Templates are designed to be safe, auditable, and integrate with existing
provider action implementations.

Each template generates code that:
- Uses the existing provider_actions module
- Includes proper error handling and logging
- Returns a standardized result dictionary
- Supports dry run mode
"""

from typing import Dict

from .playbook import ActionType


# Template for rendering Jinja2 parameters
RENDER_TEMPLATE_FUNCTION = '''
def render_template(template_str: str, context: Dict[str, Any]) -> str:
    """Render a Jinja2 template with the given context."""
    if not template_str:
        return ""
    try:
        template = Template(template_str)
        return template.render(**context)
    except Exception as e:
        logger.warning(f"Template rendering failed: {e}, template: {template_str}")
        return template_str
'''

# Template for getting provider clients
GET_PROVIDER_CLIENT_FUNCTION = '''
def get_provider_client(provider: str, dry_run: bool = True) -> IdentityProviderActions:
    """Get the appropriate provider client for the given provider name."""
    provider_map = {
        "okta": OktaActions,
        "azure": AzureActions,
        "google_workspace": GoogleWorkspaceActions,
        "google": GoogleWorkspaceActions,
        "duo": DuoActions,
    }

    provider_lower = provider.lower() if provider else "okta"
    if provider_lower == "auto":
        # Default to Okta for auto-detection
        provider_lower = "okta"

    provider_class = provider_map.get(provider_lower, OktaActions)
    return provider_class(dry_run=dry_run)
'''


# Action-specific code templates
# Each template is a string with {param} placeholders for customization

ACTION_TEMPLATES: Dict[ActionType, str] = {
    ActionType.TERMINATE_SESSIONS: '''
def step_{step_id}(context: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Step: {step_name}

    Action: Terminate all active sessions for the target user.
    """
    try:
        user_id = render_template("{user_id_template}", context)
        provider_name = "{provider}"
        reason = render_template("{reason_template}", context)

        logger.info(f"Terminating sessions for user: {{user_id}}, provider: {{provider_name}}")

        client = get_provider_client(provider_name, dry_run=dry_run)
        result = client.terminate_user_sessions(user_id)

        if result.success:
            logger.info(f"Sessions terminated successfully for {{user_id}}")
            return {{
                "success": True,
                "output": result.to_dict(),
                "next_step_id": "{on_success}"
            }}
        else:
            logger.error(f"Failed to terminate sessions: {{result.error}}")
            return {{
                "success": False,
                "error": result.error,
                "output": result.to_dict(),
                "next_step_id": "{on_failure}"
            }}
    except Exception as e:
        logger.exception(f"Step {step_id} failed with exception")
        return {{"success": False, "error": str(e), "next_step_id": "{on_failure}"}}
''',

    ActionType.DISABLE_ACCOUNT: '''
def step_{step_id}(context: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Step: {step_name}

    Action: Disable user account.
    WARNING: This is a dangerous action that affects user access.
    """
    try:
        user_id = render_template("{user_id_template}", context)
        provider_name = "{provider}"
        reason = render_template("{reason_template}", context)

        logger.info(f"Disabling account for user: {{user_id}}, provider: {{provider_name}}, reason: {{reason}}")

        client = get_provider_client(provider_name, dry_run=dry_run)
        result = client.disable_user_account(user_id)

        if result.success:
            logger.info(f"Account disabled successfully for {{user_id}}")
            return {{
                "success": True,
                "output": result.to_dict(),
                "next_step_id": "{on_success}"
            }}
        else:
            logger.error(f"Failed to disable account: {{result.error}}")
            return {{
                "success": False,
                "error": result.error,
                "output": result.to_dict(),
                "next_step_id": "{on_failure}"
            }}
    except Exception as e:
        logger.exception(f"Step {step_id} failed with exception")
        return {{"success": False, "error": str(e), "next_step_id": "{on_failure}"}}
''',

    ActionType.ENABLE_ACCOUNT: '''
def step_{step_id}(context: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Step: {step_name}

    Action: Enable (re-activate) user account.
    """
    try:
        user_id = render_template("{user_id_template}", context)
        provider_name = "{provider}"

        logger.info(f"Enabling account for user: {{user_id}}, provider: {{provider_name}}")

        client = get_provider_client(provider_name, dry_run=dry_run)
        result = client.enable_user_account(user_id)

        if result.success:
            logger.info(f"Account enabled successfully for {{user_id}}")
            return {{
                "success": True,
                "output": result.to_dict(),
                "next_step_id": "{on_success}"
            }}
        else:
            logger.error(f"Failed to enable account: {{result.error}}")
            return {{
                "success": False,
                "error": result.error,
                "output": result.to_dict(),
                "next_step_id": "{on_failure}"
            }}
    except Exception as e:
        logger.exception(f"Step {step_id} failed with exception")
        return {{"success": False, "error": str(e), "next_step_id": "{on_failure}"}}
''',

    ActionType.FORCE_PASSWORD_RESET: '''
def step_{step_id}(context: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Step: {step_name}

    Action: Force password reset for user.
    WARNING: This is a dangerous action that affects user authentication.
    """
    try:
        user_id = render_template("{user_id_template}", context)
        provider_name = "{provider}"
        notify_user = {notify_user}
        message = render_template("{message_template}", context)

        logger.info(f"Forcing password reset for user: {{user_id}}, provider: {{provider_name}}")

        client = get_provider_client(provider_name, dry_run=dry_run)
        result = client.force_password_reset(user_id)

        if result.success:
            logger.info(f"Password reset forced successfully for {{user_id}}")
            return {{
                "success": True,
                "output": {{**result.to_dict(), "notify_user": notify_user, "message": message}},
                "next_step_id": "{on_success}"
            }}
        else:
            logger.error(f"Failed to force password reset: {{result.error}}")
            return {{
                "success": False,
                "error": result.error,
                "output": result.to_dict(),
                "next_step_id": "{on_failure}"
            }}
    except Exception as e:
        logger.exception(f"Step {step_id} failed with exception")
        return {{"success": False, "error": str(e), "next_step_id": "{on_failure}"}}
''',

    ActionType.REVOKE_TOKENS: '''
def step_{step_id}(context: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Step: {step_name}

    Action: Revoke all OAuth tokens and API keys for user.
    WARNING: This is a dangerous action that affects user integrations.
    """
    try:
        user_id = render_template("{user_id_template}", context)
        provider_name = "{provider}"

        logger.info(f"Revoking tokens for user: {{user_id}}, provider: {{provider_name}}")

        client = get_provider_client(provider_name, dry_run=dry_run)
        result = client.revoke_tokens(user_id)

        if result.success:
            logger.info(f"Tokens revoked successfully for {{user_id}}")
            return {{
                "success": True,
                "output": result.to_dict(),
                "next_step_id": "{on_success}"
            }}
        else:
            logger.error(f"Failed to revoke tokens: {{result.error}}")
            return {{
                "success": False,
                "error": result.error,
                "output": result.to_dict(),
                "next_step_id": "{on_failure}"
            }}
    except Exception as e:
        logger.exception(f"Step {step_id} failed with exception")
        return {{"success": False, "error": str(e), "next_step_id": "{on_failure}"}}
''',

    ActionType.BLOCK_IP: '''
def step_{step_id}(context: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Step: {step_name}

    Action: Block IP address at firewall/WAF.
    WARNING: This is a dangerous action that affects network access.
    """
    try:
        ip_address = render_template("{ip_address_template}", context)
        duration = "{duration}"
        reason = render_template("{reason_template}", context)

        logger.info(f"Blocking IP address: {{ip_address}}, duration: {{duration}}, reason: {{reason}}")

        # IP blocking is provider-agnostic, using a simple implementation
        if dry_run:
            logger.info(f"[DRY RUN] Would block IP: {{ip_address}}")
            return {{
                "success": True,
                "output": {{
                    "ip_address": ip_address,
                    "duration": duration,
                    "reason": reason,
                    "dry_run": True,
                    "message": "Dry run - no action taken"
                }},
                "next_step_id": "{on_success}"
            }}

        # Production implementation would call firewall/WAF API
        logger.warning(f"IP blocking not implemented for production. IP: {{ip_address}}")
        return {{
            "success": False,
            "error": "Production IP blocking not configured",
            "output": {{"ip_address": ip_address}},
            "next_step_id": "{on_failure}"
        }}
    except Exception as e:
        logger.exception(f"Step {step_id} failed with exception")
        return {{"success": False, "error": str(e), "next_step_id": "{on_failure}"}}
''',

    ActionType.UNBLOCK_IP: '''
def step_{step_id}(context: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Step: {step_name}

    Action: Remove IP address block from firewall/WAF.
    """
    try:
        ip_address = render_template("{ip_address_template}", context)

        logger.info(f"Unblocking IP address: {{ip_address}}")

        if dry_run:
            logger.info(f"[DRY RUN] Would unblock IP: {{ip_address}}")
            return {{
                "success": True,
                "output": {{
                    "ip_address": ip_address,
                    "dry_run": True,
                    "message": "Dry run - no action taken"
                }},
                "next_step_id": "{on_success}"
            }}

        logger.warning(f"IP unblocking not implemented for production. IP: {{ip_address}}")
        return {{
            "success": False,
            "error": "Production IP unblocking not configured",
            "output": {{"ip_address": ip_address}},
            "next_step_id": "{on_failure}"
        }}
    except Exception as e:
        logger.exception(f"Step {step_id} failed with exception")
        return {{"success": False, "error": str(e), "next_step_id": "{on_failure}"}}
''',

    ActionType.ISOLATE_HOST: '''
def step_{step_id}(context: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Step: {step_name}

    Action: Network isolate host via EDR.
    WARNING: This is a dangerous action that affects endpoint connectivity.
    """
    try:
        host_id = render_template("{host_id_template}", context)
        hostname = render_template("{hostname_template}", context)
        reason = render_template("{reason_template}", context)

        target = host_id or hostname
        logger.info(f"Isolating host: {{target}}, reason: {{reason}}")

        if dry_run:
            logger.info(f"[DRY RUN] Would isolate host: {{target}}")
            return {{
                "success": True,
                "output": {{
                    "host_id": host_id,
                    "hostname": hostname,
                    "reason": reason,
                    "dry_run": True,
                    "message": "Dry run - no action taken"
                }},
                "next_step_id": "{on_success}"
            }}

        # Production implementation would call EDR API (CrowdStrike, SentinelOne, etc.)
        logger.warning(f"Host isolation not implemented for production. Host: {{target}}")
        return {{
            "success": False,
            "error": "Production host isolation not configured",
            "output": {{"host_id": host_id, "hostname": hostname}},
            "next_step_id": "{on_failure}"
        }}
    except Exception as e:
        logger.exception(f"Step {step_id} failed with exception")
        return {{"success": False, "error": str(e), "next_step_id": "{on_failure}"}}
''',

    ActionType.UNISOLATE_HOST: '''
def step_{step_id}(context: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Step: {step_name}

    Action: Remove network isolation from host.
    """
    try:
        host_id = render_template("{host_id_template}", context)
        hostname = render_template("{hostname_template}", context)

        target = host_id or hostname
        logger.info(f"Removing isolation from host: {{target}}")

        if dry_run:
            logger.info(f"[DRY RUN] Would unisolate host: {{target}}")
            return {{
                "success": True,
                "output": {{
                    "host_id": host_id,
                    "hostname": hostname,
                    "dry_run": True,
                    "message": "Dry run - no action taken"
                }},
                "next_step_id": "{on_success}"
            }}

        logger.warning(f"Host unisolation not implemented for production. Host: {{target}}")
        return {{
            "success": False,
            "error": "Production host unisolation not configured",
            "output": {{"host_id": host_id, "hostname": hostname}},
            "next_step_id": "{on_failure}"
        }}
    except Exception as e:
        logger.exception(f"Step {step_id} failed with exception")
        return {{"success": False, "error": str(e), "next_step_id": "{on_failure}"}}
''',

    ActionType.NOTIFY: '''
def step_{step_id}(context: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Step: {step_name}

    Action: Send notification via Slack, email, or PagerDuty.
    """
    try:
        provider = "{provider}"
        channel = render_template("{channel_template}", context)
        message = render_template("{message_template}", context)

        logger.info(f"Sending notification via {{provider}} to {{channel}}")

        if dry_run:
            logger.info(f"[DRY RUN] Would send notification: {{message[:100]}}...")
            return {{
                "success": True,
                "output": {{
                    "provider": provider,
                    "channel": channel,
                    "message": message,
                    "dry_run": True,
                    "message_preview": message[:200]
                }},
                "next_step_id": "{on_success}"
            }}

        # Production implementation would call notification API
        if provider == "slack":
            # Would call Slack webhook
            logger.warning(f"Slack notification not implemented. Channel: {{channel}}")
        elif provider == "pagerduty":
            # Would call PagerDuty API
            logger.warning(f"PagerDuty notification not implemented.")
        elif provider == "email":
            # Would call email service
            logger.warning(f"Email notification not implemented.")

        return {{
            "success": True,  # Notifications typically don't fail the playbook
            "output": {{"provider": provider, "channel": channel, "sent": False}},
            "next_step_id": "{on_success}"
        }}
    except Exception as e:
        logger.exception(f"Step {step_id} failed with exception")
        return {{"success": True, "error": str(e), "next_step_id": "{on_success}"}}  # Don't fail on notification errors
''',

    ActionType.CREATE_TICKET: '''
def step_{step_id}(context: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Step: {step_name}

    Action: Create ticket in Jira, ServiceNow, or other ticketing system.
    """
    try:
        provider = "{provider}"
        project = render_template("{project_template}", context)
        issue_type = render_template("{issue_type_template}", context)
        summary = render_template("{summary_template}", context)
        description = render_template("{description_template}", context)
        priority = render_template("{priority_template}", context)
        labels = {labels}
        assignee = render_template("{assignee_template}", context)

        logger.info(f"Creating ticket in {{provider}}: {{summary}}")

        if dry_run:
            ticket_id = f"DRY-RUN-{{str(uuid.uuid4())[:8].upper()}}"
            logger.info(f"[DRY RUN] Would create ticket: {{ticket_id}}")
            return {{
                "success": True,
                "output": {{
                    "ticket_id": ticket_id,
                    "ticket_url": f"https://{{provider}}.example.com/browse/{{ticket_id}}",
                    "project": project,
                    "summary": summary,
                    "dry_run": True
                }},
                "next_step_id": "{on_success}"
            }}

        # Production implementation would call ticketing API
        if provider == "jira":
            logger.warning(f"Jira ticket creation not implemented. Project: {{project}}")
        elif provider == "servicenow":
            logger.warning(f"ServiceNow ticket creation not implemented.")

        return {{
            "success": False,
            "error": f"Production {{provider}} integration not configured",
            "output": {{"project": project, "summary": summary}},
            "next_step_id": "{on_failure}"
        }}
    except Exception as e:
        logger.exception(f"Step {step_id} failed with exception")
        return {{"success": False, "error": str(e), "next_step_id": "{on_failure}"}}
''',

    ActionType.RUN_QUERY: '''
def step_{step_id}(context: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Step: {step_name}

    Action: Run investigation query.
    """
    try:
        query = render_template("{query_template}", context)
        query_type = "{query_type}"
        time_range = "{time_range}"

        logger.info(f"Running query: {{query[:100]}}...")

        if dry_run:
            logger.info(f"[DRY RUN] Would execute query")
            return {{
                "success": True,
                "output": {{
                    "query": query,
                    "query_type": query_type,
                    "time_range": time_range,
                    "dry_run": True,
                    "results": []
                }},
                "next_step_id": "{on_success}"
            }}

        # Production implementation would execute query via Athena or other backend
        logger.warning(f"Query execution not implemented for production.")
        return {{
            "success": False,
            "error": "Production query execution not configured",
            "output": {{"query": query}},
            "next_step_id": "{on_failure}"
        }}
    except Exception as e:
        logger.exception(f"Step {step_id} failed with exception")
        return {{"success": False, "error": str(e), "next_step_id": "{on_failure}"}}
''',

    ActionType.WEBHOOK: '''
def step_{step_id}(context: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Step: {step_name}

    Action: Call external webhook.
    """
    try:
        import urllib.request
        import urllib.error

        url = render_template("{url_template}", context)
        method = "{method}"
        headers = {headers}
        body = render_template("{body_template}", context)

        logger.info(f"Calling webhook: {{method}} {{url}}")

        if dry_run:
            logger.info(f"[DRY RUN] Would call webhook")
            return {{
                "success": True,
                "output": {{
                    "url": url,
                    "method": method,
                    "dry_run": True
                }},
                "next_step_id": "{on_success}"
            }}

        # Make the webhook call
        try:
            req = urllib.request.Request(
                url,
                data=body.encode() if body else None,
                headers=headers,
                method=method
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                response_body = response.read().decode()
                return {{
                    "success": True,
                    "output": {{
                        "url": url,
                        "status_code": response.status,
                        "response": response_body[:1000]
                    }},
                    "next_step_id": "{on_success}"
                }}
        except urllib.error.HTTPError as e:
            return {{
                "success": False,
                "error": f"HTTP {{e.code}}: {{e.reason}}",
                "output": {{"url": url}},
                "next_step_id": "{on_failure}"
            }}
    except Exception as e:
        logger.exception(f"Step {step_id} failed with exception")
        return {{"success": False, "error": str(e), "next_step_id": "{on_failure}"}}
''',

    ActionType.CUSTOM: '''
def step_{step_id}(context: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Step: {step_name}

    Action: Custom action (placeholder).
    Note: Custom actions should be reviewed for security before deployment.
    """
    try:
        logger.info(f"Executing custom action: {step_id}")

        if dry_run:
            logger.info(f"[DRY RUN] Would execute custom action")
            return {{
                "success": True,
                "output": {{
                    "action": "custom",
                    "step_id": "{step_id}",
                    "dry_run": True
                }},
                "next_step_id": "{on_success}"
            }}

        # Custom action implementation would go here
        # For security, custom actions are disabled by default
        logger.warning(f"Custom action execution disabled. Step: {step_id}")
        return {{
            "success": False,
            "error": "Custom actions are disabled for security",
            "next_step_id": "{on_failure}"
        }}
    except Exception as e:
        logger.exception(f"Step {step_id} failed with exception")
        return {{"success": False, "error": str(e), "next_step_id": "{on_failure}"}}
''',
}


# Lambda handler template
LAMBDA_HANDLER_TEMPLATE = '''
def lambda_handler(event: Dict[str, Any], lambda_context: Any) -> Dict[str, Any]:
    """Main playbook execution handler.

    Playbook: {playbook_name}
    Version: {playbook_version}

    Args:
        event: Trigger event containing:
            - trigger_type: "alert", "manual", "scheduled", or "webhook"
            - alert: Alert data (for alert triggers)
            - parameters: Manual trigger parameters
            - dry_run: Whether to execute in dry run mode
        lambda_context: AWS Lambda context

    Returns:
        Execution result dictionary
    """
    execution_id = str(uuid.uuid4())
    start_time = datetime.utcnow()

    logger.info(f"Starting playbook execution: {{execution_id}}")

    # Extract trigger context
    trigger_type = event.get("trigger_type", "manual")
    alert_data = event.get("alert", {{}})
    parameters = event.get("parameters", {{}})
    dry_run = event.get("dry_run", True)

    # Build execution context
    context = {{
        "execution": {{
            "id": execution_id,
            "started_at": start_time.isoformat(),
            "trigger_type": trigger_type,
        }},
        "alert": alert_data,
        "parameters": parameters,
        "steps": {{}},
    }}

    step_results = []
    current_step_id = "{first_step_id}"
    final_status = "completed"
    error_message = None

    # Step function map
    step_functions = {{
{step_function_map}
    }}

    # Execute steps
    while current_step_id:
        step_func = step_functions.get(current_step_id)
        if not step_func:
            logger.error(f"Unknown step: {{current_step_id}}")
            final_status = "failed"
            error_message = f"Unknown step: {{current_step_id}}"
            break

        step_start = datetime.utcnow()
        logger.info(f"Executing step: {{current_step_id}}")

        try:
            result = step_func(context, dry_run=dry_run)

            step_result = {{
                "step_id": current_step_id,
                "started_at": step_start.isoformat(),
                "completed_at": datetime.utcnow().isoformat(),
                "success": result.get("success", False),
                "output": result.get("output", {{}}),
                "error": result.get("error"),
            }}
            step_results.append(step_result)

            # Store step output in context for subsequent steps
            context["steps"][current_step_id] = {{
                "output": result.get("output", {{}})
            }}

            # Determine next step
            if result.get("success"):
                current_step_id = result.get("next_step_id")
            else:
                current_step_id = result.get("next_step_id")
                if not current_step_id:
                    final_status = "failed"
                    error_message = result.get("error", "Step failed")
                    break
        except Exception as e:
            logger.exception(f"Step {{current_step_id}} raised exception")
            step_results.append({{
                "step_id": current_step_id,
                "started_at": step_start.isoformat(),
                "completed_at": datetime.utcnow().isoformat(),
                "success": False,
                "error": str(e),
            }})
            final_status = "failed"
            error_message = str(e)
            break

    end_time = datetime.utcnow()
    duration_ms = int((end_time - start_time).total_seconds() * 1000)

    execution_result = {{
        "execution_id": execution_id,
        "playbook_id": "{playbook_id}",
        "playbook_version": "{playbook_version}",
        "trigger_type": trigger_type,
        "status": final_status,
        "started_at": start_time.isoformat(),
        "completed_at": end_time.isoformat(),
        "duration_ms": duration_ms,
        "step_results": step_results,
        "dry_run": dry_run,
    }}

    if error_message:
        execution_result["error"] = error_message

    logger.info(f"Playbook execution completed: {{execution_id}}, status: {{final_status}}")

    return execution_result
'''


# File header template
FILE_HEADER_TEMPLATE = '''"""
Playbook: {playbook_name}
ID: {playbook_id}
Version: {playbook_version}
Author: {author}
Generated: {generated_at}

Description:
{description}

WARNING: This is auto-generated code. Review before deployment.
Do not modify directly - regenerate from playbook definition.
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict

from jinja2 import Template

from shared.identity.response.provider_actions import (
    IdentityProviderActions,
    OktaActions,
    AzureActions,
    GoogleWorkspaceActions,
    DuoActions,
    ProviderActionResult,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

'''
