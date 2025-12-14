"""Microsoft Teams alert handler for sending notifications via webhooks."""

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

from .base import AlertHandler
from ...detection.alert_generator import Alert

logger = logging.getLogger(__name__)


@dataclass
class TeamsActionButton:
    """Represents an action button in Teams message."""
    title: str
    url: str
    style: str = "default"  # default, positive, destructive


class TeamsHandler(AlertHandler):
    """Handler for sending alerts to Microsoft Teams via incoming webhooks.

    Supports both legacy Office 365 Connectors and Workflows webhooks.
    Uses Adaptive Cards for rich message formatting.
    """

    # Severity to color mapping (hex colors for Adaptive Cards)
    SEVERITY_COLORS = {
        "critical": "attention",  # Red
        "high": "warning",        # Orange/Yellow
        "medium": "accent",       # Blue
        "low": "good",            # Green
        "info": "default"         # Gray
    }

    # Severity to hex colors for legacy connectors
    SEVERITY_HEX_COLORS = {
        "critical": "DC2626",
        "high": "EA580C",
        "medium": "F59E0B",
        "low": "10B981",
        "info": "3B82F6"
    }

    def __init__(
        self,
        webhook_url: str,
        title_prefix: str = "Security Alert",
        include_results_preview: bool = True,
        max_results_preview: int = 3,
        action_buttons: Optional[List[TeamsActionButton]] = None,
        mention_users: Optional[List[str]] = None,
        use_adaptive_cards: bool = True,
        timeout: int = 10
    ):
        """Initialize Teams handler.

        Args:
            webhook_url: Teams incoming webhook URL
            title_prefix: Prefix for message titles
            include_results_preview: Whether to include query results preview
            max_results_preview: Maximum number of results to show
            action_buttons: Optional action buttons to add to messages
            mention_users: Optional list of user emails to mention for critical alerts
            use_adaptive_cards: Use Adaptive Cards format (vs legacy MessageCard)
            timeout: Request timeout in seconds
        """
        self.webhook_url = webhook_url
        self.title_prefix = title_prefix
        self.include_results_preview = include_results_preview
        self.max_results_preview = max_results_preview
        self.action_buttons = action_buttons or []
        self.mention_users = mention_users or []
        self.use_adaptive_cards = use_adaptive_cards
        self.timeout = timeout

    def validate_config(self) -> bool:
        """Validate Teams configuration.

        Returns:
            True if configuration is valid
        """
        if not self.webhook_url:
            return False

        # Check for valid Teams webhook URL patterns
        valid_patterns = [
            "webhook.office.com",
            "outlook.office.com",
            ".logic.azure.com",  # Power Automate/Workflows
            "prod-",  # Power Automate regional endpoints
        ]

        return any(pattern in self.webhook_url for pattern in valid_patterns)

    def send(self, alert: Alert) -> bool:
        """Send alert to Microsoft Teams.

        Args:
            alert: Alert to send

        Returns:
            True if successful
        """
        try:
            if self.use_adaptive_cards:
                payload = self._format_adaptive_card(alert)
            else:
                payload = self._format_message_card(alert)

            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout
            )

            # Teams webhooks return 200 with empty body on success
            # or 200 with "1" for legacy connectors
            if response.status_code == 200:
                logger.info(f"Sent alert {alert.id} to Teams")
                return True

            logger.error(f"Teams webhook returned {response.status_code}: {response.text}")
            return False

        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending to Teams: {e}")
            return False

    def format_alert(self, alert: Alert) -> Dict[str, Any]:
        """Format alert for Teams (default to Adaptive Cards).

        Args:
            alert: Alert to format

        Returns:
            Teams message payload
        """
        if self.use_adaptive_cards:
            return self._format_adaptive_card(alert)
        return self._format_message_card(alert)

    def _format_adaptive_card(self, alert: Alert) -> Dict[str, Any]:
        """Format alert as Adaptive Card for Teams.

        Args:
            alert: Alert to format

        Returns:
            Adaptive Card payload
        """
        severity_style = self.SEVERITY_COLORS.get(alert.severity.lower(), "default")

        # Build card body elements
        body = []

        # Header with severity indicator
        body.append({
            "type": "TextBlock",
            "size": "Large",
            "weight": "Bolder",
            "text": f"{self.title_prefix}: {alert.title}",
            "wrap": True,
            "style": severity_style if severity_style != "default" else None
        })

        # Severity badge
        body.append({
            "type": "TextBlock",
            "text": f"**Severity:** {alert.severity.upper()}",
            "wrap": True,
            "color": severity_style if severity_style != "default" else None
        })

        # Description
        if alert.description:
            body.append({
                "type": "TextBlock",
                "text": alert.description,
                "wrap": True
            })

        # Fact set with alert details
        facts = [
            {"title": "Rule", "value": alert.rule_name},
            {"title": "Alert ID", "value": alert.id},
            {"title": "Time", "value": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")}
        ]

        # Add MITRE ATT&CK info
        if alert.mitre_attack:
            tactic = alert.mitre_attack.get("tactic", "N/A")
            technique = alert.mitre_attack.get("technique", "N/A")
            technique_id = alert.mitre_attack.get("technique_id", "")
            mitre_value = f"{tactic} - {technique}"
            if technique_id:
                mitre_value += f" ({technique_id})"
            facts.append({"title": "MITRE ATT&CK", "value": mitre_value})

        # Add result count
        if alert.results:
            facts.append({"title": "Matches", "value": str(len(alert.results))})

        body.append({
            "type": "FactSet",
            "facts": facts
        })

        # Add tags
        if alert.tags:
            tags_text = ", ".join(f"`{tag}`" for tag in alert.tags[:8])
            body.append({
                "type": "TextBlock",
                "text": f"**Tags:** {tags_text}",
                "wrap": True
            })

        # Add results preview
        if self.include_results_preview and alert.results:
            body.append({
                "type": "TextBlock",
                "text": "**Results Preview:**",
                "weight": "Bolder",
                "spacing": "Medium"
            })

            for i, result in enumerate(alert.results[:self.max_results_preview]):
                if isinstance(result, dict):
                    # Format as key-value pairs
                    result_lines = []
                    for key, value in list(result.items())[:5]:
                        result_lines.append(f"• {key}: {str(value)[:80]}")
                    result_text = "\n".join(result_lines)
                else:
                    result_text = str(result)[:200]

                body.append({
                    "type": "TextBlock",
                    "text": result_text,
                    "wrap": True,
                    "fontType": "Monospace",
                    "size": "Small"
                })

            if len(alert.results) > self.max_results_preview:
                body.append({
                    "type": "TextBlock",
                    "text": f"_...and {len(alert.results) - self.max_results_preview} more results_",
                    "isSubtle": True
                })

        # Add enrichment summary if present
        if alert.enrichment and "recommended_actions" in alert.enrichment:
            body.append({
                "type": "TextBlock",
                "text": "**Recommended Actions:**",
                "weight": "Bolder",
                "spacing": "Medium"
            })
            for i, action in enumerate(alert.enrichment["recommended_actions"][:3], 1):
                body.append({
                    "type": "TextBlock",
                    "text": f"{i}. {action}",
                    "wrap": True
                })

        # Build actions
        actions = []

        # Add configured action buttons
        for button in self.action_buttons:
            actions.append({
                "type": "Action.OpenUrl",
                "title": button.title,
                "url": button.url.replace("{{alert_id}}", alert.id)
                                 .replace("{{rule_id}}", alert.rule_id)
            })

        # Add default acknowledge action if no custom actions
        if not actions:
            actions.append({
                "type": "Action.OpenUrl",
                "title": "View Alert",
                "url": f"#alert/{alert.id}"  # Placeholder - should be configured
            })

        # Build the Adaptive Card
        card = {
            "type": "AdaptiveCard",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "version": "1.4",
            "body": body,
            "actions": actions if actions else None
        }

        # Remove None values
        card = {k: v for k, v in card.items() if v is not None}

        # Wrap in message format for Teams webhook
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": card
                }
            ]
        }

    def _format_message_card(self, alert: Alert) -> Dict[str, Any]:
        """Format alert as legacy MessageCard for Teams.

        Args:
            alert: Alert to format

        Returns:
            MessageCard payload (Office 365 Connector format)
        """
        theme_color = self.SEVERITY_HEX_COLORS.get(alert.severity.lower(), "6B7280")

        # Build sections
        sections = []

        # Main section with facts
        facts = [
            {"name": "Rule", "value": alert.rule_name},
            {"name": "Severity", "value": alert.severity.upper()},
            {"name": "Alert ID", "value": alert.id},
            {"name": "Time", "value": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")}
        ]

        if alert.mitre_attack:
            tactic = alert.mitre_attack.get("tactic", "N/A")
            technique = alert.mitre_attack.get("technique", "N/A")
            facts.append({"name": "MITRE ATT&CK", "value": f"{tactic} - {technique}"})

        if alert.results:
            facts.append({"name": "Matches", "value": str(len(alert.results))})

        main_section = {
            "activityTitle": alert.title,
            "activitySubtitle": alert.description or "",
            "facts": facts,
            "markdown": True
        }
        sections.append(main_section)

        # Tags section
        if alert.tags:
            tags_text = ", ".join(f"`{tag}`" for tag in alert.tags[:8])
            sections.append({
                "text": f"**Tags:** {tags_text}",
                "markdown": True
            })

        # Results preview
        if self.include_results_preview and alert.results:
            results_text = "**Results Preview:**\n\n"
            for i, result in enumerate(alert.results[:self.max_results_preview]):
                if isinstance(result, dict):
                    for key, value in list(result.items())[:3]:
                        results_text += f"• {key}: {str(value)[:50]}\n"
                else:
                    results_text += f"• {str(result)[:100]}\n"
                results_text += "\n"

            if len(alert.results) > self.max_results_preview:
                results_text += f"_...and {len(alert.results) - self.max_results_preview} more results_"

            sections.append({
                "text": results_text,
                "markdown": True
            })

        # Build potential actions
        potential_actions = []
        for button in self.action_buttons:
            potential_actions.append({
                "@type": "OpenUri",
                "name": button.title,
                "targets": [
                    {
                        "os": "default",
                        "uri": button.url.replace("{{alert_id}}", alert.id)
                                        .replace("{{rule_id}}", alert.rule_id)
                    }
                ]
            })

        # Build the MessageCard
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": theme_color,
            "summary": f"{self.title_prefix}: {alert.title}",
            "sections": sections,
            "potentialAction": potential_actions if potential_actions else None
        }

    def send_test_message(self) -> Dict[str, Any]:
        """Send a test message to verify webhook configuration.

        Returns:
            Dict with success status and message
        """
        test_alert = Alert(
            id=f"test-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            title="Mantissa Log Integration Test",
            description="This is a test message to verify Microsoft Teams integration. If you see this, the webhook is working correctly!",
            severity="info",
            rule_id="test-rule",
            rule_name="Integration Test",
            timestamp=datetime.utcnow(),
            results=[
                {"event": "test_event", "source": "integration_test", "status": "success"}
            ],
            tags=["test", "integration-verification"],
            metadata={"test": True}
        )

        success = self.send(test_alert)

        return {
            "success": success,
            "message": "Test message sent successfully" if success else "Failed to send test message"
        }


class TeamsWorkflowHandler(TeamsHandler):
    """Handler for Microsoft Teams using Power Automate Workflows.

    This handler supports the newer Workflows integration which replaces
    Office 365 Connectors. It uses the same Adaptive Card format but
    may require different webhook URL patterns.
    """

    def __init__(
        self,
        webhook_url: str,
        workflow_name: str = "Mantissa Log Alerts",
        **kwargs
    ):
        """Initialize Teams Workflow handler.

        Args:
            webhook_url: Power Automate workflow webhook URL
            workflow_name: Name of the workflow for logging
            **kwargs: Additional arguments passed to TeamsHandler
        """
        super().__init__(webhook_url=webhook_url, **kwargs)
        self.workflow_name = workflow_name

    def validate_config(self) -> bool:
        """Validate Teams Workflow configuration.

        Returns:
            True if configuration is valid
        """
        if not self.webhook_url:
            return False

        # Power Automate workflow URLs
        valid_patterns = [
            ".logic.azure.com",
            "prod-",
            "flow.microsoft.com"
        ]

        return any(pattern in self.webhook_url for pattern in valid_patterns)

    def send(self, alert: Alert) -> bool:
        """Send alert via Power Automate workflow.

        Args:
            alert: Alert to send

        Returns:
            True if successful
        """
        try:
            # Power Automate workflows expect a specific format
            payload = self._format_workflow_payload(alert)

            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout
            )

            # Workflows typically return 202 Accepted
            if response.status_code in (200, 202):
                logger.info(f"Sent alert {alert.id} via Teams Workflow")
                return True

            logger.error(f"Teams Workflow returned {response.status_code}: {response.text}")
            return False

        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending to Teams Workflow: {e}")
            return False

    def _format_workflow_payload(self, alert: Alert) -> Dict[str, Any]:
        """Format payload for Power Automate workflow.

        Args:
            alert: Alert to format

        Returns:
            Workflow-compatible payload
        """
        # Get the Adaptive Card
        card_payload = self._format_adaptive_card(alert)

        # Workflows may need additional metadata
        return {
            "type": "message",
            "attachments": card_payload.get("attachments", []),
            # Additional fields that workflows might use
            "alert_id": alert.id,
            "severity": alert.severity,
            "rule_name": alert.rule_name,
            "timestamp": alert.timestamp.isoformat()
        }
