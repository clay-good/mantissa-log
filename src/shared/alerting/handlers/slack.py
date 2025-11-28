"""Slack alert handler."""

import json
from typing import Optional
import requests

from .base import AlertHandler
from ...detection.alert_generator import Alert


class SlackHandler(AlertHandler):
    """Handler for sending alerts to Slack via webhooks."""

    def __init__(
        self,
        webhook_url: str,
        channel: Optional[str] = None,
        username: str = "Mantissa Log",
        icon_emoji: str = ":shield:",
        timeout: int = 10
    ):
        """Initialize Slack handler.

        Args:
            webhook_url: Slack webhook URL
            channel: Optional channel override
            username: Bot username
            icon_emoji: Bot icon emoji
            timeout: Request timeout in seconds
        """
        self.webhook_url = webhook_url
        self.channel = channel
        self.username = username
        self.icon_emoji = icon_emoji
        self.timeout = timeout

    def validate_config(self) -> bool:
        """Validate Slack configuration.

        Returns:
            True if configuration is valid
        """
        return bool(self.webhook_url and self.webhook_url.startswith("https://hooks.slack.com/"))

    def send(self, alert: Alert) -> bool:
        """Send alert to Slack.

        Args:
            alert: Alert to send

        Returns:
            True if successful
        """
        try:
            payload = self.format_alert(alert)

            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=self.timeout
            )

            response.raise_for_status()

            return response.status_code == 200

        except requests.exceptions.RequestException as e:
            print(f"Error sending to Slack: {e}")
            return False

    def format_alert(self, alert: Alert) -> dict:
        """Format alert as Slack message with Block Kit.

        Args:
            alert: Alert to format

        Returns:
            Slack message payload
        """
        # Severity color mapping
        severity_colors = {
            "critical": "#DC2626",  # Red
            "high": "#EA580C",      # Orange
            "medium": "#F59E0B",    # Amber
            "low": "#10B981",       # Green
            "info": "#3B82F6"       # Blue
        }

        color = severity_colors.get(alert.severity.lower(), "#6B7280")

        # Build blocks
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{alert.severity.upper()}: {alert.title}",
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": alert.description
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Rule:*\n{alert.rule_name}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{alert.severity.upper()}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Alert ID:*\n{alert.id}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Time:*\n{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                    }
                ]
            }
        ]

        # Add MITRE ATT&CK if present
        if alert.mitre_attack:
            tactic = alert.mitre_attack.get('tactic', 'N/A')
            technique = alert.mitre_attack.get('technique', 'N/A')

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*MITRE ATT&CK:* {tactic} - {technique}"
                }
            })

        # Add metadata if present
        if alert.metadata:
            result_count = alert.metadata.get('result_count', len(alert.results))
            if result_count:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Results:* {result_count} matches"
                    }
                })

        # Add tags
        if alert.tags:
            tags_str = ", ".join(f"`{tag}`" for tag in alert.tags[:5])
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Tags:* {tags_str}"
                }
            })

        # Build payload
        payload = {
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks,
                    "footer": "Mantissa Log",
                    "ts": int(alert.timestamp.timestamp())
                }
            ]
        }

        # Add channel override if specified
        if self.channel:
            payload["channel"] = self.channel

        return payload
