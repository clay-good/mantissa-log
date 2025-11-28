"""Generic webhook alert handler."""

import json
from typing import Dict, Optional
import requests

from .base import AlertHandler
from ...detection.alert_generator import Alert


class WebhookHandler(AlertHandler):
    """Handler for sending alerts to generic HTTP webhooks."""

    def __init__(
        self,
        webhook_url: str,
        headers: Optional[Dict[str, str]] = None,
        method: str = "POST",
        timeout: int = 10,
        payload_format: str = "json"
    ):
        """Initialize webhook handler.

        Args:
            webhook_url: Webhook URL
            headers: Optional custom headers
            method: HTTP method (POST or PUT)
            timeout: Request timeout in seconds
            payload_format: Payload format ('json' or 'form')
        """
        self.webhook_url = webhook_url
        self.headers = headers or {"Content-Type": "application/json"}
        self.method = method.upper()
        self.timeout = timeout
        self.payload_format = payload_format

    def validate_config(self) -> bool:
        """Validate webhook configuration.

        Returns:
            True if configuration is valid
        """
        return bool(
            self.webhook_url and
            self.webhook_url.startswith(("http://", "https://")) and
            self.method in ["POST", "PUT"]
        )

    def send(self, alert: Alert) -> bool:
        """Send alert to webhook.

        Args:
            alert: Alert to send

        Returns:
            True if successful
        """
        try:
            payload = self.format_alert(alert)

            if self.method == "POST":
                if self.payload_format == "json":
                    response = requests.post(
                        self.webhook_url,
                        json=payload,
                        headers=self.headers,
                        timeout=self.timeout
                    )
                else:
                    response = requests.post(
                        self.webhook_url,
                        data=payload,
                        headers=self.headers,
                        timeout=self.timeout
                    )
            else:  # PUT
                response = requests.put(
                    self.webhook_url,
                    json=payload,
                    headers=self.headers,
                    timeout=self.timeout
                )

            response.raise_for_status()

            return response.status_code in [200, 201, 202, 204]

        except requests.exceptions.RequestException as e:
            print(f"Error sending to webhook: {e}")
            return False

    def format_alert(self, alert: Alert) -> dict:
        """Format alert as JSON payload.

        Args:
            alert: Alert to format

        Returns:
            Alert payload
        """
        # Standard webhook payload format
        payload = {
            "event_type": "security_alert",
            "timestamp": alert.timestamp.isoformat(),
            "alert": {
                "id": alert.id,
                "severity": alert.severity,
                "title": alert.title,
                "description": alert.description,
                "rule_id": alert.rule_id,
                "rule_name": alert.rule_name,
                "tags": alert.tags,
            },
            "metadata": alert.metadata or {},
        }

        # Add MITRE ATT&CK if present
        if alert.mitre_attack:
            payload["alert"]["mitre_attack"] = alert.mitre_attack

        # Add results summary
        if alert.results:
            payload["results"] = {
                "count": len(alert.results),
                "samples": alert.results[:5]  # First 5 results
            }

        return payload
