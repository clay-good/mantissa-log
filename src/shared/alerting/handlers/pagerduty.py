"""PagerDuty alert handler."""

import json
from typing import Optional
import requests
import logging

from .base import AlertHandler
from ...detection.alert_generator import Alert

logger = logging.getLogger(__name__)


class PagerDutyHandler(AlertHandler):
    """Handler for sending alerts to PagerDuty."""

    def __init__(
        self,
        routing_key: str,
        api_url: str = "https://events.pagerduty.com/v2/enqueue",
        timeout: int = 10
    ):
        """Initialize PagerDuty handler.

        Args:
            routing_key: PagerDuty integration/routing key
            api_url: PagerDuty Events API URL
            timeout: Request timeout in seconds
        """
        self.routing_key = routing_key
        self.api_url = api_url
        self.timeout = timeout

    def validate_config(self) -> bool:
        """Validate PagerDuty configuration.

        Returns:
            True if configuration is valid
        """
        return bool(self.routing_key)

    def send(self, alert: Alert) -> bool:
        """Send alert to PagerDuty.

        Args:
            alert: Alert to send

        Returns:
            True if successful
        """
        try:
            payload = self.format_alert(alert)

            response = requests.post(
                self.api_url,
                json=payload,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"}
            )

            response.raise_for_status()

            return response.status_code == 202

        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending to PagerDuty: {e}")
            return False

    def format_alert(self, alert: Alert) -> dict:
        """Format alert as PagerDuty event.

        Args:
            alert: Alert to format

        Returns:
            PagerDuty event payload
        """
        # Map severity to PagerDuty severity
        severity_map = {
            "critical": "critical",
            "high": "error",
            "medium": "warning",
            "low": "info",
            "info": "info"
        }

        pd_severity = severity_map.get(alert.severity.lower(), "warning")

        # Build custom details
        custom_details = {
            "rule_id": alert.rule_id,
            "rule_name": alert.rule_name,
            "description": alert.description,
            "alert_id": alert.id,
        }

        # Add result count
        if alert.metadata:
            custom_details["result_count"] = alert.metadata.get('result_count', len(alert.results))

        # Add MITRE ATT&CK
        if alert.mitre_attack:
            custom_details["mitre_attack"] = alert.mitre_attack

        # Add tags
        if alert.tags:
            custom_details["tags"] = ", ".join(alert.tags)

        # Add first few results for context
        if alert.results and len(alert.results) > 0:
            custom_details["sample_results"] = alert.results[:3]

        # Build event payload
        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": alert.suppression_key or alert.id,
            "payload": {
                "summary": alert.title,
                "severity": pd_severity,
                "source": "mantissa-log",
                "timestamp": alert.timestamp.isoformat(),
                "component": alert.rule_name,
                "group": alert.severity.lower(),
                "class": "security_alert",
                "custom_details": custom_details
            }
        }

        # Add links if available
        links = []

        # Add MITRE ATT&CK link if applicable
        if alert.mitre_attack and alert.mitre_attack.get('technique'):
            technique_id = alert.mitre_attack['technique']
            links.append({
                "href": f"https://attack.mitre.org/techniques/{technique_id}/",
                "text": f"MITRE ATT&CK: {technique_id}"
            })

        if links:
            payload["payload"]["links"] = links

        return payload

    def resolve_alert(self, dedup_key: str) -> bool:
        """Resolve a previously triggered alert.

        Args:
            dedup_key: Deduplication key of alert to resolve

        Returns:
            True if successful
        """
        try:
            payload = {
                "routing_key": self.routing_key,
                "event_action": "resolve",
                "dedup_key": dedup_key
            }

            response = requests.post(
                self.api_url,
                json=payload,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"}
            )

            response.raise_for_status()

            return response.status_code == 202

        except requests.exceptions.RequestException as e:
            logger.error(f"Error resolving PagerDuty alert: {e}")
            return False
