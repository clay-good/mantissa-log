"""Alert generation and enrichment for detection results."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import hashlib
import json


@dataclass
class Alert:
    """Represents a security alert."""

    id: str
    rule_id: str
    rule_name: str
    severity: str
    title: str
    description: str
    timestamp: datetime
    destinations: List[str] = field(default_factory=list)
    results: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    mitre_attack: Optional[Dict[str, str]] = None
    tags: List[str] = field(default_factory=list)
    suppression_key: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary format.

        Returns:
            Dictionary representation
        """
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "destinations": self.destinations,
            "results": self.results,
            "metadata": self.metadata,
            "mitre_attack": self.mitre_attack,
            "tags": self.tags,
            "suppression_key": self.suppression_key,
        }

    def to_json(self) -> str:
        """Convert alert to JSON string.

        Returns:
            JSON string
        """
        return json.dumps(self.to_dict(), indent=2)


class AlertGenerator:
    """Generates alerts from detection results."""

    def __init__(self, enrichment_config: Optional[Dict[str, Any]] = None):
        """Initialize alert generator.

        Args:
            enrichment_config: Configuration for alert enrichment
        """
        self.enrichment_config = enrichment_config or {}

    def generate_alert(
        self,
        rule_id: str,
        rule_name: str,
        severity: str,
        title: str,
        description: str,
        results: List[Dict[str, Any]],
        destinations: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        mitre_attack: Optional[Dict[str, str]] = None,
        suppression_key: Optional[str] = None
    ) -> Alert:
        """Generate an alert from detection results.

        Args:
            rule_id: Rule identifier
            rule_name: Rule name
            severity: Alert severity
            title: Alert title
            description: Alert description
            results: Detection query results
            destinations: Alert destinations
            tags: Alert tags
            mitre_attack: MITRE ATT&CK mapping
            suppression_key: Suppression key for deduplication

        Returns:
            Alert object
        """
        # Generate unique alert ID
        alert_id = self._generate_alert_id(
            rule_id,
            title,
            results,
            datetime.utcnow()
        )

        # Enrich alert with additional context
        metadata = self._enrich_alert(results)

        # Create alert
        alert = Alert(
            id=alert_id,
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            title=title,
            description=description,
            timestamp=datetime.utcnow(),
            destinations=destinations or [],
            results=results,
            metadata=metadata,
            mitre_attack=mitre_attack,
            tags=tags or [],
            suppression_key=suppression_key
        )

        return alert

    def _generate_alert_id(
        self,
        rule_id: str,
        title: str,
        results: List[Dict[str, Any]],
        timestamp: datetime
    ) -> str:
        """Generate a unique alert ID.

        Args:
            rule_id: Rule identifier
            title: Alert title
            results: Detection results
            timestamp: Alert timestamp

        Returns:
            Unique alert ID
        """
        # Create hash from rule_id, title, and timestamp
        data = f"{rule_id}:{title}:{timestamp.isoformat()}"
        hash_obj = hashlib.sha256(data.encode())
        return hash_obj.hexdigest()[:16]

    def _enrich_alert(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Enrich alert with additional context.

        Args:
            results: Detection query results

        Returns:
            Enrichment metadata
        """
        metadata = {
            "result_count": len(results),
            "enrichment_timestamp": datetime.utcnow().isoformat(),
        }

        if not results:
            return metadata

        # Extract common fields
        first_result = results[0]

        # IP enrichment
        if "source_ip" in first_result:
            metadata["source_ip"] = first_result["source_ip"]
            # Add IP reputation lookup if configured
            if "ip_reputation" in self.enrichment_config:
                metadata["ip_reputation"] = self._lookup_ip_reputation(
                    first_result["source_ip"]
                )

        if "destination_ip" in first_result:
            metadata["destination_ip"] = first_result["destination_ip"]

        # User enrichment
        if "user" in first_result:
            metadata["user"] = first_result["user"]
            # Add user context if configured
            if "user_lookup" in self.enrichment_config:
                metadata["user_context"] = self._lookup_user_context(
                    first_result["user"]
                )

        # Geolocation enrichment
        if "source_ip" in first_result and "geolocation" in self.enrichment_config:
            metadata["geolocation"] = self._lookup_geolocation(
                first_result["source_ip"]
            )

        # Extract unique values for aggregate fields
        metadata["unique_users"] = len(set(
            r.get("user", "") for r in results if r.get("user")
        ))
        metadata["unique_source_ips"] = len(set(
            r.get("source_ip", "") for r in results if r.get("source_ip")
        ))

        return metadata

    def _lookup_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Look up IP reputation.

        Args:
            ip_address: IP address to look up

        Returns:
            Reputation data
        """
        # Placeholder for IP reputation lookup
        # In production, this would call an IP reputation service
        return {
            "ip": ip_address,
            "reputation": "unknown",
            "source": "placeholder"
        }

    def _lookup_user_context(self, user: str) -> Dict[str, Any]:
        """Look up user context information.

        Args:
            user: Username or user ID

        Returns:
            User context data
        """
        # Placeholder for user context lookup
        # In production, this would query user directory or HR system
        return {
            "user": user,
            "department": "unknown",
            "role": "unknown",
            "source": "placeholder"
        }

    def _lookup_geolocation(self, ip_address: str) -> Dict[str, Any]:
        """Look up geolocation for IP address.

        Args:
            ip_address: IP address to geolocate

        Returns:
            Geolocation data
        """
        # Placeholder for geolocation lookup
        # In production, this would use MaxMind GeoIP or similar
        return {
            "ip": ip_address,
            "country": "unknown",
            "city": "unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "source": "placeholder"
        }

    def format_for_slack(self, alert: Alert) -> Dict[str, Any]:
        """Format alert for Slack.

        Args:
            alert: Alert to format

        Returns:
            Slack message payload
        """
        # Severity color mapping
        severity_colors = {
            "critical": "#ff0000",
            "high": "#ff6600",
            "medium": "#ffaa00",
            "low": "#ffdd00",
            "info": "#00aaff"
        }

        color = severity_colors.get(alert.severity, "#999999")

        # Build fields
        fields = [
            {
                "title": "Severity",
                "value": alert.severity.upper(),
                "short": True
            },
            {
                "title": "Rule",
                "value": alert.rule_name,
                "short": True
            },
            {
                "title": "Results",
                "value": str(alert.metadata.get("result_count", 0)),
                "short": True
            },
            {
                "title": "Time",
                "value": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "short": True
            }
        ]

        # Add MITRE ATT&CK if present
        if alert.mitre_attack:
            fields.append({
                "title": "MITRE ATT&CK",
                "value": f"{alert.mitre_attack.get('tactic', '')} - {alert.mitre_attack.get('technique', '')}",
                "short": False
            })

        return {
            "attachments": [
                {
                    "color": color,
                    "title": alert.title,
                    "text": alert.description,
                    "fields": fields,
                    "footer": "Mantissa Log",
                    "ts": int(alert.timestamp.timestamp())
                }
            ]
        }

    def format_for_pagerduty(self, alert: Alert) -> Dict[str, Any]:
        """Format alert for PagerDuty.

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

        return {
            "routing_key": "",  # To be filled by router
            "event_action": "trigger",
            "dedup_key": alert.suppression_key or alert.id,
            "payload": {
                "summary": alert.title,
                "severity": severity_map.get(alert.severity, "info"),
                "source": "mantissa-log",
                "timestamp": alert.timestamp.isoformat(),
                "custom_details": {
                    "rule_id": alert.rule_id,
                    "rule_name": alert.rule_name,
                    "description": alert.description,
                    "result_count": alert.metadata.get("result_count", 0),
                    "tags": ", ".join(alert.tags)
                }
            }
        }

    def format_for_email(self, alert: Alert) -> Dict[str, str]:
        """Format alert for email.

        Args:
            alert: Alert to format

        Returns:
            Email message with subject and body
        """
        subject = f"[{alert.severity.upper()}] {alert.title}"

        body = f"""
Security Alert from Mantissa Log

Severity: {alert.severity.upper()}
Rule: {alert.rule_name}
Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

Description:
{alert.description}

Results: {alert.metadata.get('result_count', 0)} matches

"""

        # Add MITRE ATT&CK if present
        if alert.mitre_attack:
            body += f"\nMITRE ATT&CK:\n"
            body += f"Tactic: {alert.mitre_attack.get('tactic', 'N/A')}\n"
            body += f"Technique: {alert.mitre_attack.get('technique', 'N/A')}\n"

        # Add tags if present
        if alert.tags:
            body += f"\nTags: {', '.join(alert.tags)}\n"

        # Add metadata
        if alert.metadata:
            body += f"\nAdditional Context:\n"
            for key, value in alert.metadata.items():
                if key not in ["result_count", "enrichment_timestamp"]:
                    body += f"{key}: {value}\n"

        body += "\n---\nGenerated by Mantissa Log\n"

        return {
            "subject": subject,
            "body": body
        }
