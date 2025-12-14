"""ServiceNow alert handler for creating and managing incidents from security alerts."""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import requests

from .base import AlertHandler
from ...detection.alert_generator import Alert

logger = logging.getLogger(__name__)


class IncidentState(Enum):
    """ServiceNow incident states."""
    NEW = 1
    IN_PROGRESS = 2
    ON_HOLD = 3
    RESOLVED = 6
    CLOSED = 7
    CANCELED = 8


class IncidentPriority(Enum):
    """ServiceNow incident priorities."""
    CRITICAL = 1
    HIGH = 2
    MODERATE = 3
    LOW = 4
    PLANNING = 5


class IncidentImpact(Enum):
    """ServiceNow incident impact levels."""
    HIGH = 1
    MEDIUM = 2
    LOW = 3


class IncidentUrgency(Enum):
    """ServiceNow incident urgency levels."""
    HIGH = 1
    MEDIUM = 2
    LOW = 3


@dataclass
class ServiceNowIncident:
    """Represents a ServiceNow incident."""
    sys_id: str
    number: str
    state: IncidentState
    short_description: str
    description: str
    priority: IncidentPriority
    impact: IncidentImpact
    urgency: IncidentUrgency
    assignment_group: Optional[str] = None
    assigned_to: Optional[str] = None
    caller_id: Optional[str] = None
    category: Optional[str] = None
    subcategory: Optional[str] = None
    created_on: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    close_notes: Optional[str] = None
    correlation_id: Optional[str] = None


@dataclass
class SyncResult:
    """Result of a sync operation."""
    success: bool
    incident_number: Optional[str] = None
    sys_id: Optional[str] = None
    message: str = ""
    updated_fields: List[str] = field(default_factory=list)


class ServiceNowHandler(AlertHandler):
    """Handler for creating and managing ServiceNow incidents from alerts."""

    # Severity to impact/urgency mapping
    DEFAULT_SEVERITY_MAPPING = {
        "critical": {"impact": IncidentImpact.HIGH, "urgency": IncidentUrgency.HIGH},
        "high": {"impact": IncidentImpact.HIGH, "urgency": IncidentUrgency.MEDIUM},
        "medium": {"impact": IncidentImpact.MEDIUM, "urgency": IncidentUrgency.MEDIUM},
        "low": {"impact": IncidentImpact.MEDIUM, "urgency": IncidentUrgency.LOW},
        "info": {"impact": IncidentImpact.LOW, "urgency": IncidentUrgency.LOW}
    }

    def __init__(
        self,
        instance_url: str,
        username: str,
        password: str,
        assignment_group: Optional[str] = None,
        caller_id: Optional[str] = None,
        category: str = "Security",
        subcategory: str = "Security Incident",
        severity_mapping: Optional[Dict[str, Dict]] = None,
        custom_fields: Optional[Dict[str, str]] = None,
        timeout: int = 30
    ):
        """Initialize ServiceNow handler.

        Args:
            instance_url: ServiceNow instance URL (e.g., https://your-instance.service-now.com)
            username: ServiceNow username
            password: ServiceNow password or OAuth token
            assignment_group: Default assignment group sys_id
            caller_id: Default caller sys_id for incidents
            category: Incident category
            subcategory: Incident subcategory
            severity_mapping: Optional severity to impact/urgency mapping
            custom_fields: Additional custom fields to set on incidents
            timeout: Request timeout in seconds
        """
        self.instance_url = instance_url.rstrip("/")
        self.username = username
        self.password = password
        self.assignment_group = assignment_group
        self.caller_id = caller_id
        self.category = category
        self.subcategory = subcategory
        self.severity_mapping = severity_mapping or self.DEFAULT_SEVERITY_MAPPING
        self.custom_fields = custom_fields or {}
        self.timeout = timeout
        self._session = requests.Session()
        self._session.auth = (username, password)
        self._session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json"
        })

    def _api_url(self, endpoint: str) -> str:
        """Build API URL for endpoint.

        Args:
            endpoint: API endpoint path

        Returns:
            Full API URL
        """
        return f"{self.instance_url}/api/now/{endpoint}"

    def validate_config(self) -> bool:
        """Validate ServiceNow configuration by testing API connectivity.

        Returns:
            True if configuration is valid and API is accessible
        """
        if not all([self.instance_url, self.username, self.password]):
            return False

        try:
            response = self._session.get(
                self._api_url("table/sys_user?sysparm_limit=1"),
                timeout=self.timeout
            )
            return response.status_code == 200
        except requests.exceptions.RequestException as e:
            logger.error(f"ServiceNow validation failed: {e}")
            return False

    def send(self, alert: Alert) -> bool:
        """Create ServiceNow incident from alert.

        Args:
            alert: Alert to send

        Returns:
            True if incident was created successfully
        """
        try:
            result = self.create_incident(alert)
            return result.success
        except Exception as e:
            logger.error(f"Error creating ServiceNow incident: {e}")
            return False

    def create_incident(self, alert: Alert) -> SyncResult:
        """Create a new ServiceNow incident from an alert.

        Args:
            alert: Alert to create incident from

        Returns:
            SyncResult with incident details
        """
        try:
            payload = self.format_alert(alert)

            response = self._session.post(
                self._api_url("table/incident"),
                json=payload,
                timeout=self.timeout
            )

            response.raise_for_status()

            result = response.json().get("result", {})
            incident_number = result.get("number")
            sys_id = result.get("sys_id")

            logger.info(f"Created ServiceNow incident: {incident_number}")

            return SyncResult(
                success=True,
                incident_number=incident_number,
                sys_id=sys_id,
                message=f"Incident {incident_number} created successfully"
            )

        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            if hasattr(e, "response") and e.response is not None:
                try:
                    error_detail = e.response.json()
                    error_msg = error_detail.get("error", {}).get("message", error_msg)
                except Exception:
                    error_msg = e.response.text

            logger.error(f"Failed to create ServiceNow incident: {error_msg}")
            return SyncResult(success=False, message=error_msg)

    def format_alert(self, alert: Alert) -> Dict[str, Any]:
        """Format alert as ServiceNow incident payload.

        Args:
            alert: Alert to format

        Returns:
            ServiceNow incident creation payload
        """
        severity_config = self.severity_mapping.get(
            alert.severity.lower(),
            {"impact": IncidentImpact.MEDIUM, "urgency": IncidentUrgency.MEDIUM}
        )

        payload = {
            "short_description": self._format_short_description(alert),
            "description": self._format_description(alert),
            "impact": severity_config["impact"].value,
            "urgency": severity_config["urgency"].value,
            "category": self.category,
            "subcategory": self.subcategory,
            "correlation_id": alert.id,
            "correlation_display": f"Mantissa Log Alert: {alert.id}"
        }

        if self.assignment_group:
            payload["assignment_group"] = self.assignment_group

        if self.caller_id:
            payload["caller_id"] = self.caller_id

        # Add custom fields
        for field_name, field_value in self.custom_fields.items():
            payload[field_name] = field_value

        # Add work notes with technical details
        work_notes = self._format_work_notes(alert)
        if work_notes:
            payload["work_notes"] = work_notes

        return payload

    def _format_short_description(self, alert: Alert) -> str:
        """Format short description for incident.

        Args:
            alert: Alert to format

        Returns:
            Short description (max 160 chars)
        """
        desc = f"[{alert.severity.upper()}] {alert.rule_name}: {alert.title}"
        if len(desc) > 160:
            desc = desc[:157] + "..."
        return desc

    def _format_description(self, alert: Alert) -> str:
        """Format full description for incident.

        Args:
            alert: Alert to format

        Returns:
            Full description text
        """
        lines = [
            "=== SECURITY ALERT ===",
            "",
            f"Alert ID: {alert.id}",
            f"Severity: {alert.severity.upper()}",
            f"Detection Rule: {alert.rule_name}",
            f"Timestamp: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "--- Description ---",
            alert.description or "No description provided",
        ]

        # Add MITRE ATT&CK info
        if alert.mitre_attack:
            lines.extend([
                "",
                "--- MITRE ATT&CK ---",
                f"Tactic: {alert.mitre_attack.get('tactic', 'N/A')}",
                f"Technique: {alert.mitre_attack.get('technique', 'N/A')}",
            ])
            if alert.mitre_attack.get("technique_id"):
                lines.append(f"Technique ID: {alert.mitre_attack['technique_id']}")

        # Add enrichment summary
        if alert.enrichment:
            if "five_w_one_h" in alert.enrichment:
                lines.extend(["", "--- 5W1H Summary ---"])
                for key, value in alert.enrichment["five_w_one_h"].items():
                    lines.append(f"{key.upper()}: {value}")

            if "recommended_actions" in alert.enrichment:
                lines.extend(["", "--- Recommended Actions ---"])
                for i, action in enumerate(alert.enrichment["recommended_actions"], 1):
                    lines.append(f"{i}. {action}")

        # Add tags
        if alert.tags:
            lines.extend([
                "",
                "--- Tags ---",
                ", ".join(alert.tags[:10])
            ])

        lines.extend([
            "",
            "---",
            "Generated by Mantissa Log Security Platform"
        ])

        return "\n".join(lines)

    def _format_work_notes(self, alert: Alert) -> str:
        """Format work notes with technical details.

        Args:
            alert: Alert to format

        Returns:
            Work notes text
        """
        lines = ["[code]<Technical Details>[/code]"]

        # Add results summary
        if alert.results:
            result_count = len(alert.results)
            lines.append(f"\nQuery Results: {result_count} matches")

            if result_count > 0 and isinstance(alert.results[0], dict):
                # Show first result as sample
                lines.append("\nSample Result:")
                for key, value in list(alert.results[0].items())[:10]:
                    lines.append(f"  {key}: {str(value)[:100]}")

        # Add metadata
        if alert.metadata:
            lines.extend([
                "",
                "[code]<Raw Metadata>[/code]",
                json.dumps(alert.metadata, indent=2, default=str)[:2000]
            ])

        return "\n".join(lines)

    def get_incident(self, incident_number: str) -> Optional[ServiceNowIncident]:
        """Get incident details by number.

        Args:
            incident_number: Incident number (e.g., INC0012345)

        Returns:
            ServiceNowIncident if found, None otherwise
        """
        try:
            response = self._session.get(
                self._api_url(f"table/incident?sysparm_query=number={incident_number}"),
                timeout=self.timeout
            )
            response.raise_for_status()

            results = response.json().get("result", [])
            if not results:
                return None

            return self._parse_incident(results[0])

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get incident {incident_number}: {e}")
            return None

    def get_incident_by_correlation_id(self, correlation_id: str) -> Optional[ServiceNowIncident]:
        """Get incident by correlation ID (alert ID).

        Args:
            correlation_id: Alert ID used as correlation ID

        Returns:
            ServiceNowIncident if found, None otherwise
        """
        try:
            response = self._session.get(
                self._api_url(f"table/incident?sysparm_query=correlation_id={correlation_id}"),
                timeout=self.timeout
            )
            response.raise_for_status()

            results = response.json().get("result", [])
            if not results:
                return None

            return self._parse_incident(results[0])

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get incident by correlation ID {correlation_id}: {e}")
            return None

    def _parse_incident(self, data: Dict) -> ServiceNowIncident:
        """Parse incident data from API response.

        Args:
            data: Incident data dict

        Returns:
            ServiceNowIncident object
        """
        return ServiceNowIncident(
            sys_id=data.get("sys_id", ""),
            number=data.get("number", ""),
            state=IncidentState(int(data.get("state", 1))),
            short_description=data.get("short_description", ""),
            description=data.get("description", ""),
            priority=IncidentPriority(int(data.get("priority", 4))),
            impact=IncidentImpact(int(data.get("impact", 2))),
            urgency=IncidentUrgency(int(data.get("urgency", 2))),
            assignment_group=data.get("assignment_group", {}).get("value"),
            assigned_to=data.get("assigned_to", {}).get("value"),
            caller_id=data.get("caller_id", {}).get("value"),
            category=data.get("category"),
            subcategory=data.get("subcategory"),
            correlation_id=data.get("correlation_id"),
            created_on=self._parse_datetime(data.get("sys_created_on")),
            resolved_at=self._parse_datetime(data.get("resolved_at")),
            close_notes=data.get("close_notes")
        )

    def _parse_datetime(self, dt_str: Optional[str]) -> Optional[datetime]:
        """Parse ServiceNow datetime string.

        Args:
            dt_str: DateTime string in ServiceNow format

        Returns:
            datetime object or None
        """
        if not dt_str:
            return None
        try:
            return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def update_incident(
        self,
        incident_number: str,
        updates: Dict[str, Any]
    ) -> SyncResult:
        """Update an existing incident.

        Args:
            incident_number: Incident number to update
            updates: Dictionary of field updates

        Returns:
            SyncResult with update details
        """
        try:
            # First get the sys_id
            incident = self.get_incident(incident_number)
            if not incident:
                return SyncResult(
                    success=False,
                    message=f"Incident {incident_number} not found"
                )

            response = self._session.patch(
                self._api_url(f"table/incident/{incident.sys_id}"),
                json=updates,
                timeout=self.timeout
            )
            response.raise_for_status()

            return SyncResult(
                success=True,
                incident_number=incident_number,
                sys_id=incident.sys_id,
                message=f"Incident {incident_number} updated successfully",
                updated_fields=list(updates.keys())
            )

        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            logger.error(f"Failed to update incident {incident_number}: {error_msg}")
            return SyncResult(success=False, message=error_msg)

    def add_work_note(self, incident_number: str, note: str) -> SyncResult:
        """Add a work note to an incident.

        Args:
            incident_number: Incident number
            note: Work note text

        Returns:
            SyncResult
        """
        return self.update_incident(incident_number, {"work_notes": note})

    def add_comment(self, incident_number: str, comment: str) -> SyncResult:
        """Add a customer-visible comment to an incident.

        Args:
            incident_number: Incident number
            comment: Comment text

        Returns:
            SyncResult
        """
        return self.update_incident(incident_number, {"comments": comment})

    def resolve_incident(
        self,
        incident_number: str,
        resolution_code: str = "Solved (Permanently)",
        resolution_notes: str = ""
    ) -> SyncResult:
        """Resolve an incident.

        Args:
            incident_number: Incident number
            resolution_code: Resolution code
            resolution_notes: Resolution notes

        Returns:
            SyncResult
        """
        updates = {
            "state": IncidentState.RESOLVED.value,
            "close_code": resolution_code,
            "close_notes": resolution_notes or "Resolved via Mantissa Log"
        }
        return self.update_incident(incident_number, updates)

    def close_incident(
        self,
        incident_number: str,
        close_notes: str = ""
    ) -> SyncResult:
        """Close an incident.

        Args:
            incident_number: Incident number
            close_notes: Closing notes

        Returns:
            SyncResult
        """
        updates = {
            "state": IncidentState.CLOSED.value,
            "close_notes": close_notes or "Closed via Mantissa Log"
        }
        return self.update_incident(incident_number, updates)

    def sync_alert_status(self, alert_id: str, alert_status: str) -> SyncResult:
        """Sync alert status to corresponding ServiceNow incident.

        Args:
            alert_id: Mantissa Log alert ID
            alert_status: Alert status (e.g., 'resolved', 'false_positive', 'investigating')

        Returns:
            SyncResult
        """
        incident = self.get_incident_by_correlation_id(alert_id)
        if not incident:
            return SyncResult(
                success=False,
                message=f"No incident found for alert {alert_id}"
            )

        # Map alert status to incident updates
        status_mapping = {
            "investigating": {
                "state": IncidentState.IN_PROGRESS.value,
                "work_notes": "Alert marked as investigating in Mantissa Log"
            },
            "resolved": {
                "state": IncidentState.RESOLVED.value,
                "close_code": "Solved (Permanently)",
                "close_notes": "Alert resolved in Mantissa Log"
            },
            "false_positive": {
                "state": IncidentState.RESOLVED.value,
                "close_code": "Not Solved (Not Reproducible)",
                "close_notes": "Alert marked as false positive in Mantissa Log"
            },
            "dismissed": {
                "state": IncidentState.CANCELED.value,
                "close_notes": "Alert dismissed in Mantissa Log"
            },
            "escalated": {
                "state": IncidentState.IN_PROGRESS.value,
                "work_notes": "Alert escalated in Mantissa Log - requires immediate attention",
                "urgency": IncidentUrgency.HIGH.value
            }
        }

        updates = status_mapping.get(alert_status.lower())
        if not updates:
            return SyncResult(
                success=False,
                message=f"Unknown alert status: {alert_status}"
            )

        return self.update_incident(incident.number, updates)

    def get_open_incidents(self, limit: int = 100) -> List[ServiceNowIncident]:
        """Get open incidents created by Mantissa Log.

        Args:
            limit: Maximum number of incidents to return

        Returns:
            List of open incidents
        """
        try:
            query = (
                "correlation_displayLIKEMantissa Log^"
                f"stateIN{IncidentState.NEW.value},{IncidentState.IN_PROGRESS.value},{IncidentState.ON_HOLD.value}"
            )
            response = self._session.get(
                self._api_url(f"table/incident?sysparm_query={query}&sysparm_limit={limit}"),
                timeout=self.timeout
            )
            response.raise_for_status()

            results = response.json().get("result", [])
            return [self._parse_incident(r) for r in results]

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get open incidents: {e}")
            return []

    def create_test_incident(self) -> SyncResult:
        """Create a test incident to verify configuration.

        Returns:
            SyncResult with test incident details
        """
        test_alert = Alert(
            id=f"test-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            title="Mantissa Log Integration Test",
            description="This is a test incident created to verify ServiceNow integration. You can safely close this incident.",
            severity="info",
            rule_id="test-rule",
            rule_name="Integration Test",
            timestamp=datetime.now(timezone.utc),
            results=[],
            tags=["test", "integration-verification"],
            metadata={"test": True}
        )

        result = self.create_incident(test_alert)
        if result.success:
            result.message = f"Test incident {result.incident_number} created successfully. URL: {self.instance_url}/nav_to.do?uri=incident.do?sys_id={result.sys_id}"

        return result


class ServiceNowSyncService:
    """Service for bi-directional sync between Mantissa Log and ServiceNow."""

    def __init__(self, handler: ServiceNowHandler):
        """Initialize sync service.

        Args:
            handler: ServiceNow handler instance
        """
        self.handler = handler
        self._status_cache: Dict[str, str] = {}

    def sync_incident_to_alert(
        self,
        incident_number: str,
        update_alert_callback
    ) -> SyncResult:
        """Sync incident status back to Mantissa Log alert.

        Args:
            incident_number: ServiceNow incident number
            update_alert_callback: Callback function to update alert status
                                  Signature: (alert_id: str, status: str, notes: str) -> bool

        Returns:
            SyncResult
        """
        incident = self.handler.get_incident(incident_number)
        if not incident:
            return SyncResult(
                success=False,
                message=f"Incident {incident_number} not found"
            )

        if not incident.correlation_id:
            return SyncResult(
                success=False,
                message=f"Incident {incident_number} has no correlation ID (not from Mantissa Log)"
            )

        # Map incident state to alert status
        state_mapping = {
            IncidentState.NEW: "new",
            IncidentState.IN_PROGRESS: "investigating",
            IncidentState.ON_HOLD: "on_hold",
            IncidentState.RESOLVED: "resolved",
            IncidentState.CLOSED: "closed",
            IncidentState.CANCELED: "dismissed"
        }

        alert_status = state_mapping.get(incident.state, "unknown")

        # Check if status changed
        cached_status = self._status_cache.get(incident.correlation_id)
        if cached_status == alert_status:
            return SyncResult(
                success=True,
                incident_number=incident_number,
                message="No status change detected"
            )

        # Update alert via callback
        try:
            success = update_alert_callback(
                incident.correlation_id,
                alert_status,
                incident.close_notes or ""
            )

            if success:
                self._status_cache[incident.correlation_id] = alert_status
                return SyncResult(
                    success=True,
                    incident_number=incident_number,
                    message=f"Alert {incident.correlation_id} updated to status: {alert_status}"
                )
            else:
                return SyncResult(
                    success=False,
                    message="Failed to update alert status"
                )

        except Exception as e:
            return SyncResult(
                success=False,
                message=f"Error updating alert: {str(e)}"
            )

    def poll_and_sync(
        self,
        update_alert_callback,
        limit: int = 100
    ) -> List[SyncResult]:
        """Poll ServiceNow for updated incidents and sync to Mantissa Log.

        Args:
            update_alert_callback: Callback function to update alert status
            limit: Maximum incidents to process

        Returns:
            List of sync results
        """
        results = []

        # Get all Mantissa Log incidents (both open and recently closed)
        try:
            query = "correlation_displayLIKEMantissa Log"
            response = self.handler._session.get(
                self.handler._api_url(
                    f"table/incident?sysparm_query={query}&sysparm_limit={limit}"
                    "&sysparm_fields=sys_id,number,state,correlation_id,close_notes"
                ),
                timeout=self.handler.timeout
            )
            response.raise_for_status()

            incidents = response.json().get("result", [])

            for incident_data in incidents:
                incident_number = incident_data.get("number")
                result = self.sync_incident_to_alert(incident_number, update_alert_callback)
                results.append(result)

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to poll ServiceNow incidents: {e}")
            results.append(SyncResult(
                success=False,
                message=f"Poll failed: {str(e)}"
            ))

        return results
