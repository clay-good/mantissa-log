"""Incident manager - re-export for package compatibility.

This module provides the IdentityIncidentManager which manages identity
incidents and their lifecycle.
"""

from .identity_incident import IdentityIncident
from .identity_correlator import IdentityCorrelator


class IdentityIncidentManager:
    """Manages identity security incidents.

    Provides functionality to create, track, and manage identity-related
    security incidents through their lifecycle.
    """

    def __init__(
        self,
        correlator: IdentityCorrelator = None,
        incident_store=None,
    ):
        """Initialize the incident manager.

        Args:
            correlator: Optional IdentityCorrelator for incident correlation
            incident_store: Optional store for persisting incidents
        """
        self.correlator = correlator
        self.incident_store = incident_store
        self._active_incidents = {}

    def create_incident(self, alert, user_email: str = None) -> IdentityIncident:
        """Create a new incident from an alert.

        Args:
            alert: The triggering alert
            user_email: Optional user email for the incident

        Returns:
            Created IdentityIncident
        """
        from datetime import datetime, timezone
        import uuid

        incident = IdentityIncident(
            incident_id=str(uuid.uuid4()),
            attack_type=getattr(alert, "alert_type", "unknown"),
            severity=getattr(alert, "severity", "medium"),
            affected_user=user_email or getattr(alert, "user_email", "unknown"),
            source_provider=getattr(alert, "provider", "unknown"),
            related_alerts=[alert],
            created_at=datetime.now(timezone.utc),
        )

        self._active_incidents[incident.incident_id] = incident

        if self.incident_store:
            self.incident_store.save(incident)

        return incident

    def get_incident(self, incident_id: str) -> IdentityIncident:
        """Get an incident by ID.

        Args:
            incident_id: The incident ID

        Returns:
            The incident or None if not found
        """
        if incident_id in self._active_incidents:
            return self._active_incidents[incident_id]

        if self.incident_store:
            return self.incident_store.get(incident_id)

        return None

    def update_incident(self, incident: IdentityIncident) -> None:
        """Update an incident.

        Args:
            incident: The incident to update
        """
        self._active_incidents[incident.incident_id] = incident

        if self.incident_store:
            self.incident_store.save(incident)

    def close_incident(self, incident_id: str, resolution: str = None) -> None:
        """Close an incident.

        Args:
            incident_id: The incident to close
            resolution: Optional resolution notes
        """
        incident = self.get_incident(incident_id)
        if incident:
            from datetime import datetime, timezone
            incident.resolved_at = datetime.now(timezone.utc)
            incident.resolution = resolution
            self.update_incident(incident)

    def list_active_incidents(self, user_email: str = None) -> list:
        """List active incidents.

        Args:
            user_email: Optional filter by user

        Returns:
            List of active incidents
        """
        incidents = list(self._active_incidents.values())

        if user_email:
            incidents = [i for i in incidents if i.affected_user == user_email]

        return incidents

    def correlate_alert(self, alert) -> IdentityIncident:
        """Correlate an alert with existing incidents.

        Args:
            alert: The alert to correlate

        Returns:
            Existing or new incident
        """
        if self.correlator:
            return self.correlator.correlate(alert)

        # Simple correlation by user if no correlator
        user_email = getattr(alert, "user_email", None)
        for incident in self._active_incidents.values():
            if incident.affected_user == user_email:
                incident.related_alerts.append(alert)
                return incident

        return self.create_incident(alert, user_email)


__all__ = ["IdentityIncidentManager"]
