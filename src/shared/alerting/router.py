"""Alert routing orchestrator for Mantissa Log."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum

from ..detection.alert_generator import Alert

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    """Alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RouterConfig:
    """Configuration for alert router."""

    default_destinations: List[str] = field(default_factory=list)
    severity_routing: Dict[str, List[str]] = field(default_factory=dict)
    enrichment_enabled: bool = True
    max_concurrent_sends: int = 5

    @classmethod
    def from_dict(cls, config: Dict) -> "RouterConfig":
        """Create RouterConfig from dictionary.

        Args:
            config: Configuration dictionary

        Returns:
            RouterConfig instance
        """
        return cls(
            default_destinations=config.get("default_destinations", []),
            severity_routing=config.get("severity_routing", {}),
            enrichment_enabled=config.get("enrichment_enabled", True),
            max_concurrent_sends=config.get("max_concurrent_sends", 5)
        )


@dataclass
class RoutingResult:
    """Result of routing an alert."""

    alert_id: str
    destinations_attempted: List[str] = field(default_factory=list)
    destinations_succeeded: List[str] = field(default_factory=list)
    destinations_failed: Dict[str, str] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        """Check if at least one destination succeeded.

        Returns:
            True if any destination succeeded
        """
        return len(self.destinations_succeeded) > 0

    @property
    def total_destinations(self) -> int:
        """Get total number of destinations attempted.

        Returns:
            Count of destinations
        """
        return len(self.destinations_attempted)

    def to_dict(self) -> Dict:
        """Convert to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "alert_id": self.alert_id,
            "destinations_attempted": self.destinations_attempted,
            "destinations_succeeded": self.destinations_succeeded,
            "destinations_failed": self.destinations_failed,
            "success": self.success,
            "total_destinations": self.total_destinations
        }


class AlertHandler:
    """Base class for alert handlers."""

    def send(self, alert: Alert) -> bool:
        """Send alert to destination.

        Args:
            alert: Alert to send

        Returns:
            True if successful

        Raises:
            NotImplementedError: Must be implemented by subclass
        """
        raise NotImplementedError("Subclasses must implement send()")

    def validate_config(self) -> bool:
        """Validate handler configuration.

        Returns:
            True if configuration is valid
        """
        return True

    def format_alert(self, alert: Alert):
        """Format alert for this destination.

        Args:
            alert: Alert to format

        Returns:
            Formatted alert payload
        """
        return alert.to_dict()


class AlertRouter:
    """Routes alerts to configured destinations."""

    def __init__(
        self,
        handlers: Dict[str, AlertHandler],
        config: RouterConfig,
        enricher: Optional[any] = None
    ):
        """Initialize alert router.

        Args:
            handlers: Dictionary of handler name to AlertHandler instance
            config: Router configuration
            enricher: Optional AlertEnricher instance
        """
        self.handlers = handlers
        self.config = config
        self.enricher = enricher

        # Validate handlers
        for name, handler in self.handlers.items():
            if not handler.validate_config():
                logger.warning(f"Handler {name} has invalid configuration")

    def route_alert(self, alert: Alert) -> RoutingResult:
        """Route a single alert to configured destinations.

        Args:
            alert: Alert to route

        Returns:
            RoutingResult with success/failure information
        """
        # Enrich alert if enabled
        if self.enricher and self.config.enrichment_enabled:
            try:
                alert = self.enricher.enrich(alert)
            except Exception as e:
                logger.error(f"Error enriching alert {alert.id}: {e}")

        # Determine destinations
        destinations = self._determine_destinations(alert)

        result = RoutingResult(alert_id=alert.id)
        result.destinations_attempted = destinations

        # Send to each destination
        for destination in destinations:
            handler = self.handlers.get(destination)

            if not handler:
                logger.warning(f"No handler found for destination: {destination}")
                result.destinations_failed[destination] = "Handler not found"
                continue

            try:
                success = handler.send(alert)

                if success:
                    result.destinations_succeeded.append(destination)
                else:
                    result.destinations_failed[destination] = "Handler returned False"

            except Exception as e:
                error_msg = f"{type(e).__name__}: {str(e)}"
                result.destinations_failed[destination] = error_msg
                logger.error(f"Error sending alert {alert.id} to {destination}: {error_msg}")

        return result

    def route_alerts(self, alerts: List[Alert]) -> List[RoutingResult]:
        """Route multiple alerts in parallel.

        Args:
            alerts: List of alerts to route

        Returns:
            List of RoutingResults
        """
        results = []

        with ThreadPoolExecutor(max_workers=self.config.max_concurrent_sends) as executor:
            future_to_alert = {
                executor.submit(self.route_alert, alert): alert
                for alert in alerts
            }

            for future in as_completed(future_to_alert):
                alert = future_to_alert[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error routing alert {alert.id}: {e}")
                    results.append(RoutingResult(
                        alert_id=alert.id,
                        destinations_attempted=[],
                        destinations_failed={"all": str(e)}
                    ))

        return results

    def _determine_destinations(self, alert: Alert) -> List[str]:
        """Determine which destinations to send alert to.

        Args:
            alert: Alert to route

        Returns:
            List of destination names
        """
        # Start with alert-specific destinations
        destinations = set(alert.destinations) if alert.destinations else set()

        # Add severity-based destinations
        severity = alert.severity.lower()
        if severity in self.config.severity_routing:
            destinations.update(self.config.severity_routing[severity])

        # Add default destinations if none specified
        if not destinations:
            destinations.update(self.config.default_destinations)

        return list(destinations)

    def register_handler(self, name: str, handler: AlertHandler) -> None:
        """Register a new handler.

        Args:
            name: Handler name
            handler: AlertHandler instance
        """
        self.handlers[name] = handler

    def unregister_handler(self, name: str) -> None:
        """Unregister a handler.

        Args:
            name: Handler name to remove
        """
        if name in self.handlers:
            del self.handlers[name]

    def get_handler(self, name: str) -> Optional[AlertHandler]:
        """Get a handler by name.

        Args:
            name: Handler name

        Returns:
            AlertHandler instance or None
        """
        return self.handlers.get(name)

    def list_handlers(self) -> List[str]:
        """List all registered handler names.

        Returns:
            List of handler names
        """
        return list(self.handlers.keys())
