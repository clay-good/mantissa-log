"""Base alert handler interface."""

from abc import ABC, abstractmethod
from typing import Any

from ...detection.alert_generator import Alert


class AlertHandler(ABC):
    """Abstract base class for alert handlers."""

    @abstractmethod
    def send(self, alert: Alert) -> bool:
        """Send alert to destination.

        Args:
            alert: Alert to send

        Returns:
            True if successful, False otherwise
        """
        pass

    def validate_config(self) -> bool:
        """Validate handler configuration.

        Returns:
            True if configuration is valid
        """
        return True

    def format_alert(self, alert: Alert) -> Any:
        """Format alert for this destination.

        Args:
            alert: Alert to format

        Returns:
            Formatted alert payload
        """
        return alert.to_dict()
