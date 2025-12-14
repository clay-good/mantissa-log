"""Alert handlers for various destinations."""

from .base import AlertHandler
from .slack import SlackHandler
from .pagerduty import PagerDutyHandler
from .email import EmailHandler
from .webhook import (
    WebhookHandler,
    WebhookResponse,
    ResponseMapping,
    RetryConfig,
    RetryStrategy,
    ResponseHandlerConfig,
    create_webhook_with_retry,
    create_signed_webhook,
)
from .jira import JiraHandler
from .servicenow import (
    ServiceNowHandler,
    ServiceNowIncident,
    ServiceNowSyncService,
    SyncResult,
    IncidentState,
    IncidentPriority,
    IncidentImpact,
    IncidentUrgency,
)
from .teams import TeamsHandler, TeamsWorkflowHandler, TeamsActionButton

__all__ = [
    # Base
    "AlertHandler",
    # Messaging
    "SlackHandler",
    "TeamsHandler",
    "TeamsWorkflowHandler",
    "TeamsActionButton",
    # Ticketing
    "JiraHandler",
    "ServiceNowHandler",
    "ServiceNowIncident",
    "ServiceNowSyncService",
    "SyncResult",
    "IncidentState",
    "IncidentPriority",
    "IncidentImpact",
    "IncidentUrgency",
    # Incident Management
    "PagerDutyHandler",
    # Communication
    "EmailHandler",
    # Generic
    "WebhookHandler",
    "WebhookResponse",
    "ResponseMapping",
    "RetryConfig",
    "RetryStrategy",
    "ResponseHandlerConfig",
    "create_webhook_with_retry",
    "create_signed_webhook",
]
