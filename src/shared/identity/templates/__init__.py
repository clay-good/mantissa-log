"""Identity-specific alert templates.

This package provides templates for rendering identity alerts
across different output formats:
- Base alert templates with structured content
- Slack Block Kit templates for rich messaging
- HTML email templates for email notifications
"""

from .alert_templates import (
    AlertTemplate,
    RenderedAlert,
    IdentityAlertTemplates,
)
from .slack_templates import SlackTemplateRenderer
from .email_templates import EmailTemplateRenderer

__all__ = [
    "AlertTemplate",
    "RenderedAlert",
    "IdentityAlertTemplates",
    "SlackTemplateRenderer",
    "EmailTemplateRenderer",
]
