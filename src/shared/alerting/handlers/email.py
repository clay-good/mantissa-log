"""Email alert handler."""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional
import json
import logging

from .base import AlertHandler
from ...detection.alert_generator import Alert

logger = logging.getLogger(__name__)


class EmailHandler(AlertHandler):
    """Handler for sending alerts via email."""

    def __init__(
        self,
        recipients: List[str],
        smtp_host: Optional[str] = None,
        smtp_port: Optional[int] = None,
        smtp_username: Optional[str] = None,
        smtp_password: Optional[str] = None,
        smtp_use_tls: bool = True,
        from_address: str = "mantissa-log@example.com",
        use_ses: bool = False,
        ses_region: str = "us-east-1"
    ):
        """Initialize email handler.

        Args:
            recipients: List of email addresses to send to
            smtp_host: SMTP server hostname
            smtp_port: SMTP server port
            smtp_username: SMTP username
            smtp_password: SMTP password
            smtp_use_tls: Whether to use TLS
            from_address: From email address
            use_ses: Whether to use AWS SES instead of SMTP
            ses_region: AWS SES region
        """
        self.recipients = recipients
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port or (587 if smtp_use_tls else 25)
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.smtp_use_tls = smtp_use_tls
        self.from_address = from_address
        self.use_ses = use_ses
        self.ses_region = ses_region

    def validate_config(self) -> bool:
        """Validate email configuration.

        Returns:
            True if configuration is valid
        """
        if not self.recipients:
            return False

        if self.use_ses:
            return True

        return bool(self.smtp_host)

    def send(self, alert: Alert) -> bool:
        """Send alert via email.

        Args:
            alert: Alert to send

        Returns:
            True if successful
        """
        try:
            if self.use_ses:
                return self._send_via_ses(alert)
            else:
                return self._send_via_smtp(alert)

        except Exception as e:
            logger.error(f"Error sending email: {e}")
            return False

    def _send_via_smtp(self, alert: Alert) -> bool:
        """Send email via SMTP.

        Args:
            alert: Alert to send

        Returns:
            True if successful
        """
        msg = self._create_message(alert)

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30) as server:
                if self.smtp_use_tls:
                    server.starttls()

                if self.smtp_username and self.smtp_password:
                    server.login(self.smtp_username, self.smtp_password)

                server.send_message(msg)

            return True

        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
            return False

    def _send_via_ses(self, alert: Alert) -> bool:
        """Send email via AWS SES.

        Args:
            alert: Alert to send

        Returns:
            True if successful
        """
        import boto3
        from botocore.exceptions import ClientError

        ses_client = boto3.client('ses', region_name=self.ses_region)

        msg = self._create_message(alert)

        try:
            response = ses_client.send_raw_email(
                Source=self.from_address,
                Destinations=self.recipients,
                RawMessage={'Data': msg.as_string()}
            )

            return response['ResponseMetadata']['HTTPStatusCode'] == 200

        except ClientError as e:
            logger.error(f"SES error: {e}")
            return False

    def _create_message(self, alert: Alert) -> MIMEMultipart:
        """Create email message.

        Args:
            alert: Alert to format

        Returns:
            Email message
        """
        msg = MIMEMultipart('alternative')

        # Subject
        msg['Subject'] = f"[{alert.severity.upper()}] {alert.title}"
        msg['From'] = self.from_address
        msg['To'] = ", ".join(self.recipients)

        # Plain text version
        text_content = self._format_text(alert)
        text_part = MIMEText(text_content, 'plain')
        msg.attach(text_part)

        # HTML version
        html_content = self._format_html(alert)
        html_part = MIMEText(html_content, 'html')
        msg.attach(html_part)

        return msg

    def _format_text(self, alert: Alert) -> str:
        """Format alert as plain text.

        Args:
            alert: Alert to format

        Returns:
            Plain text email body
        """
        lines = [
            "=" * 70,
            f"Mantissa Log Security Alert",
            "=" * 70,
            "",
            f"Severity: {alert.severity.upper()}",
            f"Rule: {alert.rule_name}",
            f"Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Alert ID: {alert.id}",
            "",
            "Description:",
            "-" * 70,
            alert.description,
            "",
        ]

        # Add MITRE ATT&CK
        if alert.mitre_attack:
            lines.extend([
                "MITRE ATT&CK Framework:",
                "-" * 70,
                f"Tactic: {alert.mitre_attack.get('tactic', 'N/A')}",
                f"Technique: {alert.mitre_attack.get('technique', 'N/A')}",
                "",
            ])

        # Add metadata
        if alert.metadata:
            result_count = alert.metadata.get('result_count', len(alert.results))
            lines.extend([
                f"Results: {result_count} matches",
                "",
            ])

        # Add tags
        if alert.tags:
            lines.extend([
                f"Tags: {', '.join(alert.tags)}",
                "",
            ])

        # Add sample results
        if alert.results and len(alert.results) > 0:
            lines.extend([
                "Sample Results:",
                "-" * 70,
            ])

            for i, result in enumerate(alert.results[:5], 1):
                lines.append(f"\nResult {i}:")
                for key, value in result.items():
                    lines.append(f"  {key}: {value}")

        lines.extend([
            "",
            "-" * 70,
            "Generated by Mantissa Log",
            "https://github.com/clay-good/mantissa-log",
        ])

        return "\n".join(lines)

    def _format_html(self, alert: Alert) -> str:
        """Format alert as HTML.

        Args:
            alert: Alert to format

        Returns:
            HTML email body
        """
        # Severity color mapping
        severity_colors = {
            "critical": "#DC2626",
            "high": "#EA580C",
            "medium": "#F59E0B",
            "low": "#10B981",
            "info": "#3B82F6"
        }

        color = severity_colors.get(alert.severity.lower(), "#6B7280")

        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: {color}; color: white; padding: 20px; border-radius: 5px 5px 0 0; }}
                .content {{ background-color: #f9fafb; padding: 20px; border-radius: 0 0 5px 5px; }}
                .field {{ margin: 10px 0; }}
                .label {{ font-weight: bold; color: #374151; }}
                .value {{ color: #6b7280; }}
                .footer {{ margin-top: 20px; padding-top: 20px; border-top: 1px solid #d1d5db; text-align: center; color: #9ca3af; font-size: 12px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
                th {{ background-color: #f3f4f6; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2 style="margin: 0;">{alert.severity.upper()}: {alert.title}</h2>
                </div>
                <div class="content">
                    <div class="field">
                        <span class="label">Rule:</span>
                        <span class="value">{alert.rule_name}</span>
                    </div>
                    <div class="field">
                        <span class="label">Time:</span>
                        <span class="value">{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
                    </div>
                    <div class="field">
                        <span class="label">Alert ID:</span>
                        <span class="value">{alert.id}</span>
                    </div>
                    <hr>
                    <div class="field">
                        <p><strong>Description:</strong></p>
                        <p>{alert.description.replace(chr(10), '<br>')}</p>
                    </div>
        """

        # Add MITRE ATT&CK
        if alert.mitre_attack:
            html += f"""
                    <div class="field">
                        <p><strong>MITRE ATT&CK:</strong></p>
                        <p>Tactic: {alert.mitre_attack.get('tactic', 'N/A')}<br>
                        Technique: {alert.mitre_attack.get('technique', 'N/A')}</p>
                    </div>
            """

        # Add metadata
        if alert.metadata:
            result_count = alert.metadata.get('result_count', len(alert.results))
            html += f"""
                    <div class="field">
                        <span class="label">Results:</span>
                        <span class="value">{result_count} matches</span>
                    </div>
            """

        # Add tags
        if alert.tags:
            tags_html = ", ".join(f"<code>{tag}</code>" for tag in alert.tags)
            html += f"""
                    <div class="field">
                        <p><strong>Tags:</strong> {tags_html}</p>
                    </div>
            """

        html += """
                </div>
                <div class="footer">
                    Generated by Mantissa Log<br>
                    <a href="https://github.com/clay-good/mantissa-log">https://github.com/clay-good/mantissa-log</a>
                </div>
            </div>
        </body>
        </html>
        """

        return html

    def format_alert(self, alert: Alert) -> MIMEMultipart:
        """Format alert as email message.

        Args:
            alert: Alert to format

        Returns:
            Email message
        """
        return self._create_message(alert)
