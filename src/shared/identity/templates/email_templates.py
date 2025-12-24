"""HTML email templates for identity alerts.

Provides responsive HTML email templates for email notifications.
"""

import html
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class EmailMessage:
    """A complete email message with HTML content."""

    subject: str
    body_html: str
    body_text: str
    headers: Dict[str, str] = field(default_factory=dict)
    priority: str = "normal"  # low, normal, high

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format for email sending."""
        return {
            "subject": self.subject,
            "body_html": self.body_html,
            "body_text": self.body_text,
            "headers": self.headers,
            "priority": self.priority,
        }


class EmailTemplateRenderer:
    """Renders identity alerts as HTML emails.

    Creates responsive, well-formatted email notifications with:
    - Clean, professional styling
    - Severity-based color coding
    - Clear call-to-action buttons
    - Mobile-responsive design
    """

    # Severity to color mapping
    SEVERITY_COLORS = {
        "critical": {"bg": "#FEE2E2", "border": "#DC2626", "text": "#DC2626"},
        "high": {"bg": "#FFF7ED", "border": "#EA580C", "text": "#EA580C"},
        "medium": {"bg": "#FEF9C3", "border": "#CA8A04", "text": "#CA8A04"},
        "low": {"bg": "#DCFCE7", "border": "#16A34A", "text": "#16A34A"},
        "info": {"bg": "#DBEAFE", "border": "#2563EB", "text": "#2563EB"},
    }

    def __init__(
        self,
        base_url: str = "",
        company_name: str = "Security Operations",
        logo_url: str = "",
    ):
        """Initialize email template renderer.

        Args:
            base_url: Base URL for links
            company_name: Company name for branding
            logo_url: URL to company logo
        """
        self.base_url = base_url.rstrip("/")
        self.company_name = company_name
        self.logo_url = logo_url

    def render_identity_alert(
        self,
        rendered_alert: Any,
        include_actions: bool = True,
    ) -> EmailMessage:
        """Render an identity alert as an HTML email.

        Args:
            rendered_alert: RenderedAlert from IdentityAlertTemplates
            include_actions: Whether to include action buttons

        Returns:
            EmailMessage ready to send
        """
        severity = rendered_alert.severity.lower()
        colors = self.SEVERITY_COLORS.get(severity, self.SEVERITY_COLORS["info"])

        # Build email subject
        subject = self._build_subject(rendered_alert)

        # Build HTML body
        body_html = self._build_html_email(rendered_alert, colors, include_actions)

        # Build plain text body
        body_text = self._build_text_email(rendered_alert)

        # Determine priority
        priority = "high" if severity in ("critical", "high") else "normal"

        return EmailMessage(
            subject=subject,
            body_html=body_html,
            body_text=body_text,
            priority=priority,
            headers={
                "X-Priority": "1" if priority == "high" else "3",
                "X-Alert-ID": rendered_alert.alert_id,
                "X-Alert-Type": rendered_alert.alert_type,
                "X-Alert-Severity": rendered_alert.severity,
            },
        )

    def _build_subject(self, rendered_alert: Any) -> str:
        """Build email subject line.

        Args:
            rendered_alert: Rendered alert

        Returns:
            Subject line
        """
        severity = rendered_alert.severity.upper()
        prefix = f"[{severity}]" if severity in ("CRITICAL", "HIGH") else f"[{severity}]"
        return f"{prefix} {rendered_alert.title}"

    def _build_html_email(
        self,
        rendered_alert: Any,
        colors: Dict[str, str],
        include_actions: bool,
    ) -> str:
        """Build complete HTML email.

        Args:
            rendered_alert: Rendered alert
            colors: Color scheme for severity
            include_actions: Whether to include actions

        Returns:
            Complete HTML document
        """
        # Convert markdown body to HTML
        body_content = self._markdown_to_html(rendered_alert.body_markdown)

        # Build action buttons HTML
        actions_html = ""
        if include_actions and rendered_alert.action_buttons:
            actions_html = self._build_action_buttons_html(
                rendered_alert.action_buttons,
                rendered_alert.alert_id,
            )

        # Build investigation links
        links_html = ""
        if rendered_alert.investigation_links:
            links_html = self._build_links_html(rendered_alert.investigation_links)

        # Build recommended actions
        recommendations_html = ""
        if rendered_alert.recommended_actions:
            recommendations_html = self._build_recommendations_html(
                rendered_alert.recommended_actions
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>{html.escape(rendered_alert.title)}</title>
    <!--[if mso]>
    <style type="text/css">
        table {{border-collapse: collapse;}}
        .button {{padding: 12px 24px !important;}}
    </style>
    <![endif]-->
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #F3F4F6; line-height: 1.6;">
    <!-- Wrapper -->
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #F3F4F6;">
        <tr>
            <td align="center" style="padding: 20px 10px;">
                <!-- Container -->
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; width: 100%; background-color: #FFFFFF; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">

                    <!-- Header -->
                    <tr>
                        <td style="background-color: {colors['border']}; padding: 20px 30px; border-radius: 8px 8px 0 0;">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                                <tr>
                                    <td>
                                        {self._get_logo_html()}
                                        <h1 style="margin: 0; color: #FFFFFF; font-size: 20px; font-weight: 600;">
                                            Security Alert
                                        </h1>
                                    </td>
                                    <td align="right" style="vertical-align: top;">
                                        <span style="display: inline-block; padding: 4px 12px; background-color: rgba(255,255,255,0.2); border-radius: 4px; color: #FFFFFF; font-size: 12px; font-weight: 600; text-transform: uppercase;">
                                            {html.escape(rendered_alert.severity)}
                                        </span>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Alert Banner -->
                    <tr>
                        <td style="background-color: {colors['bg']}; padding: 15px 30px; border-left: 4px solid {colors['border']};">
                            <h2 style="margin: 0; color: {colors['text']}; font-size: 18px; font-weight: 600;">
                                {html.escape(rendered_alert.title)}
                            </h2>
                            <p style="margin: 5px 0 0 0; color: #6B7280; font-size: 14px;">
                                Alert Type: {html.escape(rendered_alert.alert_type.replace('_', ' ').title())} •
                                ID: {html.escape(rendered_alert.alert_id[:8])}...
                            </p>
                        </td>
                    </tr>

                    <!-- Body Content -->
                    <tr>
                        <td style="padding: 30px;">
                            {body_content}
                        </td>
                    </tr>

                    <!-- Recommended Actions -->
                    {recommendations_html}

                    <!-- Action Buttons -->
                    {actions_html}

                    <!-- Investigation Links -->
                    {links_html}

                    <!-- Footer -->
                    <tr>
                        <td style="padding: 20px 30px; background-color: #F9FAFB; border-top: 1px solid #E5E7EB; border-radius: 0 0 8px 8px;">
                            <p style="margin: 0; color: #6B7280; font-size: 12px; text-align: center;">
                                This alert was generated by {html.escape(self.company_name)} ITDR Module<br>
                                {rendered_alert.rendered_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
                            </p>
                            {self._get_mitre_html(rendered_alert.metadata.get('mitre_technique'))}
                        </td>
                    </tr>

                </table>
            </td>
        </tr>
    </table>
</body>
</html>"""

    def _build_text_email(self, rendered_alert: Any) -> str:
        """Build plain text version of email.

        Args:
            rendered_alert: Rendered alert

        Returns:
            Plain text email body
        """
        lines = [
            f"SECURITY ALERT - {rendered_alert.severity.upper()}",
            "=" * 50,
            "",
            rendered_alert.title,
            "",
            f"Alert Type: {rendered_alert.alert_type}",
            f"Alert ID: {rendered_alert.alert_id}",
            "",
            "-" * 50,
            "",
        ]

        # Add body content (strip markdown formatting)
        body_text = self._strip_markdown(rendered_alert.body_markdown)
        lines.append(body_text)
        lines.append("")

        # Add recommended actions
        if rendered_alert.recommended_actions:
            lines.append("-" * 50)
            lines.append("RECOMMENDED ACTIONS:")
            for i, action in enumerate(rendered_alert.recommended_actions, 1):
                lines.append(f"  {i}. {action}")
            lines.append("")

        # Add investigation links
        if rendered_alert.investigation_links:
            lines.append("-" * 50)
            lines.append("INVESTIGATION LINKS:")
            for link in rendered_alert.investigation_links:
                if link.get("url") and "N/A" not in link["url"]:
                    lines.append(f"  - {link['label']}: {link['url']}")
            lines.append("")

        lines.extend([
            "-" * 50,
            f"Generated by {self.company_name} ITDR Module",
            f"{rendered_alert.rendered_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        ])

        return "\n".join(lines)

    def _markdown_to_html(self, markdown: str) -> str:
        """Convert markdown to HTML for email.

        Args:
            markdown: Markdown text

        Returns:
            HTML content
        """
        # Split into sections
        sections = []
        current_section = []
        in_table = False
        table_rows = []

        for line in markdown.split("\n"):
            # Handle headers
            if line.startswith("## "):
                if current_section:
                    sections.append(self._format_section(current_section, in_table, table_rows))
                    current_section = []
                    table_rows = []
                    in_table = False

                header = html.escape(line[3:].strip())
                sections.append(
                    f'<h3 style="margin: 20px 0 10px 0; color: #1F2937; font-size: 16px; '
                    f'font-weight: 600; border-bottom: 1px solid #E5E7EB; padding-bottom: 5px;">'
                    f'{header}</h3>'
                )

            # Handle tables
            elif line.strip().startswith("|"):
                if "---" in line:
                    continue  # Skip header separator
                in_table = True
                cells = [c.strip() for c in line.split("|") if c.strip()]
                if cells:
                    table_rows.append(cells)

            # Handle list items
            elif line.strip().startswith("- ") or line.strip().startswith("* "):
                if in_table and table_rows:
                    sections.append(self._format_section(current_section, True, table_rows))
                    current_section = []
                    table_rows = []
                    in_table = False

                item = html.escape(line.strip()[2:])
                item = self._format_inline(item)
                current_section.append(f'<li style="margin: 5px 0;">{item}</li>')

            # Handle numbered lists
            elif re.match(r'^\d+\.\s', line.strip()):
                if in_table and table_rows:
                    sections.append(self._format_section(current_section, True, table_rows))
                    current_section = []
                    table_rows = []
                    in_table = False

                item = html.escape(re.sub(r'^\d+\.\s', '', line.strip()))
                item = self._format_inline(item)
                current_section.append(f'<li style="margin: 5px 0;">{item}</li>')

            # Handle regular paragraphs
            elif line.strip():
                if in_table and table_rows:
                    sections.append(self._format_section(current_section, True, table_rows))
                    current_section = []
                    table_rows = []
                    in_table = False

                text = html.escape(line.strip())
                text = self._format_inline(text)
                current_section.append(f'<p style="margin: 10px 0; color: #374151;">{text}</p>')

        # Handle remaining content
        if current_section or table_rows:
            sections.append(self._format_section(current_section, in_table, table_rows))

        return "\n".join(sections)

    def _format_section(
        self,
        content: List[str],
        is_table: bool,
        table_rows: List[List[str]],
    ) -> str:
        """Format a section of content.

        Args:
            content: List of HTML content
            is_table: Whether this section contains a table
            table_rows: Table rows if applicable

        Returns:
            Formatted HTML
        """
        result = []

        # Format table
        if is_table and table_rows:
            result.append(self._format_table(table_rows))

        # Format list or paragraphs
        if content:
            # Check if it's a list
            if all("<li" in item for item in content):
                if any(re.search(r'^\d', item) for item in content):
                    result.append(f'<ol style="margin: 10px 0; padding-left: 20px;">{"".join(content)}</ol>')
                else:
                    result.append(f'<ul style="margin: 10px 0; padding-left: 20px;">{"".join(content)}</ul>')
            else:
                result.extend(content)

        return "\n".join(result)

    def _format_table(self, rows: List[List[str]]) -> str:
        """Format a table from rows.

        Args:
            rows: List of table rows

        Returns:
            HTML table
        """
        if not rows:
            return ""

        html_rows = []

        # First row might be header
        is_header = True
        for row in rows:
            cells = []
            for cell in row:
                cell_content = html.escape(cell)
                cell_content = self._format_inline(cell_content)

                if is_header:
                    cells.append(
                        f'<td style="padding: 8px 12px; border-bottom: 2px solid #E5E7EB; '
                        f'font-weight: 600; color: #374151;">{cell_content}</td>'
                    )
                else:
                    cells.append(
                        f'<td style="padding: 8px 12px; border-bottom: 1px solid #E5E7EB; '
                        f'color: #6B7280;">{cell_content}</td>'
                    )

            html_rows.append(f'<tr>{"".join(cells)}</tr>')
            is_header = False

        return f'''<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"
            style="margin: 15px 0; border-collapse: collapse; background-color: #F9FAFB; border-radius: 4px;">
            {"".join(html_rows)}
        </table>'''

    def _format_inline(self, text: str) -> str:
        """Format inline markdown elements.

        Args:
            text: Text with markdown

        Returns:
            HTML formatted text
        """
        # Bold: **text** or __text__
        text = re.sub(
            r'\*\*(.+?)\*\*',
            r'<strong style="color: #1F2937;">\1</strong>',
            text
        )
        text = re.sub(
            r'__(.+?)__',
            r'<strong style="color: #1F2937;">\1</strong>',
            text
        )

        # Code: `text`
        text = re.sub(
            r'`(.+?)`',
            r'<code style="background-color: #F3F4F6; padding: 2px 6px; border-radius: 3px; '
            r'font-family: monospace; font-size: 13px; color: #DC2626;">\1</code>',
            text
        )

        return text

    def _strip_markdown(self, markdown: str) -> str:
        """Strip markdown formatting for plain text.

        Args:
            markdown: Markdown text

        Returns:
            Plain text
        """
        text = markdown

        # Remove headers
        text = re.sub(r'^#+\s*', '', text, flags=re.MULTILINE)

        # Remove bold/italic
        text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
        text = re.sub(r'\*(.+?)\*', r'\1', text)
        text = re.sub(r'__(.+?)__', r'\1', text)
        text = re.sub(r'_(.+?)_', r'\1', text)

        # Remove code formatting
        text = re.sub(r'`(.+?)`', r'\1', text)

        # Convert tables to plain text
        lines = []
        for line in text.split("\n"):
            if line.strip().startswith("|") and "---" not in line:
                cells = [c.strip() for c in line.split("|") if c.strip()]
                if len(cells) >= 2:
                    lines.append(f"  {cells[0]}: {cells[1]}")
            else:
                lines.append(line)

        return "\n".join(lines)

    def _build_action_buttons_html(
        self,
        buttons: List[Dict[str, str]],
        alert_id: str,
    ) -> str:
        """Build action buttons HTML.

        Args:
            buttons: Button definitions
            alert_id: Alert identifier

        Returns:
            HTML for action buttons row
        """
        button_html = []

        for button in buttons[:4]:  # Max 4 buttons
            style = button.get("style", "default")

            if style == "danger":
                bg_color = "#DC2626"
                text_color = "#FFFFFF"
            elif style == "primary":
                bg_color = "#2563EB"
                text_color = "#FFFFFF"
            elif style == "warning":
                bg_color = "#EA580C"
                text_color = "#FFFFFF"
            else:
                bg_color = "#6B7280"
                text_color = "#FFFFFF"

            url = f"{self.base_url}/actions/{button['id']}/{alert_id}"

            button_html.append(f'''
                <td align="center" style="padding: 5px;">
                    <a href="{html.escape(url)}"
                       style="display: inline-block; padding: 10px 20px;
                              background-color: {bg_color}; color: {text_color};
                              text-decoration: none; border-radius: 4px;
                              font-size: 14px; font-weight: 500;">
                        {html.escape(button['label'])}
                    </a>
                </td>
            ''')

        return f'''
            <tr>
                <td style="padding: 20px 30px;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" align="center">
                        <tr>
                            {"".join(button_html)}
                        </tr>
                    </table>
                </td>
            </tr>
        '''

    def _build_links_html(self, links: List[Dict[str, str]]) -> str:
        """Build investigation links HTML.

        Args:
            links: Link definitions

        Returns:
            HTML for links section
        """
        valid_links = [
            link for link in links
            if link.get("url") and "N/A" not in link["url"]
        ]

        if not valid_links:
            return ""

        link_items = []
        for link in valid_links[:5]:
            link_items.append(
                f'<a href="{html.escape(link["url"])}" '
                f'style="color: #2563EB; text-decoration: none; margin-right: 15px;">'
                f'{html.escape(link["label"])} →</a>'
            )

        return f'''
            <tr>
                <td style="padding: 15px 30px; background-color: #F9FAFB; border-top: 1px solid #E5E7EB;">
                    <p style="margin: 0 0 10px 0; color: #6B7280; font-size: 12px; font-weight: 600; text-transform: uppercase;">
                        Investigation Links
                    </p>
                    <p style="margin: 0;">
                        {"".join(link_items)}
                    </p>
                </td>
            </tr>
        '''

    def _build_recommendations_html(self, recommendations: List[str]) -> str:
        """Build recommended actions HTML.

        Args:
            recommendations: List of recommendations

        Returns:
            HTML for recommendations section
        """
        items = "".join(
            f'<li style="margin: 5px 0; color: #374151;">{html.escape(rec)}</li>'
            for rec in recommendations[:6]
        )

        return f'''
            <tr>
                <td style="padding: 20px 30px; background-color: #FEF3C7; border-left: 4px solid #F59E0B;">
                    <h4 style="margin: 0 0 10px 0; color: #92400E; font-size: 14px; font-weight: 600;">
                        Recommended Actions
                    </h4>
                    <ol style="margin: 0; padding-left: 20px;">
                        {items}
                    </ol>
                </td>
            </tr>
        '''

    def _get_logo_html(self) -> str:
        """Get logo HTML if logo URL is set.

        Returns:
            Logo HTML or empty string
        """
        if not self.logo_url:
            return ""

        return f'''
            <img src="{html.escape(self.logo_url)}"
                 alt="{html.escape(self.company_name)}"
                 style="max-width: 120px; max-height: 40px; margin-bottom: 10px;">
            <br>
        '''

    def _get_mitre_html(self, technique: Optional[str]) -> str:
        """Get MITRE ATT&CK technique HTML.

        Args:
            technique: MITRE technique ID

        Returns:
            HTML for MITRE reference
        """
        if not technique:
            return ""

        mitre_url = f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"

        return f'''
            <p style="margin: 10px 0 0 0; text-align: center;">
                <a href="{mitre_url}"
                   style="color: #6B7280; font-size: 11px; text-decoration: none;">
                    MITRE ATT&CK: {html.escape(technique)}
                </a>
            </p>
        '''
