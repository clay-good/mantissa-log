"""Slack Block Kit templates for identity alerts.

Provides rich formatting for Slack notifications using Block Kit components.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class SlackBlock:
    """Represents a Slack Block Kit block."""

    type: str
    content: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to Slack block format."""
        block = {"type": self.type}
        block.update(self.content)
        return block


@dataclass
class SlackMessage:
    """A complete Slack message with blocks."""

    blocks: List[SlackBlock] = field(default_factory=list)
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    text: str = ""  # Fallback text

    def to_dict(self) -> Dict[str, Any]:
        """Convert to Slack message payload."""
        return {
            "text": self.text,
            "blocks": [b.to_dict() for b in self.blocks],
            "attachments": self.attachments,
        }


class SlackTemplateRenderer:
    """Renders identity alerts as Slack Block Kit messages.

    Creates rich, interactive Slack notifications with:
    - Summary sections
    - User context
    - Anomaly details
    - Timeline sections
    - Action buttons
    """

    # Severity to emoji mapping
    SEVERITY_EMOJI = {
        "critical": ":rotating_light:",
        "high": ":warning:",
        "medium": ":large_yellow_circle:",
        "low": ":large_blue_circle:",
        "info": ":information_source:",
    }

    # Severity to color mapping (for attachments)
    SEVERITY_COLOR = {
        "critical": "#FF0000",
        "high": "#FF6600",
        "medium": "#FFCC00",
        "low": "#00CC00",
        "info": "#0066FF",
    }

    def __init__(self, base_url: str = "", action_url_base: str = ""):
        """Initialize Slack template renderer.

        Args:
            base_url: Base URL for investigation links
            action_url_base: Base URL for action endpoints
        """
        self.base_url = base_url.rstrip("/")
        self.action_url_base = action_url_base.rstrip("/")

    def render_identity_alert(
        self,
        rendered_alert: Any,
        include_actions: bool = True,
    ) -> SlackMessage:
        """Render an identity alert as a Slack message.

        Args:
            rendered_alert: RenderedAlert from IdentityAlertTemplates
            include_actions: Whether to include action buttons

        Returns:
            SlackMessage ready to send
        """
        blocks = []

        # Header section with severity emoji
        emoji = self.SEVERITY_EMOJI.get(rendered_alert.severity.lower(), ":grey_question:")
        blocks.append(self._header_block(f"{emoji} {rendered_alert.title}"))

        # Divider
        blocks.append(self._divider_block())

        # Summary section
        blocks.append(self._section_block(
            f"*Severity:* `{rendered_alert.severity.upper()}`  |  "
            f"*Type:* `{rendered_alert.alert_type}`  |  "
            f"*Alert ID:* `{rendered_alert.alert_id[:8]}...`"
        ))

        # Parse body markdown into sections
        body_sections = self._parse_markdown_sections(rendered_alert.body_markdown)

        for section_title, section_content in body_sections.items():
            if section_content.strip():
                # Add section header
                blocks.append(self._section_block(f"*{section_title}*"))

                # Handle tables vs regular content
                if "|" in section_content and "---" in section_content:
                    # It's a markdown table - convert to fields
                    fields = self._table_to_fields(section_content)
                    if fields:
                        blocks.append(self._fields_block(fields))
                else:
                    # Regular content
                    content = self._format_content_for_slack(section_content)
                    if content:
                        blocks.append(self._context_block([content]))

        # Divider before actions
        blocks.append(self._divider_block())

        # Recommended actions section
        if rendered_alert.recommended_actions:
            actions_text = "\n".join(
                f"• {action}" for action in rendered_alert.recommended_actions[:5]
            )
            blocks.append(self._section_block(f"*Recommended Actions:*\n{actions_text}"))

        # Action buttons
        if include_actions and rendered_alert.action_buttons:
            blocks.append(self._actions_block(
                rendered_alert.action_buttons,
                rendered_alert.alert_id,
            ))

        # Investigation links as context
        if rendered_alert.investigation_links:
            links_text = " | ".join(
                f"<{link['url']}|{link['label']}>"
                for link in rendered_alert.investigation_links
                if link.get("url") and "N/A" not in link["url"]
            )
            if links_text:
                blocks.append(self._context_block([f":mag: {links_text}"]))

        # Footer with timestamp
        blocks.append(self._context_block([
            f"Rendered at {rendered_alert.rendered_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        ]))

        return SlackMessage(
            blocks=blocks,
            text=f"{emoji} {rendered_alert.title}",
            attachments=[{
                "color": self.SEVERITY_COLOR.get(rendered_alert.severity.lower(), "#808080"),
                "fallback": rendered_alert.title,
            }],
        )

    def render_brute_force_alert(
        self,
        user_email: str,
        failure_count: int,
        source_ip: str,
        source_location: str,
        time_window: str,
        severity: str = "high",
        alert_id: str = "",
        additional_context: Optional[Dict[str, Any]] = None,
    ) -> SlackMessage:
        """Render a brute force alert with specific formatting.

        Args:
            user_email: Target user email
            failure_count: Number of failed attempts
            source_ip: Attacking IP address
            source_location: Geographic location
            time_window: Time window of attack
            severity: Alert severity
            alert_id: Alert identifier
            additional_context: Additional context data

        Returns:
            SlackMessage for brute force alert
        """
        blocks = []
        ctx = additional_context or {}
        emoji = self.SEVERITY_EMOJI.get(severity.lower(), ":warning:")

        # Header
        blocks.append(self._header_block(
            f"{emoji} Brute Force Attack Detected"
        ))
        blocks.append(self._divider_block())

        # Summary
        blocks.append(self._section_block(
            f"*{failure_count} failed login attempts* detected for "
            f"`{user_email}` from `{source_ip}` ({source_location}) "
            f"in {time_window}."
        ))

        # User context
        blocks.append(self._fields_block([
            ("Department", ctx.get("department", "Unknown")),
            ("Risk Score", f"{ctx.get('risk_score', 0)}/100"),
            ("Normal Hours", ctx.get("typical_hours", "9 AM - 6 PM")),
            ("Provider", ctx.get("provider", "Unknown")),
        ]))

        # Attack details
        blocks.append(self._section_block("*Attack Details*"))
        blocks.append(self._fields_block([
            ("First Attempt", ctx.get("first_attempt", "N/A")),
            ("Last Attempt", ctx.get("last_attempt", "N/A")),
            ("Failure Reasons", ctx.get("failure_reasons", "Invalid credentials")),
            ("Source ISP", ctx.get("source_isp", "Unknown")),
        ]))

        blocks.append(self._divider_block())

        # Actions
        blocks.append(self._actions_block([
            {"id": "investigate", "label": "Investigate", "style": "primary"},
            {"id": "block_ip", "label": f"Block {source_ip}", "style": "danger"},
            {"id": "notify_user", "label": "Notify User", "style": "default"},
            {"id": "dismiss", "label": "Dismiss", "style": "default"},
        ], alert_id))

        return SlackMessage(
            blocks=blocks,
            text=f"{emoji} Brute Force Attack: {user_email}",
            attachments=[{"color": self.SEVERITY_COLOR.get(severity.lower(), "#FF6600")}],
        )

    def render_impossible_travel_alert(
        self,
        user_email: str,
        first_location: str,
        second_location: str,
        distance_km: float,
        time_between: str,
        severity: str = "high",
        alert_id: str = "",
        additional_context: Optional[Dict[str, Any]] = None,
    ) -> SlackMessage:
        """Render an impossible travel alert.

        Args:
            user_email: User email
            first_location: First login location
            second_location: Second login location
            distance_km: Distance between locations
            time_between: Time between logins
            severity: Alert severity
            alert_id: Alert identifier
            additional_context: Additional context

        Returns:
            SlackMessage for impossible travel alert
        """
        blocks = []
        ctx = additional_context or {}
        emoji = self.SEVERITY_EMOJI.get(severity.lower(), ":warning:")

        # Header
        blocks.append(self._header_block(
            f"{emoji} Impossible Travel Detected"
        ))
        blocks.append(self._divider_block())

        # Summary
        blocks.append(self._section_block(
            f"User `{user_email}` logged in from *{first_location}* "
            f"and then *{second_location}* ({distance_km:.0f} km apart) "
            f"within {time_between}."
        ))

        # Travel analysis
        blocks.append(self._section_block("*Travel Analysis*"))
        blocks.append(self._fields_block([
            ("Distance", f"{distance_km:.0f} km"),
            ("Time Between", time_between),
            ("Required Speed", ctx.get("required_speed", "N/A")),
            ("Verdict", ":x: Physically Impossible"),
        ]))

        # Location details
        blocks.append(self._section_block("*Location Details*"))
        blocks.append(self._fields_block([
            ("First Login", f"{first_location}\n{ctx.get('first_time', 'N/A')}"),
            ("Second Login", f"{second_location}\n{ctx.get('second_time', 'N/A')}"),
            ("First IP", ctx.get("first_ip", "Unknown")),
            ("Second IP", ctx.get("second_ip", "Unknown")),
        ]))

        blocks.append(self._divider_block())

        # Actions
        blocks.append(self._actions_block([
            {"id": "investigate", "label": "Investigate", "style": "primary"},
            {"id": "revoke_second", "label": "Revoke 2nd Session", "style": "danger"},
            {"id": "contact_user", "label": "Contact User", "style": "default"},
            {"id": "mark_vpn", "label": "Mark as VPN", "style": "default"},
        ], alert_id))

        return SlackMessage(
            blocks=blocks,
            text=f"{emoji} Impossible Travel: {user_email}",
            attachments=[{"color": self.SEVERITY_COLOR.get(severity.lower(), "#FF6600")}],
        )

    def render_mfa_fatigue_alert(
        self,
        user_email: str,
        push_count: int,
        time_window: str,
        was_approved: bool,
        severity: str = "critical" if True else "high",
        alert_id: str = "",
        additional_context: Optional[Dict[str, Any]] = None,
    ) -> SlackMessage:
        """Render an MFA fatigue (push bombing) alert.

        Args:
            user_email: Target user email
            push_count: Number of push notifications
            time_window: Time window of attack
            was_approved: Whether user eventually approved
            severity: Alert severity
            alert_id: Alert identifier
            additional_context: Additional context

        Returns:
            SlackMessage for MFA fatigue alert
        """
        blocks = []
        ctx = additional_context or {}

        # Escalate severity if approved
        if was_approved:
            severity = "critical"

        emoji = self.SEVERITY_EMOJI.get(severity.lower(), ":warning:")

        # Header with urgent warning if approved
        title = f"{emoji} MFA Fatigue Attack"
        if was_approved:
            title = f":rotating_light: URGENT: MFA Fatigue Attack - USER APPROVED :rotating_light:"

        blocks.append(self._header_block(title))
        blocks.append(self._divider_block())

        # Summary
        approval_status = ":white_check_mark: User Approved (COMPROMISED)" if was_approved else ":x: User Resisted"
        blocks.append(self._section_block(
            f"*{push_count} MFA push notifications* sent to `{user_email}` "
            f"in {time_window}.\n\n*Status:* {approval_status}"
        ))

        if was_approved:
            blocks.append(self._section_block(
                ":warning: *Account may be compromised. Immediate action required.*"
            ))

        # Attack details
        blocks.append(self._fields_block([
            ("Push Count", str(push_count)),
            ("Time Window", time_window),
            ("Denial Count", str(ctx.get("denial_count", push_count - (1 if was_approved else 0)))),
            ("Final Result", "Approved :x:" if was_approved else "Denied :white_check_mark:"),
        ]))

        # Source info
        blocks.append(self._section_block("*Attack Source*"))
        blocks.append(self._fields_block([
            ("Source IP", ctx.get("source_ip", "Unknown")),
            ("Location", ctx.get("source_location", "Unknown")),
            ("Device", ctx.get("source_device", "Unknown")),
        ]))

        blocks.append(self._divider_block())

        # Actions - more urgent if approved
        if was_approved:
            blocks.append(self._actions_block([
                {"id": "revoke_sessions", "label": ":rotating_light: Revoke All Sessions", "style": "danger"},
                {"id": "disable_account", "label": "Disable Account", "style": "danger"},
                {"id": "contact_user", "label": "Contact User", "style": "primary"},
                {"id": "investigate", "label": "Investigate", "style": "default"},
            ], alert_id))
        else:
            blocks.append(self._actions_block([
                {"id": "investigate", "label": "Investigate", "style": "primary"},
                {"id": "block_ip", "label": "Block Source IP", "style": "danger"},
                {"id": "contact_user", "label": "Contact User", "style": "default"},
                {"id": "dismiss", "label": "Dismiss", "style": "default"},
            ], alert_id))

        return SlackMessage(
            blocks=blocks,
            text=f"{emoji} MFA Fatigue Attack: {user_email}",
            attachments=[{"color": self.SEVERITY_COLOR.get(severity.lower(), "#FF0000")}],
        )

    def render_account_takeover_alert(
        self,
        user_email: str,
        indicators: List[str],
        severity: str = "critical",
        alert_id: str = "",
        additional_context: Optional[Dict[str, Any]] = None,
    ) -> SlackMessage:
        """Render an account takeover alert.

        Args:
            user_email: Compromised user email
            indicators: List of takeover indicators
            severity: Alert severity
            alert_id: Alert identifier
            additional_context: Additional context

        Returns:
            SlackMessage for account takeover alert
        """
        blocks = []
        ctx = additional_context or {}

        # Always critical
        emoji = ":rotating_light:"

        # Urgent header
        blocks.append(self._header_block(
            f"{emoji} ACCOUNT TAKEOVER DETECTED {emoji}"
        ))
        blocks.append(self._divider_block())

        # Critical warning
        blocks.append(self._section_block(
            f":warning: *CRITICAL: Account `{user_email}` appears to be compromised.*\n"
            f"Multiple indicators suggest unauthorized access."
        ))

        # Indicators
        indicators_text = "\n".join(f":small_red_triangle: {ind}" for ind in indicators[:5])
        blocks.append(self._section_block(f"*Compromise Indicators:*\n{indicators_text}"))

        # Attack context
        blocks.append(self._fields_block([
            ("Attack Started", ctx.get("attack_start", "N/A")),
            ("Source IP", ctx.get("source_ip", "Unknown")),
            ("Location", ctx.get("source_location", "Unknown")),
            ("Data Accessed", ctx.get("data_accessed", "Under investigation")),
        ]))

        blocks.append(self._divider_block())

        # Urgent action instructions
        blocks.append(self._section_block(
            "*Immediate Actions Required:*\n"
            "1. Disable account immediately\n"
            "2. Revoke all active sessions and tokens\n"
            "3. Reset credentials and MFA\n"
            "4. Notify user through alternate channel\n"
            "5. Initiate incident response"
        ))

        # Actions
        blocks.append(self._actions_block([
            {"id": "disable_account", "label": ":no_entry: DISABLE ACCOUNT", "style": "danger"},
            {"id": "revoke_all", "label": "Revoke All Sessions", "style": "danger"},
            {"id": "create_incident", "label": "Create Incident", "style": "primary"},
            {"id": "investigate", "label": "Investigate", "style": "default"},
        ], alert_id))

        return SlackMessage(
            blocks=blocks,
            text=f":rotating_light: ACCOUNT TAKEOVER: {user_email}",
            attachments=[{"color": "#FF0000"}],
        )

    def _header_block(self, text: str) -> SlackBlock:
        """Create a header block."""
        return SlackBlock(
            type="header",
            content={"text": {"type": "plain_text", "text": text[:150], "emoji": True}},
        )

    def _section_block(self, text: str) -> SlackBlock:
        """Create a section block with markdown text."""
        return SlackBlock(
            type="section",
            content={"text": {"type": "mrkdwn", "text": text[:3000]}},
        )

    def _fields_block(self, fields: List[tuple]) -> SlackBlock:
        """Create a section block with fields."""
        slack_fields = []
        for label, value in fields[:10]:  # Max 10 fields
            slack_fields.append({
                "type": "mrkdwn",
                "text": f"*{label}*\n{value}",
            })

        return SlackBlock(
            type="section",
            content={"fields": slack_fields},
        )

    def _context_block(self, elements: List[str]) -> SlackBlock:
        """Create a context block."""
        return SlackBlock(
            type="context",
            content={
                "elements": [
                    {"type": "mrkdwn", "text": elem[:300]}
                    for elem in elements[:10]
                ]
            },
        )

    def _divider_block(self) -> SlackBlock:
        """Create a divider block."""
        return SlackBlock(type="divider")

    def _actions_block(
        self,
        buttons: List[Dict[str, str]],
        alert_id: str,
    ) -> SlackBlock:
        """Create an actions block with buttons."""
        elements = []

        for button in buttons[:5]:  # Max 5 buttons
            style = button.get("style", "default")

            element = {
                "type": "button",
                "text": {"type": "plain_text", "text": button["label"][:75], "emoji": True},
                "action_id": f"{button['id']}_{alert_id}",
                "value": alert_id,
            }

            # Only primary and danger are valid Slack styles
            if style == "primary":
                element["style"] = "primary"
            elif style in ("danger", "warning"):
                element["style"] = "danger"

            elements.append(element)

        return SlackBlock(type="actions", content={"elements": elements})

    def _parse_markdown_sections(self, markdown: str) -> Dict[str, str]:
        """Parse markdown into sections by headers.

        Args:
            markdown: Markdown text

        Returns:
            Dictionary of section title to content
        """
        sections = {}
        current_section = "Summary"
        current_content = []

        for line in markdown.split("\n"):
            if line.startswith("## "):
                # Save previous section
                if current_content:
                    sections[current_section] = "\n".join(current_content).strip()

                # Start new section
                current_section = line[3:].strip()
                current_content = []
            else:
                current_content.append(line)

        # Save last section
        if current_content:
            sections[current_section] = "\n".join(current_content).strip()

        return sections

    def _table_to_fields(self, table_markdown: str) -> List[tuple]:
        """Convert markdown table to Slack fields.

        Args:
            table_markdown: Markdown table

        Returns:
            List of (label, value) tuples
        """
        fields = []
        lines = [l.strip() for l in table_markdown.split("\n") if l.strip()]

        for line in lines:
            if line.startswith("|") and "---" not in line:
                # Parse table row
                cells = [c.strip() for c in line.split("|") if c.strip()]
                if len(cells) >= 2:
                    # Skip header row detection
                    label = cells[0].replace("**", "").replace("*", "")
                    value = cells[1] if len(cells) > 1 else ""

                    # Skip if looks like header
                    if label.lower() not in ("field", "metric", "indicator"):
                        fields.append((label, value))

        return fields[:10]

    def _format_content_for_slack(self, content: str) -> str:
        """Format markdown content for Slack.

        Args:
            content: Markdown content

        Returns:
            Slack-formatted content
        """
        # Remove excessive whitespace
        lines = [l.strip() for l in content.split("\n")]
        formatted = []

        for line in lines:
            if line:
                # Convert markdown bold to Slack bold
                line = line.replace("**", "*")
                formatted.append(line)

        return "\n".join(formatted)[:2000]
