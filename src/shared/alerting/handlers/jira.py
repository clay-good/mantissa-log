"""Jira alert handler for creating tickets from security alerts."""

import base64
import json
from typing import Dict, Optional
import requests

from .base import AlertHandler
from ...detection.alert_generator import Alert


class JiraHandler(AlertHandler):
    """Handler for creating Jira tickets from alerts."""

    # Severity to priority mapping
    DEFAULT_PRIORITY_MAPPING = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest"
    }

    def __init__(
        self,
        url: str,
        email: str,
        api_token: str,
        project_key: str,
        issue_type: str = "Bug",
        priority_mapping: Optional[Dict[str, str]] = None,
        summary_template: str = "[{{severity}}] {{rule_name}}",
        description_template: str = "default",
        timeout: int = 30
    ):
        """Initialize Jira handler.

        Args:
            url: Jira instance URL (e.g., https://your-domain.atlassian.net)
            email: Email address for authentication
            api_token: Jira API token
            project_key: Project key where issues will be created
            issue_type: Issue type (Bug, Task, Story, etc.)
            priority_mapping: Optional severity to priority mapping
            summary_template: Template for issue summary
            description_template: Template type for description (default, detailed, minimal)
            timeout: Request timeout in seconds
        """
        self.url = url.rstrip("/")
        self.email = email
        self.api_token = api_token
        self.project_key = project_key
        self.issue_type = issue_type
        self.priority_mapping = priority_mapping or self.DEFAULT_PRIORITY_MAPPING
        self.summary_template = summary_template
        self.description_template = description_template
        self.timeout = timeout

    def _get_auth_header(self) -> str:
        """Generate Basic Auth header.

        Returns:
            Base64 encoded auth string
        """
        auth_string = f"{self.email}:{self.api_token}"
        encoded = base64.b64encode(auth_string.encode()).decode()
        return f"Basic {encoded}"

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers.

        Returns:
            Headers dict
        """
        return {
            "Authorization": self._get_auth_header(),
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def validate_config(self) -> bool:
        """Validate Jira configuration by testing API connectivity.

        Returns:
            True if configuration is valid and API is accessible
        """
        if not all([self.url, self.email, self.api_token, self.project_key]):
            return False

        try:
            response = requests.get(
                f"{self.url}/rest/api/3/myself",
                headers=self._get_headers(),
                timeout=self.timeout
            )
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def get_projects(self) -> list:
        """Fetch available Jira projects.

        Returns:
            List of project dicts with key and name
        """
        try:
            response = requests.get(
                f"{self.url}/rest/api/3/project",
                headers=self._get_headers(),
                timeout=self.timeout
            )
            response.raise_for_status()

            projects = response.json()
            return [
                {"key": p["key"], "name": p["name"]}
                for p in projects
            ]
        except requests.exceptions.RequestException:
            return []

    def get_issue_types(self, project_key: Optional[str] = None) -> list:
        """Fetch available issue types for a project.

        Args:
            project_key: Optional project key, uses configured project if not provided

        Returns:
            List of issue type names
        """
        project = project_key or self.project_key
        try:
            response = requests.get(
                f"{self.url}/rest/api/3/project/{project}",
                headers=self._get_headers(),
                timeout=self.timeout
            )
            response.raise_for_status()

            project_data = response.json()
            issue_types = project_data.get("issueTypes", [])
            return [it["name"] for it in issue_types if not it.get("subtask", False)]
        except requests.exceptions.RequestException:
            return ["Bug", "Task", "Story", "Epic"]

    def _render_summary(self, alert: Alert) -> str:
        """Render summary from template.

        Args:
            alert: Alert to render

        Returns:
            Rendered summary string
        """
        summary = self.summary_template
        summary = summary.replace("{{severity}}", alert.severity.upper())
        summary = summary.replace("{{rule_name}}", alert.rule_name)
        summary = summary.replace("{{timestamp}}", alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"))
        summary = summary.replace("{{title}}", alert.title)

        # Jira summary has a max length of 255 characters
        if len(summary) > 255:
            summary = summary[:252] + "..."

        return summary

    def _render_description(self, alert: Alert) -> str:
        """Render description based on template type.

        Args:
            alert: Alert to render

        Returns:
            Rendered description in Jira wiki format
        """
        if self.description_template == "minimal":
            return self._render_minimal_description(alert)
        elif self.description_template == "detailed":
            return self._render_detailed_description(alert)
        else:
            return self._render_default_description(alert)

    def _render_minimal_description(self, alert: Alert) -> str:
        """Render minimal description.

        Args:
            alert: Alert to render

        Returns:
            Minimal description
        """
        lines = [
            f"h2. {alert.title}",
            "",
            f"*Severity:* {alert.severity.upper()}",
            f"*Rule:* {alert.rule_name}",
            f"*Time:* {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"*Alert ID:* {alert.id}",
        ]

        if alert.description:
            lines.extend(["", alert.description])

        return "\n".join(lines)

    def _render_default_description(self, alert: Alert) -> str:
        """Render default description with alert details and results.

        Args:
            alert: Alert to render

        Returns:
            Default description
        """
        lines = [
            f"h2. {alert.title}",
            "",
            f"*Severity:* {alert.severity.upper()}",
            f"*Rule:* {alert.rule_name}",
            f"*Time:* {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"*Alert ID:* {alert.id}",
        ]

        if alert.description:
            lines.extend(["", "h3. Description", alert.description])

        # Add MITRE ATT&CK info
        if alert.mitre_attack:
            tactic = alert.mitre_attack.get("tactic", "N/A")
            technique = alert.mitre_attack.get("technique", "N/A")
            technique_id = alert.mitre_attack.get("technique_id", "")
            lines.extend([
                "",
                "h3. MITRE ATT&CK",
                f"*Tactic:* {tactic}",
                f"*Technique:* {technique}",
            ])
            if technique_id:
                lines.append(f"*Technique ID:* {technique_id}")

        # Add tags
        if alert.tags:
            lines.extend([
                "",
                "h3. Tags",
                ", ".join(f"{{{{monospace}}}}{tag}{{{{monospace}}}}" for tag in alert.tags[:10])
            ])

        # Add results summary
        if alert.results:
            result_count = len(alert.results)
            lines.extend([
                "",
                f"h3. Results ({result_count} matches)",
            ])

            # Show first few results as a table
            if result_count > 0 and isinstance(alert.results[0], dict):
                headers = list(alert.results[0].keys())[:5]
                lines.append("||" + "||".join(headers) + "||")

                for result in alert.results[:5]:
                    row_values = [str(result.get(h, ""))[:50] for h in headers]
                    lines.append("|" + "|".join(row_values) + "|")

                if result_count > 5:
                    lines.append(f"_... and {result_count - 5} more results_")

        lines.extend([
            "",
            "----",
            "_Generated by Mantissa Log_"
        ])

        return "\n".join(lines)

    def _render_detailed_description(self, alert: Alert) -> str:
        """Render detailed description with full context.

        Args:
            alert: Alert to render

        Returns:
            Detailed description
        """
        lines = [
            f"h1. Security Alert: {alert.title}",
            "",
            "h2. Alert Details",
            "||Property||Value||",
            f"|Severity|{alert.severity.upper()}|",
            f"|Rule Name|{alert.rule_name}|",
            f"|Alert ID|{alert.id}|",
            f"|Timestamp|{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}|",
        ]

        if alert.description:
            lines.extend([
                "",
                "h2. Description",
                alert.description
            ])

        # Add MITRE ATT&CK info
        if alert.mitre_attack:
            lines.extend([
                "",
                "h2. MITRE ATT&CK Mapping",
                "||Category||Value||",
            ])
            for key, value in alert.mitre_attack.items():
                lines.append(f"|{key.replace('_', ' ').title()}|{value}|")

        # Add enrichment data if present
        if alert.enrichment:
            lines.extend([
                "",
                "h2. Enrichment Data",
            ])

            if "five_w_one_h" in alert.enrichment:
                lines.append("h3. 5W1H Summary")
                for key, value in alert.enrichment["five_w_one_h"].items():
                    lines.append(f"*{key.upper()}:* {value}")

            if "behavioral_context" in alert.enrichment:
                lines.extend([
                    "",
                    "h3. Behavioral Context",
                    alert.enrichment["behavioral_context"]
                ])

            if "recommended_actions" in alert.enrichment:
                lines.extend([
                    "",
                    "h3. Recommended Actions",
                ])
                for i, action in enumerate(alert.enrichment["recommended_actions"], 1):
                    lines.append(f"# {action}")

        # Add tags
        if alert.tags:
            lines.extend([
                "",
                "h2. Tags",
                ", ".join(f"{{{{monospace}}}}{tag}{{{{monospace}}}}" for tag in alert.tags)
            ])

        # Add full results
        if alert.results:
            result_count = len(alert.results)
            lines.extend([
                "",
                f"h2. Query Results ({result_count} matches)",
            ])

            if result_count > 0 and isinstance(alert.results[0], dict):
                headers = list(alert.results[0].keys())
                lines.append("||" + "||".join(headers) + "||")

                for result in alert.results[:20]:
                    row_values = [str(result.get(h, ""))[:100] for h in headers]
                    lines.append("|" + "|".join(row_values) + "|")

                if result_count > 20:
                    lines.append(f"_... and {result_count - 20} more results_")

        # Add raw event data
        if alert.metadata:
            lines.extend([
                "",
                "h2. Metadata",
                "{code:json}",
                json.dumps(alert.metadata, indent=2, default=str),
                "{code}"
            ])

        lines.extend([
            "",
            "----",
            "_Generated by Mantissa Log - Security Detection Platform_"
        ])

        return "\n".join(lines)

    def _get_priority(self, severity: str) -> str:
        """Get Jira priority for alert severity.

        Args:
            severity: Alert severity level

        Returns:
            Jira priority name
        """
        return self.priority_mapping.get(severity.lower(), "Medium")

    def send(self, alert: Alert) -> bool:
        """Create Jira ticket from alert.

        Args:
            alert: Alert to send

        Returns:
            True if ticket was created successfully
        """
        try:
            payload = self.format_alert(alert)

            response = requests.post(
                f"{self.url}/rest/api/3/issue",
                headers=self._get_headers(),
                json=payload,
                timeout=self.timeout
            )

            response.raise_for_status()

            result = response.json()
            ticket_key = result.get("key")
            if ticket_key:
                print(f"Created Jira ticket: {ticket_key}")
                return True

            return False

        except requests.exceptions.RequestException as e:
            print(f"Error creating Jira ticket: {e}")
            if hasattr(e, "response") and e.response is not None:
                try:
                    error_detail = e.response.json()
                    print(f"Jira API error: {json.dumps(error_detail)}")
                except Exception:
                    print(f"Response text: {e.response.text}")
            return False

    def format_alert(self, alert: Alert) -> dict:
        """Format alert as Jira issue payload.

        Args:
            alert: Alert to format

        Returns:
            Jira issue creation payload
        """
        summary = self._render_summary(alert)
        description = self._render_description(alert)
        priority = self._get_priority(alert.severity)

        # Build the issue payload
        payload = {
            "fields": {
                "project": {
                    "key": self.project_key
                },
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": description
                                }
                            ]
                        }
                    ]
                },
                "issuetype": {
                    "name": self.issue_type
                },
                "priority": {
                    "name": priority
                },
                "labels": self._get_labels(alert)
            }
        }

        return payload

    def _get_labels(self, alert: Alert) -> list:
        """Generate Jira labels from alert.

        Args:
            alert: Alert to get labels from

        Returns:
            List of label strings
        """
        labels = ["mantissa-log", "security-alert"]

        # Add severity as label
        labels.append(f"severity-{alert.severity.lower()}")

        # Add MITRE technique if present
        if alert.mitre_attack:
            technique_id = alert.mitre_attack.get("technique_id", "")
            if technique_id:
                labels.append(technique_id.replace(".", "-"))

        # Add some tags (sanitized for Jira labels)
        if alert.tags:
            for tag in alert.tags[:5]:
                # Jira labels can't have spaces
                sanitized = tag.replace(" ", "-").replace(".", "-")
                if len(sanitized) <= 255:
                    labels.append(sanitized)

        return labels

    def create_test_ticket(self) -> dict:
        """Create a test ticket to verify configuration.

        Returns:
            Dict with success status and ticket URL or error message
        """
        from datetime import datetime, timezone

        # Create a test alert
        test_alert = Alert(
            id="test-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
            title="Mantissa Log Test Alert",
            description="This is a test ticket created to verify Jira integration. You can safely delete this ticket.",
            severity="info",
            rule_id="test-rule",
            rule_name="Integration Test",
            timestamp=datetime.now(timezone.utc),
            results=[],
            tags=["test", "integration-verification"],
            metadata={"test": True}
        )

        try:
            payload = self.format_alert(test_alert)

            response = requests.post(
                f"{self.url}/rest/api/3/issue",
                headers=self._get_headers(),
                json=payload,
                timeout=self.timeout
            )

            response.raise_for_status()

            result = response.json()
            ticket_key = result.get("key")
            ticket_url = f"{self.url}/browse/{ticket_key}"

            return {
                "success": True,
                "ticket_key": ticket_key,
                "ticket_url": ticket_url,
                "message": f"Test ticket {ticket_key} created successfully"
            }

        except requests.exceptions.RequestException as e:
            error_message = str(e)
            if hasattr(e, "response") and e.response is not None:
                try:
                    error_detail = e.response.json()
                    error_message = json.dumps(error_detail.get("errors", error_detail))
                except Exception:
                    error_message = e.response.text

            return {
                "success": False,
                "message": f"Failed to create test ticket: {error_message}"
            }
