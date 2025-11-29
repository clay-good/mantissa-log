"""
Enrichment Prompt Templates

Structured prompts for LLM-powered alert enrichment.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime


class EnrichmentPromptBuilder:
    """Builds structured prompts for alert enrichment."""

    SYSTEM_PROMPT = """You are a security analyst assistant for Mantissa Log, an open-source SIEM.
Your task is to analyze security alerts and provide enriched context to help analysts investigate.

You will receive:
1. Detection rule information (what triggered the alert)
2. Event data from the alert
3. Behavioral context (historical patterns for the user/entity)
4. Baseline statistics (normal vs current activity levels)

Provide analysis in the exact format requested. Be concise but thorough.
Focus on actionable insights. Do not speculate beyond the evidence provided.
If you cannot determine something from the data, say "Unknown" rather than guessing."""

    @staticmethod
    def build_enrichment_prompt(
        alert_data: Dict[str, Any],
        rule_info: Dict[str, Any],
        behavioral_context: Dict[str, Any],
        baseline_stats: Dict[str, Any],
        include_components: Dict[str, bool]
    ) -> str:
        """
        Build the enrichment prompt for the LLM.

        Args:
            alert_data: Alert payload with event details
            rule_info: Sigma rule metadata
            behavioral_context: Historical behavior for the entity
            baseline_stats: Statistical baseline comparison
            include_components: Which enrichment sections to include

        Returns:
            Formatted prompt string
        """
        prompt_parts = []

        # Header
        prompt_parts.append("# Security Alert Enrichment Request\n")

        # Alert Data Section
        prompt_parts.append("## Alert Data\n")
        prompt_parts.append(f"- Alert ID: {alert_data.get('alert_id', 'N/A')}")
        prompt_parts.append(f"- Detection Name: {alert_data.get('detection_name', 'N/A')}")
        prompt_parts.append(f"- Severity: {alert_data.get('severity', 'N/A')}")
        prompt_parts.append(f"- Timestamp: {alert_data.get('timestamp', 'N/A')}")
        prompt_parts.append(f"- Event Count: {alert_data.get('event_count', 'N/A')}")

        # Event Details
        if alert_data.get('events'):
            prompt_parts.append("\n### Event Details (First Event)")
            first_event = alert_data['events'][0] if isinstance(alert_data['events'], list) else alert_data['events']
            for key, value in first_event.items():
                if value is not None:
                    prompt_parts.append(f"- {key}: {value}")

        # Rule Information
        prompt_parts.append("\n## Detection Rule Information")
        prompt_parts.append(f"- Rule ID: {rule_info.get('id', 'N/A')}")
        prompt_parts.append(f"- Rule Title: {rule_info.get('title', 'N/A')}")
        prompt_parts.append(f"- Description: {rule_info.get('description', 'N/A')}")

        if rule_info.get('mitre_attack'):
            mitre = rule_info['mitre_attack']
            prompt_parts.append(f"- MITRE ATT&CK Tactic: {mitre.get('tactic', 'N/A')}")
            prompt_parts.append(f"- MITRE ATT&CK Technique: {mitre.get('technique', 'N/A')}")

        if rule_info.get('tags'):
            prompt_parts.append(f"- Tags: {', '.join(rule_info['tags'])}")

        if rule_info.get('falsepositives'):
            prompt_parts.append(f"- Known False Positives: {', '.join(rule_info['falsepositives'])}")

        # Behavioral Context
        if include_components.get('behavioral_context', True) and behavioral_context:
            prompt_parts.append("\n## Behavioral Context (Historical Data)")

            if behavioral_context.get('user_history'):
                user_hist = behavioral_context['user_history']
                prompt_parts.append("\n### User Activity History")
                prompt_parts.append(f"- Has performed this action before: {user_hist.get('has_done_before', 'Unknown')}")
                prompt_parts.append(f"- Previous occurrences (30 days): {user_hist.get('previous_count', 'N/A')}")
                prompt_parts.append(f"- Typical source IPs: {', '.join(user_hist.get('typical_ips', ['N/A']))}")
                prompt_parts.append(f"- Typical times: {user_hist.get('typical_times', 'N/A')}")

            if behavioral_context.get('ip_history'):
                ip_hist = behavioral_context['ip_history']
                prompt_parts.append("\n### Source IP History")
                prompt_parts.append(f"- IP Address: {ip_hist.get('ip', 'N/A')}")
                prompt_parts.append(f"- First seen: {ip_hist.get('first_seen', 'N/A')}")
                prompt_parts.append(f"- Total events from this IP: {ip_hist.get('total_events', 'N/A')}")
                prompt_parts.append(f"- Is internal IP: {ip_hist.get('is_internal', 'Unknown')}")
                prompt_parts.append(f"- Geolocation: {ip_hist.get('geolocation', 'Unknown')}")

            if behavioral_context.get('session_context'):
                session = behavioral_context['session_context']
                prompt_parts.append("\n### Session Context")
                prompt_parts.append(f"- Other actions in same session: {session.get('action_count', 'N/A')}")
                prompt_parts.append(f"- Actions: {', '.join(session.get('actions', ['N/A']))}")
                prompt_parts.append(f"- Session start: {session.get('session_start', 'N/A')}")

        # Baseline Statistics
        if include_components.get('baseline_deviation', True) and baseline_stats:
            prompt_parts.append("\n## Baseline Comparison (Last 30 Days)")
            prompt_parts.append(f"- Average daily occurrences: {baseline_stats.get('avg_daily', 'N/A')}")
            prompt_parts.append(f"- Today's count: {baseline_stats.get('today_count', 'N/A')}")
            prompt_parts.append(f"- Deviation from baseline: {baseline_stats.get('deviation_percent', 'N/A')}%")
            prompt_parts.append(f"- Is anomalous: {baseline_stats.get('is_anomalous', 'Unknown')}")

        # Output Format Instructions
        prompt_parts.append("\n---\n")
        prompt_parts.append("# Required Output Format\n")
        prompt_parts.append("Analyze the above data and provide the following sections:\n")

        if include_components.get('five_w_one_h', True):
            prompt_parts.append("""
## 5W1H SUMMARY
Provide a structured summary answering:
- WHO: [The user, service account, or entity that performed the action]
- WHAT: [The specific action/event that triggered the detection]
- WHEN: [Timestamp with day-of-week and business hours context]
- WHERE: [AWS region, IP address with ISP/location if available, resource affected]
- WHY: [Likely intent based on context - be careful not to over-speculate]
- HOW: [Technical method - API call, console, CLI, SDK, etc.]
""")

        if include_components.get('behavioral_context', True):
            prompt_parts.append("""
## BEHAVIORAL CONTEXT
Analyze the historical patterns and note:
- Whether this is normal or unusual for this user/entity
- Any deviations from typical behavior (IP, time, location, action frequency)
- Related actions in the same session that form a pattern
Use indicators like "NORMAL", "UNUSUAL", "FIRST TIME", "ELEVATED" to be clear.
""")

        if include_components.get('baseline_deviation', True):
            prompt_parts.append("""
## BASELINE COMPARISON
Compare current activity to the 30-day baseline:
- Statistical deviation (percentage above/below normal)
- Whether this is a significant anomaly
- Similar anomalies in recent history
""")

        if include_components.get('detection_explainer', True):
            prompt_parts.append("""
## DETECTION DETAILS
Explain:
- What the detection rule looks for and why it triggered
- The MITRE ATT&CK technique and its significance
- Why this matters from a security perspective (potential business impact)
""")

        if include_components.get('recommended_actions', True):
            prompt_parts.append("""
## RECOMMENDED ACTIONS
Provide 3-5 specific, actionable next steps for the analyst, such as:
- Verification steps (check change management, contact user)
- Investigation steps (what else to look at)
- Remediation steps (if confirmed malicious)
""")

        return "\n".join(prompt_parts)

    @staticmethod
    def parse_enrichment_response(response: str) -> Dict[str, str]:
        """
        Parse the LLM response into structured sections.

        Args:
            response: Raw LLM response text

        Returns:
            Dictionary with section names as keys
        """
        sections = {
            'five_w_one_h': '',
            'behavioral_context': '',
            'baseline_comparison': '',
            'detection_details': '',
            'recommended_actions': '',
            'raw_response': response
        }

        current_section = None
        current_content = []

        for line in response.split('\n'):
            line_lower = line.lower().strip()

            # Detect section headers
            if '5w1h' in line_lower or 'summary' in line_lower and 'who' in response.lower():
                if current_section:
                    sections[current_section] = '\n'.join(current_content).strip()
                current_section = 'five_w_one_h'
                current_content = []
            elif 'behavioral context' in line_lower:
                if current_section:
                    sections[current_section] = '\n'.join(current_content).strip()
                current_section = 'behavioral_context'
                current_content = []
            elif 'baseline' in line_lower and ('comparison' in line_lower or 'deviation' in line_lower):
                if current_section:
                    sections[current_section] = '\n'.join(current_content).strip()
                current_section = 'baseline_comparison'
                current_content = []
            elif 'detection' in line_lower and 'details' in line_lower:
                if current_section:
                    sections[current_section] = '\n'.join(current_content).strip()
                current_section = 'detection_details'
                current_content = []
            elif 'recommended' in line_lower and 'action' in line_lower:
                if current_section:
                    sections[current_section] = '\n'.join(current_content).strip()
                current_section = 'recommended_actions'
                current_content = []
            elif current_section:
                # Skip the header line itself
                if not line.startswith('##'):
                    current_content.append(line)

        # Save the last section
        if current_section and current_content:
            sections[current_section] = '\n'.join(current_content).strip()

        return sections

    @staticmethod
    def format_enriched_alert(
        original_payload: Dict[str, Any],
        enrichment_sections: Dict[str, str],
        severity: str
    ) -> str:
        """
        Format the enriched alert for output to Slack/Jira.

        Args:
            original_payload: Original alert payload
            enrichment_sections: Parsed enrichment sections from LLM
            severity: Alert severity

        Returns:
            Formatted alert string
        """
        severity_indicator = {
            'critical': 'CRITICAL',
            'high': 'HIGH',
            'medium': 'MEDIUM',
            'low': 'LOW',
            'info': 'INFO'
        }.get(severity.lower(), 'ALERT')

        lines = []
        lines.append(f"{severity_indicator}: {original_payload.get('detection_name', 'Security Alert')}")
        lines.append("")

        # 5W1H Summary
        if enrichment_sections.get('five_w_one_h'):
            lines.append("5W1H SUMMARY:")
            lines.append("-" * 60)
            lines.append(enrichment_sections['five_w_one_h'])
            lines.append("")

        # Behavioral Context
        if enrichment_sections.get('behavioral_context'):
            lines.append("BEHAVIORAL CONTEXT:")
            lines.append("-" * 60)
            lines.append(enrichment_sections['behavioral_context'])
            lines.append("")

        # Baseline Comparison
        if enrichment_sections.get('baseline_comparison'):
            lines.append("BASELINE COMPARISON (Last 30 Days):")
            lines.append("-" * 60)
            lines.append(enrichment_sections['baseline_comparison'])
            lines.append("")

        # Detection Details
        if enrichment_sections.get('detection_details'):
            lines.append("DETECTION DETAILS:")
            lines.append("-" * 60)
            lines.append(enrichment_sections['detection_details'])
            lines.append("")

        # Recommended Actions
        if enrichment_sections.get('recommended_actions'):
            lines.append("RECOMMENDED ACTIONS:")
            lines.append("-" * 60)
            lines.append(enrichment_sections['recommended_actions'])
            lines.append("")

        # Footer
        lines.append("-" * 60)
        lines.append(f"Alert ID: {original_payload.get('alert_id', 'N/A')}")
        lines.append(f"Rule ID: {original_payload.get('rule_id', 'N/A')}")
        lines.append("Generated by Mantissa Log LLM-Enriched Alerts")

        return "\n".join(lines)
