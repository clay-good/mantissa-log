"""Sigma to Natural Language Description Generator.

Generates human-readable descriptions from Sigma YAML rules.
Includes: what it detects, why it matters, and response steps.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


# MITRE ATT&CK tactic descriptions
TACTIC_DESCRIPTIONS = {
    "reconnaissance": "gathering information about the target",
    "resource_development": "establishing infrastructure for attacks",
    "initial_access": "gaining initial foothold in the environment",
    "execution": "running malicious code",
    "persistence": "maintaining access to systems",
    "privilege_escalation": "gaining higher-level permissions",
    "defense_evasion": "avoiding detection",
    "credential_access": "stealing credentials",
    "discovery": "exploring the environment",
    "lateral_movement": "moving through the network",
    "collection": "gathering data of interest",
    "command_and_control": "communicating with compromised systems",
    "exfiltration": "stealing data from the network",
    "impact": "disrupting or destroying systems and data",
}

# Common technique descriptions
TECHNIQUE_DESCRIPTIONS = {
    "t1110": "attempting to gain access through password guessing or brute force",
    "t1110.001": "performing password guessing attacks",
    "t1110.003": "conducting password spraying attacks",
    "t1078": "using valid accounts for access",
    "t1078.004": "using cloud accounts for access",
    "t1136": "creating new accounts for persistence",
    "t1098": "manipulating accounts to maintain access",
    "t1098.001": "adding additional credentials to accounts",
    "t1098.004": "adding SSH keys for persistence",
    "t1562": "impairing defenses",
    "t1562.001": "disabling security tools",
    "t1562.008": "disabling cloud logging",
    "t1562.007": "modifying firewall rules",
    "t1087": "enumerating accounts in the environment",
    "t1046": "scanning network services",
    "t1530": "accessing data from cloud storage",
    "t1567": "exfiltrating data over web services",
    "t1041": "exfiltrating data over command and control channels",
    "t1071": "communicating using application layer protocols",
    "t1071.004": "using DNS for command and control",
    "t1486": "encrypting data for impact (ransomware)",
    "t1496": "using resources for cryptocurrency mining",
    "t1566": "using phishing for initial access",
    "t1566.001": "using spearphishing attachments",
    "t1648": "serverless compute abuse",
}

# Log source descriptions
LOGSOURCE_DESCRIPTIONS = {
    ("aws", "cloudtrail"): "AWS CloudTrail audit logs",
    ("aws", "vpcflow"): "AWS VPC Flow Logs",
    ("aws", "guardduty"): "AWS GuardDuty findings",
    ("gcp", "gcp.audit"): "Google Cloud audit logs",
    ("gcp", "gke"): "Google Kubernetes Engine logs",
    ("azure", "activitylogs"): "Azure Activity Logs",
    ("azure", "signinlogs"): "Azure AD sign-in logs",
    ("m365", "audit"): "Microsoft 365 audit logs",
    ("kubernetes", "audit"): "Kubernetes audit logs",
    ("windows", "security"): "Windows Security event logs",
    ("windows", "sysmon"): "Windows Sysmon logs",
    ("linux", "audit"): "Linux audit logs",
}


@dataclass
class NLDescription:
    """Natural language description of a Sigma rule."""

    rule_id: str
    rule_title: str

    # Main description components
    what_it_detects: str = ""
    why_it_matters: str = ""
    response_steps: List[str] = field(default_factory=list)

    # Additional context
    technical_summary: str = ""
    data_sources: List[str] = field(default_factory=list)
    mitre_attack_summary: str = ""

    # Full formatted description
    full_description: str = ""

    # Severity explanation
    severity_explanation: str = ""

    success: bool = True
    error: Optional[str] = None


class SigmaToNLConverter:
    """Converts Sigma rules to human-readable natural language descriptions."""

    def __init__(self, llm_provider: Optional[Any] = None):
        """Initialize the converter.

        Args:
            llm_provider: Optional LLM provider for enhanced descriptions
        """
        self.llm_provider = llm_provider

    def convert(self, sigma_rule: Dict[str, Any]) -> NLDescription:
        """Convert a Sigma rule to natural language description.

        Args:
            sigma_rule: Sigma rule as dictionary

        Returns:
            NLDescription with human-readable components
        """
        rule_id = sigma_rule.get("id", "unknown")
        rule_title = sigma_rule.get("title", "Untitled Rule")

        try:
            # Generate what it detects
            what_it_detects = self._generate_what_it_detects(sigma_rule)

            # Generate why it matters
            why_it_matters = self._generate_why_it_matters(sigma_rule)

            # Generate response steps
            response_steps = self._generate_response_steps(sigma_rule)

            # Generate technical summary
            technical_summary = self._generate_technical_summary(sigma_rule)

            # Get data sources
            data_sources = self._get_data_sources(sigma_rule)

            # Generate MITRE ATT&CK summary
            mitre_summary = self._generate_mitre_summary(sigma_rule)

            # Generate severity explanation
            severity_explanation = self._generate_severity_explanation(sigma_rule)

            # Combine into full description
            full_description = self._combine_description(
                rule_title=rule_title,
                what_it_detects=what_it_detects,
                why_it_matters=why_it_matters,
                response_steps=response_steps,
                technical_summary=technical_summary,
                data_sources=data_sources,
                mitre_summary=mitre_summary,
                severity_explanation=severity_explanation,
            )

            return NLDescription(
                rule_id=rule_id,
                rule_title=rule_title,
                what_it_detects=what_it_detects,
                why_it_matters=why_it_matters,
                response_steps=response_steps,
                technical_summary=technical_summary,
                data_sources=data_sources,
                mitre_attack_summary=mitre_summary,
                full_description=full_description,
                severity_explanation=severity_explanation,
                success=True,
            )

        except Exception as e:
            logger.error(f"Error converting Sigma rule to NL: {e}")
            return NLDescription(
                rule_id=rule_id,
                rule_title=rule_title,
                success=False,
                error=str(e),
            )

    def convert_yaml(self, sigma_yaml: str) -> NLDescription:
        """Convert Sigma YAML string to natural language description.

        Args:
            sigma_yaml: Sigma rule as YAML string

        Returns:
            NLDescription
        """
        try:
            sigma_dict = yaml.safe_load(sigma_yaml)
            return self.convert(sigma_dict)
        except yaml.YAMLError as e:
            return NLDescription(
                rule_id="unknown",
                rule_title="Unknown",
                success=False,
                error=f"Invalid YAML: {str(e)}",
            )

    def _generate_what_it_detects(self, rule: Dict[str, Any]) -> str:
        """Generate description of what the rule detects."""
        title = rule.get("title", "")
        description = rule.get("description", "")
        detection = rule.get("detection", {})

        # Start with existing description if available
        if description:
            what_detects = description
        else:
            what_detects = f"This rule detects {title.lower()}"

        # Enhance with detection specifics
        detection_details = []

        for key, value in detection.items():
            if key in ["condition", "timeframe"]:
                continue

            if isinstance(value, dict):
                for field_name, field_value in value.items():
                    if isinstance(field_value, list):
                        values_str = ", ".join(str(v) for v in field_value[:3])
                        if len(field_value) > 3:
                            values_str += f" (and {len(field_value) - 3} more)"
                        detection_details.append(f"{field_name} matching {values_str}")
                    elif isinstance(field_value, str):
                        if "*" in field_value:
                            detection_details.append(f"{field_name} containing pattern '{field_value}'")
                        else:
                            detection_details.append(f"{field_name} equals '{field_value}'")

        if detection_details and len(what_detects) < 200:
            what_detects += f". Specifically, it looks for events where {', '.join(detection_details[:3])}"
            if len(detection_details) > 3:
                what_detects += f" and {len(detection_details) - 3} additional conditions"

        return what_detects + "."

    def _generate_why_it_matters(self, rule: Dict[str, Any]) -> str:
        """Generate explanation of why the detection matters."""
        level = rule.get("level", "medium")
        tags = rule.get("tags", [])

        # Extract MITRE tactics and techniques
        tactics = []
        techniques = []

        for tag in tags:
            if isinstance(tag, str) and tag.startswith("attack."):
                attack_value = tag.replace("attack.", "")
                if attack_value.startswith("t"):
                    techniques.append(attack_value)
                else:
                    tactics.append(attack_value)

        why_matters = []

        # Add severity context
        severity_context = {
            "critical": "This is a critical security alert that requires immediate attention.",
            "high": "This is a high-severity detection indicating potentially serious security risks.",
            "medium": "This detection indicates moderate security concerns that should be investigated.",
            "low": "This is a low-severity detection that may indicate suspicious but not immediately threatening activity.",
            "informational": "This is an informational alert for awareness and trend tracking.",
        }
        why_matters.append(severity_context.get(level, ""))

        # Add tactic context
        if tactics:
            tactic_desc = []
            for tactic in tactics[:2]:
                desc = TACTIC_DESCRIPTIONS.get(tactic, tactic.replace("_", " "))
                tactic_desc.append(desc)
            why_matters.append(f"This activity is associated with {' and '.join(tactic_desc)}.")

        # Add technique context
        if techniques:
            tech_desc = []
            for tech in techniques[:2]:
                desc = TECHNIQUE_DESCRIPTIONS.get(tech.lower(), f"technique {tech.upper()}")
                tech_desc.append(desc)
            if tech_desc:
                why_matters.append(f"Attackers use this technique for {' or '.join(tech_desc)}.")

        # Add false positives context
        false_positives = rule.get("falsepositives", [])
        if false_positives and false_positives != ["Unknown"]:
            why_matters.append(
                f"Note: This may also trigger from legitimate activities such as {', '.join(false_positives[:2])}."
            )

        return " ".join(why_matters)

    def _generate_response_steps(self, rule: Dict[str, Any]) -> List[str]:
        """Generate recommended response steps."""
        level = rule.get("level", "medium")
        tags = rule.get("tags", [])
        logsource = rule.get("logsource", {})

        steps = []

        # Initial triage
        steps.append("Verify the alert is not a false positive by checking the source and context")

        # Level-specific steps
        if level in ["critical", "high"]:
            steps.append("Escalate to security team immediately if confirmed")
            steps.append("Consider isolating affected systems if active compromise is suspected")
        else:
            steps.append("Review related events in the timeframe for additional context")

        # Tactic-specific steps
        for tag in tags:
            if isinstance(tag, str):
                tag_lower = tag.lower()
                if "credential" in tag_lower:
                    steps.append("Check for unauthorized access attempts and reset affected credentials")
                elif "persistence" in tag_lower:
                    steps.append("Audit the system for unauthorized scheduled tasks, services, or startup items")
                elif "exfiltration" in tag_lower:
                    steps.append("Review network traffic logs for data transfer patterns")
                elif "defense_evasion" in tag_lower:
                    steps.append("Verify security tool configurations and logging are intact")

        # Source-specific steps
        product = logsource.get("product", "")
        if product == "aws":
            steps.append("Review CloudTrail logs for related API calls")
            steps.append("Check IAM permissions and recent credential usage")
        elif product == "gcp":
            steps.append("Review Cloud Audit logs for related actions")
            steps.append("Check IAM bindings and service account usage")
        elif product == "azure":
            steps.append("Review Azure Activity logs and sign-in logs")
            steps.append("Check Azure AD for suspicious account activity")

        # General closing steps
        steps.append("Document findings and update incident tracking")

        # Deduplicate while preserving order
        seen = set()
        unique_steps = []
        for step in steps:
            if step not in seen:
                seen.add(step)
                unique_steps.append(step)

        return unique_steps[:7]  # Limit to 7 steps

    def _generate_technical_summary(self, rule: Dict[str, Any]) -> str:
        """Generate technical summary of the detection logic."""
        detection = rule.get("detection", {})
        condition = detection.get("condition", "")
        timeframe = detection.get("timeframe", "")

        summary_parts = []

        # Describe the condition logic
        if condition:
            summary_parts.append(f"Detection condition: {condition}")

        # Count selections and filters
        selections = [k for k in detection.keys() if k.startswith("selection")]
        filters = [k for k in detection.keys() if k.startswith("filter")]

        if selections:
            summary_parts.append(f"Uses {len(selections)} selection block(s)")
        if filters:
            summary_parts.append(f"with {len(filters)} filter(s) to reduce false positives")

        # Timeframe
        if timeframe:
            summary_parts.append(f"Aggregates events within {timeframe} timeframe")

        return ". ".join(summary_parts) + "." if summary_parts else ""

    def _get_data_sources(self, rule: Dict[str, Any]) -> List[str]:
        """Get list of data sources required for the rule."""
        logsource = rule.get("logsource", {})
        sources = []

        product = logsource.get("product", "")
        service = logsource.get("service", "")
        category = logsource.get("category", "")

        # Look up friendly description
        key = (product.lower() if product else "", service.lower() if service else "")
        if key in LOGSOURCE_DESCRIPTIONS:
            sources.append(LOGSOURCE_DESCRIPTIONS[key])
        else:
            if product:
                sources.append(f"{product.upper()} logs")
            if service:
                sources.append(f"{service} service")
            if category:
                sources.append(f"{category} category")

        return sources if sources else ["Unspecified log source"]

    def _generate_mitre_summary(self, rule: Dict[str, Any]) -> str:
        """Generate MITRE ATT&CK framework summary."""
        tags = rule.get("tags", [])

        tactics = []
        techniques = []

        for tag in tags:
            if isinstance(tag, str) and tag.startswith("attack."):
                attack_value = tag.replace("attack.", "")
                if attack_value.startswith("t"):
                    techniques.append(attack_value.upper())
                elif attack_value in TACTIC_DESCRIPTIONS:
                    tactics.append(attack_value.replace("_", " ").title())

        parts = []
        if tactics:
            parts.append(f"Tactics: {', '.join(tactics)}")
        if techniques:
            parts.append(f"Techniques: {', '.join(techniques)}")

        return " | ".join(parts) if parts else "No MITRE ATT&CK mapping available"

    def _generate_severity_explanation(self, rule: Dict[str, Any]) -> str:
        """Explain the severity level."""
        level = rule.get("level", "medium")

        explanations = {
            "critical": "Critical severity indicates this detection should trigger immediate response. "
                       "The detected activity has a high likelihood of being malicious and could cause "
                       "significant damage if not addressed immediately.",
            "high": "High severity indicates serious security concerns requiring prompt investigation. "
                   "The detected activity is commonly associated with active attacks or serious "
                   "policy violations.",
            "medium": "Medium severity indicates potentially suspicious activity that warrants "
                     "investigation. While not immediately critical, these detections may reveal "
                     "ongoing issues or early attack stages.",
            "low": "Low severity indicates activity that deviates from normal patterns but is "
                  "often benign. These alerts help establish baselines and detect subtle anomalies.",
            "informational": "Informational severity is for awareness and auditing purposes. "
                           "These detections track notable events without necessarily indicating threats.",
        }

        return explanations.get(level, f"Severity level: {level}")

    def _combine_description(
        self,
        rule_title: str,
        what_it_detects: str,
        why_it_matters: str,
        response_steps: List[str],
        technical_summary: str,
        data_sources: List[str],
        mitre_summary: str,
        severity_explanation: str,
    ) -> str:
        """Combine all components into a full description."""
        lines = [
            f"# {rule_title}",
            "",
            "## What This Detects",
            what_it_detects,
            "",
            "## Why It Matters",
            why_it_matters,
            "",
            "## Severity",
            severity_explanation,
            "",
            "## Recommended Response Steps",
        ]

        for i, step in enumerate(response_steps, 1):
            lines.append(f"{i}. {step}")

        lines.extend([
            "",
            "## Technical Details",
            technical_summary,
            "",
            f"**Data Sources:** {', '.join(data_sources)}",
            "",
            f"**MITRE ATT&CK:** {mitre_summary}",
        ])

        return "\n".join(lines)


def sigma_to_nl(sigma_yaml: str, llm_provider: Optional[Any] = None) -> NLDescription:
    """Convenience function to convert Sigma YAML to natural language.

    Args:
        sigma_yaml: Sigma rule as YAML string
        llm_provider: Optional LLM provider for enhanced descriptions

    Returns:
        NLDescription
    """
    converter = SigmaToNLConverter(llm_provider=llm_provider)
    return converter.convert_yaml(sigma_yaml)
