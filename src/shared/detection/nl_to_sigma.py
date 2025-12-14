"""Natural Language to Sigma Rule Conversion.

This module provides LLM-powered conversion of natural language descriptions
to complete Sigma detection rules with automatic MITRE ATT&CK mapping.
"""

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)


# MITRE ATT&CK tactics and common techniques for automatic mapping
MITRE_TACTICS = {
    "reconnaissance": "TA0043",
    "resource_development": "TA0042",
    "initial_access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege_escalation": "TA0004",
    "defense_evasion": "TA0005",
    "credential_access": "TA0006",
    "discovery": "TA0007",
    "lateral_movement": "TA0008",
    "collection": "TA0009",
    "command_and_control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}

# Common technique keywords for automatic mapping
TECHNIQUE_KEYWORDS = {
    "brute force": ("credential_access", "T1110"),
    "password spray": ("credential_access", "T1110.003"),
    "mfa": ("credential_access", "T1111"),
    "phishing": ("initial_access", "T1566"),
    "spearphishing": ("initial_access", "T1566.001"),
    "privilege escalation": ("privilege_escalation", "T1078"),
    "account creation": ("persistence", "T1136"),
    "ssh key": ("persistence", "T1098.004"),
    "access key": ("persistence", "T1098.001"),
    "scheduled task": ("persistence", "T1053"),
    "cron": ("persistence", "T1053.003"),
    "lambda": ("execution", "T1648"),
    "cloud function": ("execution", "T1648"),
    "data exfiltration": ("exfiltration", "T1041"),
    "s3 bucket": ("collection", "T1530"),
    "storage": ("collection", "T1530"),
    "logging disabled": ("defense_evasion", "T1562.008"),
    "cloudtrail": ("defense_evasion", "T1562.008"),
    "guardduty": ("defense_evasion", "T1562.001"),
    "security group": ("defense_evasion", "T1562.007"),
    "firewall": ("defense_evasion", "T1562.004"),
    "port scan": ("discovery", "T1046"),
    "enumeration": ("discovery", "T1087"),
    "reconnaissance": ("reconnaissance", "T1595"),
    "dns": ("command_and_control", "T1071.004"),
    "crypto mining": ("impact", "T1496"),
    "ransomware": ("impact", "T1486"),
    "encryption": ("impact", "T1486"),
    "root account": ("privilege_escalation", "T1078.004"),
    "admin": ("privilege_escalation", "T1078"),
    "assume role": ("privilege_escalation", "T1078"),
    "sts": ("privilege_escalation", "T1078"),
    "impossible travel": ("initial_access", "T1078"),
    "geolocation": ("initial_access", "T1078"),
    "anomalous": ("initial_access", "T1078"),
}

# Log source mappings for common cloud services
LOG_SOURCE_MAPPINGS = {
    "cloudtrail": {"product": "aws", "service": "cloudtrail"},
    "aws": {"product": "aws", "service": "cloudtrail"},
    "vpc flow": {"product": "aws", "service": "vpcflow"},
    "vpc_flow": {"product": "aws", "service": "vpcflow"},
    "s3": {"product": "aws", "service": "s3"},
    "guardduty": {"product": "aws", "service": "guardduty"},
    "gcp": {"product": "gcp", "service": "gcp.audit"},
    "gcp audit": {"product": "gcp", "service": "gcp.audit"},
    "google workspace": {"product": "google_workspace", "service": "google_workspace.admin"},
    "azure": {"product": "azure", "service": "activitylogs"},
    "azure activity": {"product": "azure", "service": "activitylogs"},
    "azure ad": {"product": "azure", "service": "signinlogs"},
    "entra": {"product": "azure", "service": "signinlogs"},
    "m365": {"product": "m365", "service": "audit"},
    "office 365": {"product": "m365", "service": "audit"},
    "kubernetes": {"product": "kubernetes", "service": "audit"},
    "k8s": {"product": "kubernetes", "service": "audit"},
}


@dataclass
class SigmaGenerationResult:
    """Result of Sigma rule generation from natural language."""

    success: bool
    sigma_yaml: Optional[str] = None
    sigma_dict: Optional[Dict[str, Any]] = None
    rule_id: Optional[str] = None
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None


class NLToSigmaConverter:
    """Converts natural language descriptions to Sigma detection rules."""

    # System prompt for LLM
    SYSTEM_PROMPT = """You are a security detection engineer expert in Sigma rule creation.
Your task is to convert natural language descriptions of security threats into valid Sigma YAML rules.

Rules for creating Sigma rules:
1. Always include: title, id, status, description, author, date, logsource, detection, level, tags
2. Use proper Sigma detection syntax with selection blocks and conditions
3. Map to MITRE ATT&CK techniques using attack.tXXXX format in tags
4. Include relevant false positives
5. Use appropriate severity levels: critical, high, medium, low, informational
6. For cloud logs, use proper logsource (product: aws/gcp/azure, service: cloudtrail/audit/etc.)

Output ONLY valid YAML. Do not include markdown code blocks or explanations."""

    # Example prompt for few-shot learning
    FEW_SHOT_EXAMPLE = """
Example input: "Detect when someone disables CloudTrail logging in AWS"

Example output:
title: AWS CloudTrail Logging Disabled
id: aws-cloudtrail-disabled-001
status: experimental
description: Detects when CloudTrail logging is stopped or deleted, which may indicate an attacker attempting to hide their activities
author: Mantissa Security
date: {date}
modified: {date}

logsource:
  product: aws
  service: cloudtrail

detection:
  selection:
    eventSource: cloudtrail.amazonaws.com
    eventName:
      - StopLogging
      - DeleteTrail
      - UpdateTrail
  filter_update:
    eventName: UpdateTrail
    requestParameters.isMultiRegionTrail: true
  condition: selection and not filter_update

fields:
  - userIdentity.arn
  - eventName
  - requestParameters.name
  - sourceIPAddress

falsepositives:
  - Legitimate CloudTrail configuration changes by administrators
  - Infrastructure as code deployments

level: high

tags:
  - attack.defense_evasion
  - attack.t1562.008
"""

    def __init__(
        self,
        llm_provider: Optional[Any] = None,
        default_author: str = "Mantissa Security",
    ):
        """Initialize the converter.

        Args:
            llm_provider: LLM provider instance (AnthropicProvider, etc.)
            default_author: Default author name for generated rules
        """
        self.llm_provider = llm_provider
        self.default_author = default_author

    def convert(
        self,
        natural_language: str,
        log_source_hint: Optional[str] = None,
        severity_hint: Optional[str] = None,
        additional_context: Optional[str] = None,
    ) -> SigmaGenerationResult:
        """Convert natural language description to Sigma rule.

        Args:
            natural_language: Natural language description of the detection
            log_source_hint: Optional hint about the log source (e.g., "cloudtrail", "gcp")
            severity_hint: Optional hint about severity (critical, high, medium, low)
            additional_context: Optional additional context for the LLM

        Returns:
            SigmaGenerationResult with the generated rule or error
        """
        if not self.llm_provider:
            return SigmaGenerationResult(
                success=False,
                error="No LLM provider configured. Cannot generate Sigma rules."
            )

        # Auto-detect MITRE techniques from keywords
        detected_tactics, detected_techniques = self._detect_mitre_from_keywords(natural_language)

        # Auto-detect log source from keywords
        detected_logsource = self._detect_logsource(natural_language, log_source_hint)

        # Build the prompt
        prompt = self._build_prompt(
            natural_language=natural_language,
            log_source=detected_logsource,
            severity_hint=severity_hint,
            detected_techniques=detected_techniques,
            additional_context=additional_context,
        )

        try:
            # Call LLM
            response = self.llm_provider.generate(
                prompt=prompt,
                max_tokens=2000,
                temperature=0.1,  # Low temperature for consistent output
            )

            # Parse the YAML response
            sigma_yaml = self._clean_yaml_response(response.content)
            sigma_dict = yaml.safe_load(sigma_yaml)

            # Validate and enhance the rule
            sigma_dict, warnings = self._validate_and_enhance(
                sigma_dict,
                detected_tactics,
                detected_techniques,
            )

            # Generate final YAML
            final_yaml = yaml.dump(sigma_dict, default_flow_style=False, sort_keys=False)

            # Calculate confidence score
            confidence = self._calculate_confidence(sigma_dict, natural_language)

            return SigmaGenerationResult(
                success=True,
                sigma_yaml=final_yaml,
                sigma_dict=sigma_dict,
                rule_id=sigma_dict.get("id"),
                mitre_techniques=detected_techniques,
                mitre_tactics=detected_tactics,
                confidence_score=confidence,
                warnings=warnings,
            )

        except yaml.YAMLError as e:
            logger.error(f"Failed to parse LLM response as YAML: {e}")
            return SigmaGenerationResult(
                success=False,
                error=f"Invalid YAML in LLM response: {str(e)}"
            )
        except Exception as e:
            logger.error(f"Error generating Sigma rule: {e}")
            return SigmaGenerationResult(
                success=False,
                error=str(e)
            )

    def _build_prompt(
        self,
        natural_language: str,
        log_source: Optional[Dict[str, str]],
        severity_hint: Optional[str],
        detected_techniques: List[str],
        additional_context: Optional[str],
    ) -> str:
        """Build the LLM prompt for Sigma generation."""
        today = datetime.utcnow().strftime("%Y-%m-%d")

        prompt_parts = [
            self.SYSTEM_PROMPT,
            "",
            self.FEW_SHOT_EXAMPLE.format(date=today),
            "",
            "Now create a Sigma rule for the following:",
            f"Description: {natural_language}",
        ]

        if log_source:
            prompt_parts.append(f"Log source: product={log_source.get('product')}, service={log_source.get('service')}")

        if severity_hint:
            prompt_parts.append(f"Severity level: {severity_hint}")

        if detected_techniques:
            prompt_parts.append(f"Relevant MITRE ATT&CK techniques: {', '.join(detected_techniques)}")

        if additional_context:
            prompt_parts.append(f"Additional context: {additional_context}")

        prompt_parts.extend([
            "",
            f"Use today's date: {today}",
            f"Use author: {self.default_author}",
            f"Generate a unique rule ID starting with the pattern: mantissa-{uuid.uuid4().hex[:8]}",
            "",
            "Output ONLY the YAML rule, nothing else:",
        ])

        return "\n".join(prompt_parts)

    def _clean_yaml_response(self, response: str) -> str:
        """Clean the LLM response to extract valid YAML."""
        # Remove markdown code blocks if present
        response = re.sub(r'^```ya?ml?\s*', '', response, flags=re.MULTILINE)
        response = re.sub(r'^```\s*$', '', response, flags=re.MULTILINE)

        # Remove any leading/trailing whitespace
        response = response.strip()

        return response

    def _detect_mitre_from_keywords(
        self, text: str
    ) -> Tuple[List[str], List[str]]:
        """Detect MITRE ATT&CK tactics and techniques from keywords."""
        text_lower = text.lower()
        tactics = set()
        techniques = set()

        for keyword, (tactic, technique) in TECHNIQUE_KEYWORDS.items():
            if keyword in text_lower:
                tactics.add(tactic)
                techniques.add(technique)

        return list(tactics), list(techniques)

    def _detect_logsource(
        self, text: str, hint: Optional[str] = None
    ) -> Optional[Dict[str, str]]:
        """Detect appropriate log source from text and hint."""
        # Use hint if provided
        if hint:
            hint_lower = hint.lower()
            for key, mapping in LOG_SOURCE_MAPPINGS.items():
                if key in hint_lower:
                    return mapping

        # Try to detect from text
        text_lower = text.lower()
        for key, mapping in LOG_SOURCE_MAPPINGS.items():
            if key in text_lower:
                return mapping

        return None

    def _validate_and_enhance(
        self,
        sigma_dict: Dict[str, Any],
        detected_tactics: List[str],
        detected_techniques: List[str],
    ) -> Tuple[Dict[str, Any], List[str]]:
        """Validate and enhance the generated Sigma rule."""
        warnings = []

        # Ensure required fields exist
        required_fields = ["title", "logsource", "detection"]
        for field_name in required_fields:
            if field_name not in sigma_dict:
                warnings.append(f"Missing required field: {field_name}")

        # Generate ID if missing
        if "id" not in sigma_dict:
            sigma_dict["id"] = f"mantissa-{uuid.uuid4().hex[:12]}"
            warnings.append("Generated missing rule ID")

        # Set status if missing
        if "status" not in sigma_dict:
            sigma_dict["status"] = "experimental"

        # Set date if missing
        if "date" not in sigma_dict:
            sigma_dict["date"] = datetime.utcnow().strftime("%Y-%m-%d")

        # Set default level if missing
        if "level" not in sigma_dict:
            sigma_dict["level"] = "medium"
            warnings.append("Set default severity to medium")

        # Ensure tags list exists
        if "tags" not in sigma_dict:
            sigma_dict["tags"] = []

        # Add detected MITRE techniques to tags
        existing_tags = set(sigma_dict.get("tags", []))
        for tactic in detected_tactics:
            tag = f"attack.{tactic}"
            if tag not in existing_tags:
                sigma_dict["tags"].append(tag)
                existing_tags.add(tag)

        for technique in detected_techniques:
            tag = f"attack.{technique.lower()}"
            if tag not in existing_tags:
                sigma_dict["tags"].append(tag)
                existing_tags.add(tag)

        # Validate detection structure
        if "detection" in sigma_dict:
            detection = sigma_dict["detection"]
            if "condition" not in detection:
                warnings.append("Detection missing condition field")
                # Try to auto-generate condition from selection keys
                selection_keys = [k for k in detection.keys() if k.startswith("selection")]
                if selection_keys:
                    detection["condition"] = " or ".join(selection_keys)
                    warnings.append(f"Auto-generated condition: {detection['condition']}")

        # Add default falsepositives if missing
        if "falsepositives" not in sigma_dict:
            sigma_dict["falsepositives"] = ["Unknown"]

        return sigma_dict, warnings

    def _calculate_confidence(
        self, sigma_dict: Dict[str, Any], original_text: str
    ) -> float:
        """Calculate a confidence score for the generated rule."""
        score = 0.0

        # Has all required fields (+30%)
        required = ["title", "id", "logsource", "detection", "level"]
        for field_name in required:
            if field_name in sigma_dict:
                score += 0.06  # 6% per field = 30%

        # Has proper detection structure (+20%)
        if "detection" in sigma_dict:
            detection = sigma_dict["detection"]
            if "condition" in detection:
                score += 0.1
            selection_keys = [k for k in detection.keys() if k.startswith("selection")]
            if selection_keys:
                score += 0.1

        # Has MITRE tags (+15%)
        tags = sigma_dict.get("tags", [])
        attack_tags = [t for t in tags if t.startswith("attack.")]
        if attack_tags:
            score += min(0.15, len(attack_tags) * 0.05)

        # Has proper logsource (+15%)
        if "logsource" in sigma_dict:
            logsource = sigma_dict["logsource"]
            if "product" in logsource and "service" in logsource:
                score += 0.15

        # Has false positives (+10%)
        if "falsepositives" in sigma_dict and sigma_dict["falsepositives"]:
            score += 0.1

        # Has fields (+5%)
        if "fields" in sigma_dict and sigma_dict["fields"]:
            score += 0.05

        # Has references (+5%)
        if "references" in sigma_dict and sigma_dict["references"]:
            score += 0.05

        return min(1.0, score)

    def convert_without_llm(
        self,
        title: str,
        description: str,
        event_fields: Dict[str, Any],
        log_source: str,
        severity: str = "medium",
    ) -> SigmaGenerationResult:
        """Convert structured input to Sigma rule without LLM.

        This is a fallback method for simple rules when LLM is not available.

        Args:
            title: Rule title
            description: Rule description
            event_fields: Dictionary of field names to values for detection
            log_source: Log source type (cloudtrail, gcp, azure, etc.)
            severity: Severity level

        Returns:
            SigmaGenerationResult with the generated rule
        """
        # Get logsource mapping
        logsource = LOG_SOURCE_MAPPINGS.get(
            log_source.lower(),
            {"product": "generic", "service": "generic"}
        )

        # Detect MITRE from title/description
        combined_text = f"{title} {description}"
        detected_tactics, detected_techniques = self._detect_mitre_from_keywords(combined_text)

        # Build tags
        tags = []
        for tactic in detected_tactics:
            tags.append(f"attack.{tactic}")
        for technique in detected_techniques:
            tags.append(f"attack.{technique.lower()}")

        # Build detection
        detection = {
            "selection": event_fields,
            "condition": "selection"
        }

        # Build the Sigma rule
        sigma_dict = {
            "title": title,
            "id": f"mantissa-{uuid.uuid4().hex[:12]}",
            "status": "experimental",
            "description": description,
            "author": self.default_author,
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "logsource": logsource,
            "detection": detection,
            "falsepositives": ["Unknown"],
            "level": severity,
            "tags": tags if tags else ["custom"],
        }

        sigma_yaml = yaml.dump(sigma_dict, default_flow_style=False, sort_keys=False)

        return SigmaGenerationResult(
            success=True,
            sigma_yaml=sigma_yaml,
            sigma_dict=sigma_dict,
            rule_id=sigma_dict["id"],
            mitre_techniques=detected_techniques,
            mitre_tactics=detected_tactics,
            confidence_score=0.6,  # Lower confidence for non-LLM generation
            warnings=["Generated without LLM - manual review recommended"],
        )


def create_sigma_from_query(
    query: str,
    llm_provider: Optional[Any] = None,
    log_source: Optional[str] = None,
    severity: Optional[str] = None,
) -> SigmaGenerationResult:
    """Convenience function to create a Sigma rule from a natural language query.

    Args:
        query: Natural language description of the detection
        llm_provider: Optional LLM provider instance
        log_source: Optional log source hint
        severity: Optional severity hint

    Returns:
        SigmaGenerationResult
    """
    converter = NLToSigmaConverter(llm_provider=llm_provider)
    return converter.convert(
        natural_language=query,
        log_source_hint=log_source,
        severity_hint=severity,
    )
