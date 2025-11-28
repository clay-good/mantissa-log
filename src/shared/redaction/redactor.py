"""
PII/PHI Redaction Engine

Automatically redacts sensitive information from alert payloads before
sending to external integrations (Slack, Jira, PagerDuty, etc.).

IMPORTANT: Redaction is ONLY applied to integration destinations.
Full raw logs are preserved in storage and query results.
"""

import re
import json
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum


class RedactionType(Enum):
    """Types of data that can be redacted."""
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    AWS_KEY = "aws_key"
    CUSTOM = "custom"


@dataclass
class RedactionPattern:
    """A pattern for redacting sensitive data."""
    type: RedactionType
    pattern: str  # Regex pattern
    replacement: str  # What to replace matches with
    enabled: bool = True
    description: Optional[str] = None

    def redact(self, text: str) -> str:
        """Apply redaction to text."""
        if not self.enabled:
            return text

        return re.sub(self.pattern, self.replacement, text, flags=re.IGNORECASE)


@dataclass
class RedactionResult:
    """Result of redaction operation."""
    original_text: str
    redacted_text: str
    redaction_count: int
    redacted_fields: List[str] = field(default_factory=list)
    patterns_matched: Dict[str, int] = field(default_factory=dict)


# Default redaction patterns
DEFAULT_PATTERNS = {
    RedactionType.EMAIL: RedactionPattern(
        type=RedactionType.EMAIL,
        pattern=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        replacement='[EMAIL_REDACTED]',
        description='Email addresses'
    ),
    RedactionType.PHONE: RedactionPattern(
        type=RedactionType.PHONE,
        pattern=r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
        replacement='[PHONE_REDACTED]',
        description='Phone numbers (US format)'
    ),
    RedactionType.SSN: RedactionPattern(
        type=RedactionType.SSN,
        pattern=r'\b(?!000|666|9\d{2})\d{3}-?(?!00)\d{2}-?(?!0000)\d{4}\b',
        replacement='[SSN_REDACTED]',
        description='Social Security Numbers'
    ),
    RedactionType.CREDIT_CARD: RedactionPattern(
        type=RedactionType.CREDIT_CARD,
        pattern=r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b',
        replacement='[CARD_REDACTED]',
        description='Credit card numbers'
    ),
    RedactionType.IP_ADDRESS: RedactionPattern(
        type=RedactionType.IP_ADDRESS,
        pattern=r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        replacement='[IP_REDACTED]',
        enabled=False,  # Disabled by default - often needed for security analysis
        description='IPv4 addresses'
    ),
    RedactionType.AWS_KEY: RedactionPattern(
        type=RedactionType.AWS_KEY,
        pattern=r'(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}',
        replacement='[AWS_KEY_REDACTED]',
        description='AWS Access Keys'
    ),
}


class Redactor:
    """
    PII/PHI redaction engine.

    Features:
    - Multiple redaction patterns (email, phone, SSN, credit cards, etc.)
    - Custom regex patterns
    - Field-level redaction
    - Audit trail of what was redacted
    - Configurable per integration
    """

    def __init__(self, patterns: Optional[Dict[RedactionType, RedactionPattern]] = None):
        """
        Initialize redactor.

        Args:
            patterns: Custom patterns (uses defaults if not provided)
        """
        self.patterns = patterns or DEFAULT_PATTERNS.copy()

    def add_pattern(
        self,
        name: str,
        pattern: str,
        replacement: str = '[REDACTED]',
        enabled: bool = True
    ):
        """
        Add a custom redaction pattern.

        Args:
            name: Pattern name
            pattern: Regex pattern
            replacement: Replacement text
            enabled: Whether pattern is enabled
        """
        custom_pattern = RedactionPattern(
            type=RedactionType.CUSTOM,
            pattern=pattern,
            replacement=replacement,
            enabled=enabled,
            description=f'Custom pattern: {name}'
        )

        self.patterns[f'custom_{name}'] = custom_pattern

    def enable_pattern(self, pattern_type: RedactionType):
        """Enable a redaction pattern."""
        if pattern_type in self.patterns:
            self.patterns[pattern_type].enabled = True

    def disable_pattern(self, pattern_type: RedactionType):
        """Disable a redaction pattern."""
        if pattern_type in self.patterns:
            self.patterns[pattern_type].enabled = False

    def redact_text(self, text: str) -> RedactionResult:
        """
        Redact sensitive data from text.

        Args:
            text: Text to redact

        Returns:
            RedactionResult with redacted text and metadata
        """
        if not text:
            return RedactionResult(
                original_text=text,
                redacted_text=text,
                redaction_count=0
            )

        original_text = text
        redacted_text = text
        patterns_matched = {}

        # Apply each enabled pattern
        for key, pattern in self.patterns.items():
            if not pattern.enabled:
                continue

            # Count matches before redaction
            matches = re.findall(pattern.pattern, redacted_text, flags=re.IGNORECASE)
            match_count = len(matches)

            if match_count > 0:
                redacted_text = pattern.redact(redacted_text)
                patterns_matched[pattern.type.value] = match_count

        redaction_count = sum(patterns_matched.values())

        return RedactionResult(
            original_text=original_text,
            redacted_text=redacted_text,
            redaction_count=redaction_count,
            patterns_matched=patterns_matched
        )

    def redact_dict(
        self,
        data: Dict[str, Any],
        exclude_fields: Optional[Set[str]] = None
    ) -> Dict[str, Any]:
        """
        Redact sensitive data from a dictionary.

        Args:
            data: Dictionary to redact
            exclude_fields: Fields to exclude from redaction

        Returns:
            Dictionary with redacted values
        """
        if exclude_fields is None:
            exclude_fields = set()

        redacted = {}

        for key, value in data.items():
            # Skip excluded fields
            if key in exclude_fields:
                redacted[key] = value
                continue

            # Recursively redact nested dictionaries
            if isinstance(value, dict):
                redacted[key] = self.redact_dict(value, exclude_fields)

            # Redact lists
            elif isinstance(value, list):
                redacted[key] = [
                    self.redact_dict(item, exclude_fields) if isinstance(item, dict)
                    else self.redact_text(str(item)).redacted_text if isinstance(item, str)
                    else item
                    for item in value
                ]

            # Redact strings
            elif isinstance(value, str):
                result = self.redact_text(value)
                redacted[key] = result.redacted_text

            # Keep other types as-is
            else:
                redacted[key] = value

        return redacted

    def redact_alert_payload(
        self,
        payload: Dict[str, Any],
        preserve_fields: Optional[Set[str]] = None
    ) -> Dict[str, Any]:
        """
        Redact an alert payload for external integrations.

        Args:
            payload: Alert payload
            preserve_fields: Fields to preserve (not redact)

        Returns:
            Redacted payload
        """
        # Common fields to preserve for context
        default_preserve = {
            'alert_id',
            'rule_id',
            'severity',
            'timestamp',
            'event_count',
            'detection_name'
        }

        preserve_fields = preserve_fields or set()
        preserve_fields.update(default_preserve)

        return self.redact_dict(payload, exclude_fields=preserve_fields)

    def get_redaction_summary(
        self,
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Get a summary of what would be redacted without actually redacting.

        Args:
            payload: Payload to analyze

        Returns:
            Summary of potential redactions
        """
        summary = {
            'total_fields_scanned': 0,
            'fields_with_pii': [],
            'redaction_counts': {}
        }

        def scan_dict(d: Dict[str, Any], path: str = ''):
            for key, value in d.items():
                current_path = f'{path}.{key}' if path else key
                summary['total_fields_scanned'] += 1

                if isinstance(value, dict):
                    scan_dict(value, current_path)
                elif isinstance(value, str):
                    result = self.redact_text(value)
                    if result.redaction_count > 0:
                        summary['fields_with_pii'].append({
                            'field': current_path,
                            'patterns_matched': result.patterns_matched
                        })
                        for pattern_type, count in result.patterns_matched.items():
                            summary['redaction_counts'][pattern_type] = \
                                summary['redaction_counts'].get(pattern_type, 0) + count

        scan_dict(payload)

        return summary


class IntegrationRedactionConfig:
    """
    Redaction configuration for a specific integration.

    Allows per-integration customization of redaction rules.
    """

    def __init__(
        self,
        integration_id: str,
        integration_type: str,
        enabled: bool = True,
        enabled_patterns: Optional[Set[RedactionType]] = None,
        custom_patterns: Optional[Dict[str, str]] = None,
        preserve_fields: Optional[Set[str]] = None
    ):
        """
        Initialize integration redaction config.

        Args:
            integration_id: Integration ID
            integration_type: Type of integration
            enabled: Whether redaction is enabled for this integration
            enabled_patterns: Which patterns to enable
            custom_patterns: Custom regex patterns {name: pattern}
            preserve_fields: Fields to preserve (not redact)
        """
        self.integration_id = integration_id
        self.integration_type = integration_type
        self.enabled = enabled
        self.enabled_patterns = enabled_patterns or {
            RedactionType.EMAIL,
            RedactionType.PHONE,
            RedactionType.SSN,
            RedactionType.CREDIT_CARD,
            RedactionType.AWS_KEY
        }
        self.custom_patterns = custom_patterns or {}
        self.preserve_fields = preserve_fields or set()

    def create_redactor(self) -> Redactor:
        """
        Create a redactor instance for this integration.

        Returns:
            Configured Redactor instance
        """
        # Start with default patterns
        patterns = {}

        for pattern_type, pattern in DEFAULT_PATTERNS.items():
            if pattern_type in self.enabled_patterns:
                patterns[pattern_type] = RedactionPattern(
                    type=pattern.type,
                    pattern=pattern.pattern,
                    replacement=pattern.replacement,
                    enabled=True,
                    description=pattern.description
                )

        redactor = Redactor(patterns)

        # Add custom patterns
        for name, pattern in self.custom_patterns.items():
            redactor.add_pattern(name, pattern)

        return redactor

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'integration_id': self.integration_id,
            'integration_type': self.integration_type,
            'enabled': self.enabled,
            'enabled_patterns': [p.value for p in self.enabled_patterns],
            'custom_patterns': self.custom_patterns,
            'preserve_fields': list(self.preserve_fields)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IntegrationRedactionConfig':
        """Create from dictionary."""
        return cls(
            integration_id=data['integration_id'],
            integration_type=data['integration_type'],
            enabled=data.get('enabled', True),
            enabled_patterns={RedactionType(p) for p in data.get('enabled_patterns', [])},
            custom_patterns=data.get('custom_patterns', {}),
            preserve_fields=set(data.get('preserve_fields', []))
        )


def redact_for_integration(
    payload: Dict[str, Any],
    integration_config: IntegrationRedactionConfig
) -> Dict[str, Any]:
    """
    Redact a payload for a specific integration.

    Args:
        payload: Alert payload to redact
        integration_config: Integration-specific redaction config

    Returns:
        Redacted payload
    """
    if not integration_config.enabled:
        # Redaction disabled for this integration
        return payload

    redactor = integration_config.create_redactor()

    return redactor.redact_alert_payload(
        payload,
        preserve_fields=integration_config.preserve_fields
    )


# Example usage for testing
if __name__ == '__main__':
    # Create redactor
    redactor = Redactor()

    # Test text
    test_text = """
    Contact John Doe at john.doe@example.com or call 555-123-4567.
    SSN: 123-45-6789
    Credit Card: 4532-1234-5678-9010
    AWS Key: AKIAIOSFODNN7EXAMPLE
    IP: 192.168.1.100
    """

    result = redactor.redact_text(test_text)

    print("Original:")
    print(test_text)
    print("\nRedacted:")
    print(result.redacted_text)
    print(f"\nRedaction count: {result.redaction_count}")
    print(f"Patterns matched: {result.patterns_matched}")

    # Test dictionary redaction
    test_payload = {
        'alert_id': 'alert-123',
        'severity': 'high',
        'message': 'Suspicious login from user john.doe@example.com',
        'details': {
            'user_email': 'john.doe@example.com',
            'phone': '555-123-4567',
            'ip_address': '192.168.1.100'
        }
    }

    redacted_payload = redactor.redact_alert_payload(test_payload)

    print("\n\nOriginal payload:")
    print(json.dumps(test_payload, indent=2))
    print("\nRedacted payload:")
    print(json.dumps(redacted_payload, indent=2))
