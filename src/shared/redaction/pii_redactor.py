"""
PII/PHI Redaction Module

Redacts sensitive personally identifiable information and protected health information
from alert payloads before sending to external integrations (Slack, Jira, PagerDuty, etc.).

IMPORTANT: Redaction is ONLY applied to integration payloads, NOT to stored logs or query results.
"""

import re
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class RedactionType(Enum):
    """Types of PII/PHI that can be redacted."""
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    MAC_ADDRESS = "mac_address"
    MEDICAL_RECORD = "medical_record"
    CUSTOM = "custom"


@dataclass
class RedactionPattern:
    """Defines a redaction pattern with regex and replacement strategy."""
    type: RedactionType
    pattern: re.Pattern
    replacement: str
    description: str
    enabled: bool = True


# Pre-compiled regex patterns for common PII/PHI
# IMPORTANT: Order matters! More specific patterns (credit cards) must come before
# less specific patterns (phone numbers) to prevent false matches.
REDACTION_PATTERNS = [
    ('credit_card', RedactionPattern(
        type=RedactionType.CREDIT_CARD,
        pattern=re.compile(
            r'\b(?:'
            r'4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|'  # Visa with separators (16 digits)
            r'4[0-9]{15}|'  # Visa without separators (16 digits)
            r'4[0-9]{12}|'  # Visa without separators (13 digits)
            r'5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|'  # MasterCard with separators
            r'5[1-5][0-9]{14}|'  # MasterCard without separators
            r'3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}|'  # American Express with separators
            r'3[47][0-9]{13}|'  # American Express without separators
            r'3(?:0[0-5]|[68][0-9])[0-9]{11}|'  # Diners Club
            r'6(?:011|5[0-9]{2})[0-9]{12}|'  # Discover
            r'(?:2131|1800|35\d{3})\d{11}'  # JCB
            r')\b'
        ),
        replacement='[CARD_REDACTED]',
        description='Credit card numbers'
    )),

    ('email', RedactionPattern(
        type=RedactionType.EMAIL,
        pattern=re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        ),
        replacement='[EMAIL_REDACTED]',
        description='Email addresses'
    )),

    ('ssn', RedactionPattern(
        type=RedactionType.SSN,
        pattern=re.compile(
            r'\b(?!000|666|9\d{2})\d{3}-?(?!00)\d{2}-?(?!0000)\d{4}\b'
        ),
        replacement='[SSN_REDACTED]',
        description='Social Security Numbers'
    )),

    ('phone', RedactionPattern(
        type=RedactionType.PHONE,
        pattern=re.compile(
            r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'
        ),
        replacement='[PHONE_REDACTED]',
        description='Phone numbers (US and international formats)'
    )),

    ('ip_address', RedactionPattern(
        type=RedactionType.IP_ADDRESS,
        pattern=re.compile(
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|'  # IPv4
            r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b'  # IPv6
        ),
        replacement='[IP_REDACTED]',
        description='IP addresses (IPv4 and IPv6)',
        enabled=False  # Disabled by default as IPs may be needed for security context
    )),

    ('mac_address', RedactionPattern(
        type=RedactionType.MAC_ADDRESS,
        pattern=re.compile(
            r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b'
        ),
        replacement='[MAC_REDACTED]',
        description='MAC addresses',
        enabled=False
    )),

    ('medical_record', RedactionPattern(
        type=RedactionType.MEDICAL_RECORD,
        pattern=re.compile(
            r'\b(?:MRN|MR|MEDICAL\s*RECORD)[:\s]+[A-Z0-9]{6,12}\b',
            re.IGNORECASE
        ),
        replacement='[MRN_REDACTED]',
        description='Medical record numbers'
    )),
]

# Convert to dict for backward compatibility while preserving order
REDACTION_PATTERNS_DICT = {RedactionType(p[1].type.value): p[1] for p in REDACTION_PATTERNS}


class PIIRedactor:
    """Redacts PII/PHI from text and structured data."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize redactor with optional configuration.

        Args:
            config: Configuration dict with:
                - enabled_patterns: List of RedactionType values to enable
                - custom_patterns: List of custom regex patterns to add
                - hash_redacted_values: If True, include hash of original value
        """
        self.config = config or {}
        self.patterns = self._initialize_patterns()
        self.hash_redacted = self.config.get('hash_redacted_values', False)
        self.redaction_log: List[Dict[str, Any]] = []

    def _initialize_patterns(self) -> List[Tuple[str, RedactionPattern]]:
        """Initialize redaction patterns based on configuration.

        Returns ordered list of (name, pattern) tuples.
        """
        # Start with copy of default patterns
        patterns = [(name, RedactionPattern(
            type=p.type,
            pattern=p.pattern,
            replacement=p.replacement,
            description=p.description,
            enabled=p.enabled
        )) for name, p in REDACTION_PATTERNS]

        # Override enabled status from config
        enabled_types = self.config.get('enabled_patterns', None)
        if enabled_types is not None:
            for i, (name, pattern) in enumerate(patterns):
                patterns[i] = (name, RedactionPattern(
                    type=pattern.type,
                    pattern=pattern.pattern,
                    replacement=pattern.replacement,
                    description=pattern.description,
                    enabled=pattern.type in enabled_types
                ))

        # Add custom patterns at the end
        custom_patterns = self.config.get('custom_patterns', [])
        for i, custom in enumerate(custom_patterns):
            patterns.append((f'custom_{i}', RedactionPattern(
                type=RedactionType.CUSTOM,
                pattern=re.compile(custom['regex']),
                replacement=custom.get('replacement', '[REDACTED]'),
                description=custom.get('description', f'Custom pattern {i}'),
                enabled=True
            )))

        return patterns

    def redact_text(self, text: str, track: bool = True) -> str:
        """
        Redact PII/PHI from a text string.

        Args:
            text: Text to redact
            track: Whether to track redactions for audit

        Returns:
            Redacted text
        """
        if not text or not isinstance(text, str):
            return text

        redacted = text
        redacted_types: Set[str] = set()

        for pattern_name, pattern in self.patterns:
            if not pattern.enabled:
                continue

            matches = pattern.pattern.findall(redacted)
            if matches:
                redacted_types.add(pattern.type.value)

                if self.hash_redacted:
                    # Replace with hash of original value
                    def replace_with_hash(match, replacement=pattern.replacement):
                        original = match.group(0)
                        hash_val = hashlib.sha256(original.encode()).hexdigest()[:8]
                        return f'{replacement}:{hash_val}'

                    redacted = pattern.pattern.sub(replace_with_hash, redacted)
                else:
                    redacted = pattern.pattern.sub(pattern.replacement, redacted)

        # Track redaction for audit if requested
        if track and redacted != text:
            self.redaction_log.append({
                'original_length': len(text),
                'redacted_length': len(redacted),
                'types_redacted': list(redacted_types),
                'timestamp': None  # Will be set by caller
            })

        return redacted

    def redact_dict(
        self,
        data: Dict[str, Any],
        fields_to_redact: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Recursively redact PII/PHI from dictionary values.

        Args:
            data: Dictionary to redact
            fields_to_redact: Optional list of specific field names to redact.
                             If None, redacts all string values.

        Returns:
            Dictionary with redacted values
        """
        if not isinstance(data, dict):
            return data

        redacted_data = {}

        for key, value in data.items():
            # Check if this field should be redacted
            should_redact = (
                fields_to_redact is None or
                key in fields_to_redact
            )

            if isinstance(value, str) and should_redact:
                redacted_data[key] = self.redact_text(value)
            elif isinstance(value, dict):
                redacted_data[key] = self.redact_dict(value, fields_to_redact)
            elif isinstance(value, list):
                redacted_data[key] = [
                    self.redact_dict(item, fields_to_redact) if isinstance(item, dict)
                    else self.redact_text(item) if isinstance(item, str) and should_redact
                    else item
                    for item in value
                ]
            else:
                redacted_data[key] = value

        return redacted_data

    def redact_integration_payload(
        self,
        integration_type: str,
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Redact PII/PHI from an integration payload.

        This is the main entry point for redacting alert payloads before
        sending to external integrations.

        Args:
            integration_type: Type of integration (slack, jira, pagerduty, etc.)
            payload: The payload to redact

        Returns:
            Redacted payload ready to send to integration
        """
        # Define which fields contain user-visible text per integration
        INTEGRATION_FIELDS = {
            'slack': ['text', 'blocks', 'attachments'],
            'jira': ['summary', 'description', 'fields'],
            'pagerduty': ['summary', 'details', 'custom_details'],
            'email': ['subject', 'body', 'html'],
            'webhook': None  # Redact all fields
        }

        fields_to_redact = INTEGRATION_FIELDS.get(integration_type)

        return self.redact_dict(payload, fields_to_redact)

    def get_redaction_summary(self) -> Dict[str, Any]:
        """
        Get summary of redactions performed.

        Returns:
            Summary with counts and types
        """
        if not self.redaction_log:
            return {
                'total_redactions': 0,
                'types_redacted': [],
                'enabled_patterns': [
                    p.type.value for name, p in self.patterns if p.enabled
                ]
            }

        all_types = set()
        for entry in self.redaction_log:
            all_types.update(entry['types_redacted'])

        return {
            'total_redactions': len(self.redaction_log),
            'types_redacted': list(all_types),
            'enabled_patterns': [
                p.type.value for name, p in self.patterns if p.enabled
            ]
        }

    def clear_log(self):
        """Clear the redaction audit log."""
        self.redaction_log = []


def create_redactor(user_config: Optional[Dict[str, Any]] = None) -> PIIRedactor:
    """
    Factory function to create a configured PIIRedactor.

    Args:
        user_config: User-specific redaction configuration

    Returns:
        Configured PIIRedactor instance
    """
    # Default configuration: enable all PII/PHI patterns except IP/MAC
    default_config = {
        'enabled_patterns': [
            RedactionType.EMAIL,
            RedactionType.PHONE,
            RedactionType.SSN,
            RedactionType.CREDIT_CARD,
            RedactionType.MEDICAL_RECORD,
        ],
        'hash_redacted_values': False,
        'custom_patterns': []
    }

    # Merge with user config
    if user_config:
        default_config.update(user_config)

    return PIIRedactor(default_config)
