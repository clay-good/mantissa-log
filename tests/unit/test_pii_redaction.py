"""
Unit tests for PII/PHI redaction module.
"""

import pytest
from src.shared.redaction.pii_redactor import (
    PIIRedactor,
    RedactionType,
    create_redactor
)


class TestEmailRedaction:
    """Tests for email address redaction."""

    def test_redact_single_email(self):
        redactor = create_redactor()
        text = "Contact user@example.com for details"
        result = redactor.redact_text(text)
        assert result == "Contact [EMAIL_REDACTED] for details"

    def test_redact_multiple_emails(self):
        redactor = create_redactor()
        text = "Send to john@example.com and jane@company.org"
        result = redactor.redact_text(text)
        assert "[EMAIL_REDACTED]" in result
        assert "john@example.com" not in result
        assert "jane@company.org" not in result

    def test_email_with_plus_addressing(self):
        redactor = create_redactor()
        text = "Email: user+tag@example.com"
        result = redactor.redact_text(text)
        assert result == "Email: [EMAIL_REDACTED]"

    def test_email_with_subdomain(self):
        redactor = create_redactor()
        text = "Contact: admin@mail.company.co.uk"
        result = redactor.redact_text(text)
        assert result == "Contact: [EMAIL_REDACTED]"


class TestPhoneRedaction:
    """Tests for phone number redaction."""

    def test_redact_phone_with_dashes(self):
        redactor = create_redactor()
        text = "Call 555-123-4567"
        result = redactor.redact_text(text)
        assert result == "Call [PHONE_REDACTED]"

    def test_redact_phone_with_parentheses(self):
        redactor = create_redactor()
        text = "Phone: (555) 123-4567"
        result = redactor.redact_text(text)
        assert result == "Phone: [PHONE_REDACTED]"

    def test_redact_phone_with_plus(self):
        redactor = create_redactor()
        text = "International: +1-555-123-4567"
        result = redactor.redact_text(text)
        assert result == "International: [PHONE_REDACTED]"

    def test_redact_phone_no_separators(self):
        redactor = create_redactor()
        text = "Number: 5551234567"
        result = redactor.redact_text(text)
        assert result == "Number: [PHONE_REDACTED]"


class TestSSNRedaction:
    """Tests for Social Security Number redaction."""

    def test_redact_ssn_with_dashes(self):
        redactor = create_redactor()
        text = "SSN: 123-45-6789"
        result = redactor.redact_text(text)
        assert result == "SSN: [SSN_REDACTED]"

    def test_redact_ssn_no_dashes(self):
        redactor = create_redactor()
        text = "SSN: 123456789"
        result = redactor.redact_text(text)
        assert result == "SSN: [SSN_REDACTED]"

    def test_invalid_ssn_not_redacted(self):
        """SSNs starting with 000, 666, or 900-999 are invalid."""
        redactor = create_redactor()
        text = "Invalid: 000-12-3456 666-12-3456 999-12-3456"
        result = redactor.redact_text(text)
        # These should NOT be redacted as they're invalid SSNs
        assert "000-12-3456" in result
        assert "666-12-3456" in result


class TestCreditCardRedaction:
    """Tests for credit card number redaction."""

    def test_redact_visa(self):
        redactor = create_redactor()
        text = "Card: 4111-1111-1111-1111"
        result = redactor.redact_text(text)
        assert result == "Card: [CARD_REDACTED]"

    def test_redact_mastercard(self):
        redactor = create_redactor()
        text = "MC: 5555-5555-5555-4444"
        result = redactor.redact_text(text)
        assert result == "MC: [CARD_REDACTED]"

    def test_redact_amex(self):
        redactor = create_redactor()
        text = "Amex: 3782-822463-10005"
        result = redactor.redact_text(text)
        assert result == "Amex: [CARD_REDACTED]"

    def test_redact_card_no_dashes(self):
        redactor = create_redactor()
        text = "Card: 4111111111111111"
        result = redactor.redact_text(text)
        assert result == "Card: [CARD_REDACTED]"


class TestIPAddressRedaction:
    """Tests for IP address redaction."""

    def test_redact_ipv4(self):
        config = {'enabled_patterns': [RedactionType.IP_ADDRESS]}
        redactor = create_redactor(config)
        text = "Source IP: 192.168.1.1"
        result = redactor.redact_text(text)
        assert result == "Source IP: [IP_REDACTED]"

    def test_redact_ipv6(self):
        config = {'enabled_patterns': [RedactionType.IP_ADDRESS]}
        redactor = create_redactor(config)
        text = "IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        result = redactor.redact_text(text)
        assert result == "IPv6: [IP_REDACTED]"

    def test_ip_not_redacted_by_default(self):
        """IPs are not redacted by default to preserve security context."""
        redactor = create_redactor()
        text = "Source: 10.0.0.1"
        result = redactor.redact_text(text)
        assert result == "Source: 10.0.0.1"


class TestMedicalRecordRedaction:
    """Tests for medical record number redaction."""

    def test_redact_mrn(self):
        redactor = create_redactor()
        text = "Patient MRN: AB123456"
        result = redactor.redact_text(text)
        assert result == "Patient [MRN_REDACTED]"

    def test_redact_medical_record(self):
        redactor = create_redactor()
        text = "Medical Record: XY987654"
        result = redactor.redact_text(text)
        assert result == "Medical [MRN_REDACTED]"


class TestDictionaryRedaction:
    """Tests for dictionary redaction."""

    def test_redact_dict_all_fields(self):
        redactor = create_redactor()
        data = {
            'user': 'john@example.com',
            'phone': '555-123-4567',
            'message': 'Call me at (555) 999-8888'
        }
        result = redactor.redact_dict(data)

        assert result['user'] == '[EMAIL_REDACTED]'
        assert result['phone'] == '[PHONE_REDACTED]'
        assert '[PHONE_REDACTED]' in result['message']

    def test_redact_dict_specific_fields(self):
        redactor = create_redactor()
        data = {
            'email': 'user@example.com',
            'log_message': 'User user@example.com logged in',
            'ip': '192.168.1.1'
        }
        result = redactor.redact_dict(data, fields_to_redact=['email', 'log_message'])

        assert result['email'] == '[EMAIL_REDACTED]'
        assert '[EMAIL_REDACTED]' in result['log_message']
        assert result['ip'] == '192.168.1.1'  # Not in fields_to_redact

    def test_redact_nested_dict(self):
        redactor = create_redactor()
        data = {
            'user': {
                'email': 'john@example.com',
                'phone': '555-123-4567'
            },
            'metadata': {
                'ip': '10.0.0.1'
            }
        }
        result = redactor.redact_dict(data)

        assert result['user']['email'] == '[EMAIL_REDACTED]'
        assert result['user']['phone'] == '[PHONE_REDACTED]'

    def test_redact_dict_with_lists(self):
        redactor = create_redactor()
        data = {
            'emails': ['user1@example.com', 'user2@example.com'],
            'nested': [
                {'email': 'user3@example.com'},
                {'email': 'user4@example.com'}
            ]
        }
        result = redactor.redact_dict(data)

        assert result['emails'] == ['[EMAIL_REDACTED]', '[EMAIL_REDACTED]']
        assert result['nested'][0]['email'] == '[EMAIL_REDACTED]'
        assert result['nested'][1]['email'] == '[EMAIL_REDACTED]'


class TestIntegrationPayloadRedaction:
    """Tests for integration-specific payload redaction."""

    def test_redact_slack_payload(self):
        redactor = create_redactor()
        payload = {
            'text': 'User john@example.com triggered alert',
            'channel': '#security',
            'blocks': [
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': 'Details: SSN 123-45-6789'
                    }
                }
            ]
        }
        result = redactor.redact_integration_payload('slack', payload)

        assert '[EMAIL_REDACTED]' in result['text']
        assert '[SSN_REDACTED]' in result['blocks'][0]['text']['text']
        assert result['channel'] == '#security'  # Non-text field unchanged

    def test_redact_jira_payload(self):
        redactor = create_redactor()
        payload = {
            'fields': {
                'summary': 'Alert from user@example.com',
                'description': 'Phone: 555-123-4567, Card: 4111-1111-1111-1111',
                'project': {'key': 'SEC'}
            }
        }
        result = redactor.redact_integration_payload('jira', payload)

        assert '[EMAIL_REDACTED]' in result['fields']['summary']
        assert '[PHONE_REDACTED]' in result['fields']['description']
        assert '[CARD_REDACTED]' in result['fields']['description']
        assert result['fields']['project']['key'] == 'SEC'

    def test_redact_pagerduty_payload(self):
        redactor = create_redactor()
        payload = {
            'routing_key': 'abc123',
            'payload': {
                'summary': 'Alert: contact admin@example.com',
                'details': 'SSN: 123-45-6789'
            }
        }
        result = redactor.redact_integration_payload('pagerduty', payload)

        assert '[EMAIL_REDACTED]' in result['payload']['summary']
        assert '[SSN_REDACTED]' in result['payload']['details']

    def test_redact_webhook_payload(self):
        """Webhooks redact all fields."""
        redactor = create_redactor()
        payload = {
            'alert_type': 'security',
            'user': 'john@example.com',
            'details': {
                'phone': '555-123-4567',
                'notes': 'Call (555) 999-8888'
            }
        }
        result = redactor.redact_integration_payload('webhook', payload)

        assert result['user'] == '[EMAIL_REDACTED]'
        assert result['details']['phone'] == '[PHONE_REDACTED]'
        assert '[PHONE_REDACTED]' in result['details']['notes']


class TestCustomPatterns:
    """Tests for custom redaction patterns."""

    def test_custom_pattern(self):
        config = {
            'custom_patterns': [
                {
                    'regex': r'\bEMP-\d{6}\b',
                    'replacement': '[EMP_ID_REDACTED]',
                    'description': 'Employee ID'
                }
            ]
        }
        redactor = create_redactor(config)
        text = "Employee EMP-123456 accessed the system"
        result = redactor.redact_text(text)
        assert result == "Employee [EMP_ID_REDACTED] accessed the system"

    def test_multiple_custom_patterns(self):
        config = {
            'custom_patterns': [
                {
                    'regex': r'\bCUST-\d{8}\b',
                    'replacement': '[CUSTOMER_ID_REDACTED]'
                },
                {
                    'regex': r'\bORD-\d{10}\b',
                    'replacement': '[ORDER_ID_REDACTED]'
                }
            ]
        }
        redactor = create_redactor(config)
        text = "Customer CUST-12345678 placed order ORD-9876543210"
        result = redactor.redact_text(text)
        assert "[CUSTOMER_ID_REDACTED]" in result
        assert "[ORDER_ID_REDACTED]" in result


class TestHashedRedaction:
    """Tests for hashed redaction values."""

    def test_hashed_redaction(self):
        config = {'hash_redacted_values': True}
        redactor = create_redactor(config)
        text = "Email: user@example.com"
        result = redactor.redact_text(text)

        assert "[EMAIL_REDACTED]:" in result
        assert "user@example.com" not in result
        # Hash should be 8 characters
        assert len(result.split(':')[-1]) == 8

    def test_same_value_same_hash(self):
        """Same PII should produce same hash for correlation."""
        config = {'hash_redacted_values': True}
        redactor = create_redactor(config)

        text1 = "Email: user@example.com"
        text2 = "Contact user@example.com again"

        result1 = redactor.redact_text(text1)
        result2 = redactor.redact_text(text2)

        # Extract hashes
        hash1 = result1.split(':')[-1]
        hash2 = result2.split(':')[-1]

        assert hash1 == hash2


class TestRedactionSummary:
    """Tests for redaction summary and tracking."""

    def test_redaction_summary(self):
        redactor = create_redactor()
        text = "User john@example.com called from 555-123-4567"
        redactor.redact_text(text)

        summary = redactor.get_redaction_summary()

        assert summary['total_redactions'] == 1
        assert 'email' in summary['types_redacted']
        assert 'phone' in summary['types_redacted']

    def test_no_redaction_summary(self):
        redactor = create_redactor()
        text = "No PII in this text"
        redactor.redact_text(text)

        summary = redactor.get_redaction_summary()
        assert summary['total_redactions'] == 0

    def test_clear_log(self):
        redactor = create_redactor()
        redactor.redact_text("test@example.com")
        assert redactor.get_redaction_summary()['total_redactions'] == 1

        redactor.clear_log()
        assert redactor.get_redaction_summary()['total_redactions'] == 0


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_none_input(self):
        redactor = create_redactor()
        result = redactor.redact_text(None)
        assert result is None

    def test_empty_string(self):
        redactor = create_redactor()
        result = redactor.redact_text("")
        assert result == ""

    def test_non_string_dict_values(self):
        redactor = create_redactor()
        data = {
            'count': 123,
            'active': True,
            'value': None,
            'items': []
        }
        result = redactor.redact_dict(data)
        assert result == data  # No changes for non-string values

    def test_complex_mixed_content(self):
        redactor = create_redactor()
        text = """
        Alert Details:
        User: john.doe@example.com
        Phone: (555) 123-4567
        SSN: 123-45-6789
        Card: 4111-1111-1111-1111
        IP: 192.168.1.1 (preserved by default)
        Message: Please call (555) 999-8888 or email support@company.com
        """
        result = redactor.redact_text(text)

        assert '[EMAIL_REDACTED]' in result
        assert '[PHONE_REDACTED]' in result
        assert '[SSN_REDACTED]' in result
        assert '[CARD_REDACTED]' in result
        assert '192.168.1.1' in result  # IP not redacted by default
        assert 'john.doe@example.com' not in result
        assert '555-123-4567' not in result


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
