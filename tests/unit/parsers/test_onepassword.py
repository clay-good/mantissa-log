"""
Unit tests for 1Password Events API parser
"""

import pytest
from datetime import datetime, timezone

from src.shared.parsers.onepassword import OnePasswordParser


class TestOnePasswordParser:
    """Tests for OnePasswordParser class"""

    @pytest.fixture
    def parser(self):
        """Create parser instance"""
        return OnePasswordParser()

    # ==================== Sign-in Event Tests ====================

    def test_parse_signin_success(self, parser):
        """Test parsing successful sign-in event"""
        raw_event = {
            "uuid": "ABC123",
            "timestamp": "2025-01-28T10:30:00Z",
            "action": "signin",
            "actor": {
                "uuid": "user-uuid-123",
                "email": "john.doe@company.com",
                "name": "John Doe",
                "type": "user"
            },
            "session": {
                "uuid": "session-uuid-456",
                "device_uuid": "device-uuid-789"
            },
            "client": {
                "app_name": "1Password for Mac",
                "app_version": "8.10.0",
                "platform": "macOS",
                "os_version": "14.2.1"
            },
            "location": {
                "ip": "192.168.1.100",
                "country": "US",
                "region": "California",
                "city": "San Francisco"
            }
        }

        result = parser.parse(raw_event)

        assert result['@timestamp'] == "2025-01-28T10:30:00+00:00"
        assert result['event']['action'] == "signin"
        assert result['event']['provider'] == "1password"
        assert result['event']['module'] == "authentication"
        assert 'authentication' in result['event']['category']
        assert 'start' in result['event']['type']
        assert result['user']['email'] == "john.doe@company.com"
        assert result['source']['ip'] == "192.168.1.100"
        assert result['source']['geo']['country_iso_code'] == "US"
        assert result['user_agent']['name'] == "1Password for Mac"
        assert result['onepassword']['actor']['email'] == "john.doe@company.com"

    def test_parse_signin_failure(self, parser):
        """Test parsing failed sign-in event"""
        raw_event = {
            "uuid": "DEF456",
            "timestamp": "2025-01-28T11:00:00Z",
            "action": "signin",
            "outcome": "failure",
            "actor": {
                "email": "attacker@evil.com"
            },
            "location": {
                "ip": "10.0.0.1",
                "country": "CN"
            },
            "error": "Invalid credentials"
        }

        result = parser.parse(raw_event)

        assert result['event']['outcome'] == "failure"
        assert result['source']['ip'] == "10.0.0.1"

    def test_parse_mfa_verify(self, parser):
        """Test parsing MFA verification event"""
        raw_event = {
            "uuid": "GHI789",
            "timestamp": "2025-01-28T10:31:00Z",
            "action": "mfa_verify",
            "actor": {
                "uuid": "user-uuid-123",
                "email": "john.doe@company.com"
            },
            "session": {
                "uuid": "session-uuid-456"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "mfa_verify"
        assert result['event']['module'] == "authentication"
        assert 'authentication' in result['event']['category']

    def test_parse_sso_signin(self, parser):
        """Test parsing SSO sign-in event"""
        raw_event = {
            "uuid": "JKL012",
            "timestamp": "2025-01-28T12:00:00Z",
            "action": "sso_signin",
            "actor": {
                "email": "employee@company.com"
            },
            "location": {
                "ip": "203.0.113.50"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "sso_signin"
        assert 'authentication' in result['event']['category']

    # ==================== Vault Event Tests ====================

    def test_parse_vault_create(self, parser):
        """Test parsing vault creation event"""
        raw_event = {
            "uuid": "MNO345",
            "timestamp": "2025-01-28T14:00:00Z",
            "action": "vault_create",
            "actor": {
                "uuid": "admin-uuid",
                "email": "admin@company.com",
                "name": "Admin User"
            },
            "target": {
                "type": "vault",
                "uuid": "vault-uuid-new",
                "name": "Engineering Secrets"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "vault_create"
        assert 'configuration' in result['event']['category']
        assert 'creation' in result['event']['type']
        assert result['onepassword']['target']['name'] == "Engineering Secrets"

    def test_parse_vault_share(self, parser):
        """Test parsing vault sharing event"""
        raw_event = {
            "uuid": "PQR678",
            "timestamp": "2025-01-28T14:30:00Z",
            "action": "vault_share",
            "actor": {
                "email": "owner@company.com"
            },
            "vault": {
                "uuid": "vault-uuid",
                "name": "Shared Vault"
            },
            "target": {
                "type": "user",
                "uuid": "target-user-uuid",
                "name": "New Team Member"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "vault_share"
        assert 'allowed' in result['event']['type']
        assert result['onepassword']['is_sharing'] is True
        assert result['onepassword']['vault']['name'] == "Shared Vault"

    def test_parse_vault_delete(self, parser):
        """Test parsing vault deletion event"""
        raw_event = {
            "uuid": "STU901",
            "timestamp": "2025-01-28T15:00:00Z",
            "action": "vault_delete",
            "actor": {
                "email": "admin@company.com"
            },
            "target": {
                "type": "vault",
                "uuid": "deleted-vault-uuid",
                "name": "Old Projects"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "vault_delete"
        assert 'deletion' in result['event']['type']
        assert result['onepassword']['is_sensitive'] is True

    # ==================== Item Event Tests ====================

    def test_parse_item_access(self, parser):
        """Test parsing item access event"""
        raw_event = {
            "uuid": "VWX234",
            "timestamp": "2025-01-28T09:00:00Z",
            "action": "item_access",
            "actor": {
                "uuid": "user-uuid",
                "email": "developer@company.com"
            },
            "vault": {
                "uuid": "vault-uuid",
                "name": "Development"
            },
            "item": {
                "uuid": "item-uuid",
                "title": "AWS Production Credentials",
                "category": "Login"
            },
            "client": {
                "app_name": "1Password CLI",
                "app_version": "2.18.0",
                "platform": "Linux"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "item_access"
        assert 'database' in result['event']['category']
        assert 'access' in result['event']['type']
        assert result['onepassword']['item']['title'] == "AWS Production Credentials"
        assert result['onepassword']['item']['category'] == "Login"
        assert result['onepassword']['vault']['name'] == "Development"

    def test_parse_password_reveal(self, parser):
        """Test parsing password reveal event (sensitive)"""
        raw_event = {
            "uuid": "YZA567",
            "timestamp": "2025-01-28T10:00:00Z",
            "action": "password_reveal",
            "actor": {
                "email": "user@company.com"
            },
            "item": {
                "uuid": "item-uuid",
                "title": "Database Root Password"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "password_reveal"
        assert result['onepassword']['is_sensitive'] is True
        assert 'access' in result['event']['type']

    def test_parse_item_export(self, parser):
        """Test parsing item export event (sensitive)"""
        raw_event = {
            "uuid": "BCD890",
            "timestamp": "2025-01-28T16:00:00Z",
            "action": "item_export",
            "actor": {
                "email": "user@company.com"
            },
            "vault": {
                "uuid": "vault-uuid",
                "name": "Personal"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "item_export"
        assert result['onepassword']['is_sensitive'] is True

    def test_parse_credential_autofill(self, parser):
        """Test parsing credential autofill event"""
        raw_event = {
            "uuid": "EFG123",
            "timestamp": "2025-01-28T11:30:00Z",
            "action": "credential_autofill",
            "actor": {
                "email": "user@company.com"
            },
            "item": {
                "uuid": "login-item-uuid",
                "title": "GitHub",
                "category": "Login"
            },
            "client": {
                "app_name": "1Password Browser Extension",
                "platform": "Chrome"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "credential_autofill"
        assert result['event']['module'] == "item"

    # ==================== User Management Event Tests ====================

    def test_parse_user_create(self, parser):
        """Test parsing user creation event"""
        raw_event = {
            "uuid": "HIJ456",
            "timestamp": "2025-01-28T09:00:00Z",
            "action": "user_create",
            "actor": {
                "email": "admin@company.com",
                "name": "Admin"
            },
            "target": {
                "type": "user",
                "uuid": "new-user-uuid",
                "name": "New Employee"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "user_create"
        assert 'iam' in result['event']['category']
        assert 'creation' in result['event']['type']
        assert result['user']['target']['name'] == "New Employee"

    def test_parse_user_suspend(self, parser):
        """Test parsing user suspension event"""
        raw_event = {
            "uuid": "KLM789",
            "timestamp": "2025-01-28T17:00:00Z",
            "action": "user_suspend",
            "actor": {
                "email": "admin@company.com"
            },
            "target": {
                "type": "user",
                "uuid": "suspended-user-uuid",
                "name": "Departed Employee"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "user_suspend"
        assert 'deletion' in result['event']['type']

    def test_parse_user_invite(self, parser):
        """Test parsing user invite event"""
        raw_event = {
            "uuid": "NOP012",
            "timestamp": "2025-01-28T08:00:00Z",
            "action": "user_invite",
            "actor": {
                "email": "hr@company.com"
            },
            "target": {
                "type": "user",
                "name": "new.hire@company.com"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "user_invite"
        assert 'creation' in result['event']['type']

    # ==================== Group Event Tests ====================

    def test_parse_group_member_add(self, parser):
        """Test parsing group member addition"""
        raw_event = {
            "uuid": "QRS345",
            "timestamp": "2025-01-28T13:00:00Z",
            "action": "group_member_add",
            "actor": {
                "email": "admin@company.com"
            },
            "target": {
                "type": "group",
                "name": "Engineering Team"
            },
            "aux_info": {
                "member_email": "developer@company.com"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "group_member_add"
        assert 'iam' in result['event']['category']

    def test_parse_group_grant_access(self, parser):
        """Test parsing group vault access grant"""
        raw_event = {
            "uuid": "TUV678",
            "timestamp": "2025-01-28T13:30:00Z",
            "action": "group_grant_access",
            "actor": {
                "email": "admin@company.com"
            },
            "target": {
                "type": "group",
                "name": "DevOps Team"
            },
            "vault": {
                "uuid": "vault-uuid",
                "name": "Production Secrets"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "group_grant_access"
        assert result['onepassword']['is_sharing'] is True

    # ==================== Service Account Event Tests ====================

    def test_parse_service_account_create(self, parser):
        """Test parsing service account creation"""
        raw_event = {
            "uuid": "WXY901",
            "timestamp": "2025-01-28T10:00:00Z",
            "action": "service_account_create",
            "actor": {
                "email": "admin@company.com"
            },
            "target": {
                "type": "service_account",
                "uuid": "sa-uuid",
                "name": "CI/CD Pipeline"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "service_account_create"
        assert result['event']['module'] == "service_account"

    def test_parse_service_account_token_create(self, parser):
        """Test parsing service account token creation (sensitive)"""
        raw_event = {
            "uuid": "ZAB234",
            "timestamp": "2025-01-28T10:15:00Z",
            "action": "service_account_token_create",
            "actor": {
                "email": "admin@company.com"
            },
            "target": {
                "type": "service_account",
                "name": "CI/CD Pipeline"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "service_account_token_create"
        assert result['onepassword']['is_sensitive'] is True

    # ==================== Admin/Settings Event Tests ====================

    def test_parse_settings_update(self, parser):
        """Test parsing settings update event (sensitive)"""
        raw_event = {
            "uuid": "CDE567",
            "timestamp": "2025-01-28T14:00:00Z",
            "action": "settings_update",
            "actor": {
                "email": "admin@company.com"
            },
            "aux_info": {
                "setting": "master_password_policy",
                "old_value": "standard",
                "new_value": "strict"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "settings_update"
        assert result['event']['module'] == "admin"
        assert result['onepassword']['is_sensitive'] is True

    def test_parse_policy_create(self, parser):
        """Test parsing policy creation event"""
        raw_event = {
            "uuid": "FGH890",
            "timestamp": "2025-01-28T15:00:00Z",
            "action": "policy_create",
            "actor": {
                "email": "admin@company.com"
            },
            "target": {
                "type": "policy",
                "name": "Require MFA"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "policy_create"
        assert 'configuration' in result['event']['category']

    # ==================== Security Event Tests ====================

    def test_parse_security_alert(self, parser):
        """Test parsing security alert event"""
        raw_event = {
            "uuid": "IJK123",
            "timestamp": "2025-01-28T16:00:00Z",
            "action": "security_alert",
            "actor": {
                "email": "user@company.com"
            },
            "aux_info": {
                "alert_type": "compromised_password",
                "item_uuid": "item-uuid"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "security_alert"
        assert 'intrusion_detection' in result['event']['category']
        assert result['event']['module'] == "security"

    def test_parse_watchtower_alert(self, parser):
        """Test parsing Watchtower alert event"""
        raw_event = {
            "uuid": "LMN456",
            "timestamp": "2025-01-28T17:00:00Z",
            "action": "watchtower_alert",
            "aux_info": {
                "alert_type": "weak_password",
                "affected_items": 5
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "watchtower_alert"
        assert result['event']['module'] == "security"

    def test_parse_breach_report_view(self, parser):
        """Test parsing breach report view (sensitive)"""
        raw_event = {
            "uuid": "OPQ789",
            "timestamp": "2025-01-28T18:00:00Z",
            "action": "breach_report_view",
            "actor": {
                "email": "security@company.com"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "breach_report_view"
        assert result['onepassword']['is_sensitive'] is True

    # ==================== SCIM Event Tests ====================

    def test_parse_scim_provision(self, parser):
        """Test parsing SCIM provisioning event"""
        raw_event = {
            "uuid": "RST012",
            "timestamp": "2025-01-28T08:00:00Z",
            "action": "scim_provision",
            "target": {
                "type": "user",
                "email": "new.employee@company.com"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "scim_provision"
        assert result['event']['module'] == "scim"
        assert 'iam' in result['event']['category']

    # ==================== Legacy Format Tests ====================

    def test_parse_legacy_event(self, parser):
        """Test parsing legacy event format"""
        raw_event = {
            "event_type": "sign_in",
            "timestamp": "2025-01-28T10:00:00Z",
            "user_email": "user@company.com",
            "user_uuid": "user-uuid",
            "ip_address": "192.168.1.1"
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "signin"
        assert result['event']['module'] == "legacy"
        assert result['user']['email'] == "user@company.com"
        assert result['source']['ip'] == "192.168.1.1"

    # ==================== Validation Tests ====================

    def test_validate_events_api_format(self, parser):
        """Test validation of Events API format"""
        valid_event = {"action": "signin", "timestamp": "2025-01-28T10:00:00Z"}
        assert parser.validate(valid_event) is True

    def test_validate_legacy_format(self, parser):
        """Test validation of legacy format"""
        valid_event = {"event_type": "sign_in"}
        assert parser.validate(valid_event) is True

    def test_validate_minimal_event(self, parser):
        """Test validation with only timestamp"""
        valid_event = {"timestamp": "2025-01-28T10:00:00Z"}
        assert parser.validate(valid_event) is True

    def test_validate_invalid_event(self, parser):
        """Test validation of invalid event"""
        invalid_event = {"random": "data"}
        assert parser.validate(invalid_event) is False

    # ==================== Related Fields Tests ====================

    def test_related_fields_populated(self, parser):
        """Test that related fields are properly populated"""
        raw_event = {
            "action": "signin",
            "timestamp": "2025-01-28T10:00:00Z",
            "actor": {
                "uuid": "user-uuid",
                "email": "user@company.com",
                "name": "Test User"
            },
            "location": {
                "ip": "192.168.1.100"
            }
        }

        result = parser.parse(raw_event)

        assert "192.168.1.100" in result['related']['ip']
        assert "user@company.com" in result['related']['user']
        assert "Test User" in result['related']['user']

    # ==================== Message Building Tests ====================

    def test_message_building(self, parser):
        """Test human-readable message construction"""
        raw_event = {
            "action": "vault_create",
            "timestamp": "2025-01-28T10:00:00Z",
            "actor": {
                "email": "admin@company.com"
            },
            "target": {
                "type": "vault",
                "name": "New Vault"
            }
        }

        result = parser.parse(raw_event)

        assert "admin@company.com" in result['message']
        assert "vault create" in result['message']
        assert "New Vault" in result['message']

    # ==================== Timestamp Parsing Tests ====================

    def test_parse_iso_timestamp(self, parser):
        """Test parsing ISO 8601 timestamp"""
        raw_event = {
            "action": "signin",
            "timestamp": "2025-01-28T10:30:00.123Z"
        }

        result = parser.parse(raw_event)
        assert "2025-01-28" in result['@timestamp']

    def test_parse_unix_timestamp(self, parser):
        """Test parsing Unix timestamp"""
        raw_event = {
            "action": "signin",
            "timestamp": "1706437800"
        }

        result = parser.parse(raw_event)
        assert "@timestamp" in result

    # ==================== Edge Cases ====================

    def test_empty_actor(self, parser):
        """Test handling of missing actor"""
        raw_event = {
            "action": "item_access",
            "timestamp": "2025-01-28T10:00:00Z",
            "item": {
                "uuid": "item-uuid",
                "title": "Test Item"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "item_access"
        # Should not crash, user fields may be empty

    def test_none_values_removed(self, parser):
        """Test that None values are removed from output"""
        raw_event = {
            "action": "signin",
            "timestamp": "2025-01-28T10:00:00Z"
        }

        result = parser.parse(raw_event)

        # Recursively check for None values
        def check_no_none(d):
            if isinstance(d, dict):
                for v in d.values():
                    assert v is not None
                    check_no_none(v)
            elif isinstance(d, list):
                for item in d:
                    assert item is not None
                    check_no_none(item)

        check_no_none(result)

    def test_outcome_from_deny_action(self, parser):
        """Test outcome determination from deny action"""
        raw_event = {
            "action": "firewall_deny",
            "timestamp": "2025-01-28T10:00:00Z",
            "location": {
                "ip": "10.0.0.1"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['outcome'] == "failure"

    def test_generic_event_parsing(self, parser):
        """Test parsing of unknown/generic event"""
        raw_event = {
            "created_at": "2025-01-28T10:00:00Z",
            "custom_field": "value"
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "unknown"
        assert result['event']['module'] == "generic"
