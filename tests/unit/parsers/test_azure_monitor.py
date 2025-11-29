"""
Unit tests for Azure Monitor Logs parser
"""

import pytest
from datetime import datetime, timezone

from src.shared.parsers.azure_monitor import AzureMonitorParser


class TestAzureMonitorParser:
    """Tests for AzureMonitorParser class"""

    @pytest.fixture
    def parser(self):
        """Create parser instance"""
        return AzureMonitorParser()

    # ==================== Activity Log Tests ====================

    def test_parse_activity_log_write_operation(self, parser):
        """Test parsing activity log write operation"""
        raw_event = {
            "eventTimestamp": "2025-01-28T10:30:00Z",
            "operationName": {
                "value": "Microsoft.Compute/virtualMachines/write",
                "localizedValue": "Create or Update Virtual Machine"
            },
            "resourceId": "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/myVM",
            "category": {
                "value": "Administrative"
            },
            "status": {
                "value": "Succeeded"
            },
            "caller": "admin@company.com",
            "callerIpAddress": "192.168.1.100",
            "correlationId": "abc-123-def-456",
            "location": "eastus",
            "claims": {
                "oid": "user-object-id",
                "upn": "admin@company.com"
            }
        }

        result = parser.parse(raw_event)

        assert result['@timestamp'] == "2025-01-28T10:30:00+00:00"
        assert result['event']['action'] == "Create or Update Virtual Machine"
        assert result['event']['provider'] == "azure"
        assert result['event']['module'] == "activity_log"
        assert result['event']['outcome'] == "success"
        assert 'configuration' in result['event']['category']
        assert result['user']['name'] == "admin@company.com"
        assert result['source']['ip'] == "192.168.1.100"
        assert result['cloud']['provider'] == "azure"
        assert result['cloud']['region'] == "eastus"
        assert result['azure']['subscription_id'] == "12345678-1234-1234-1234-123456789012"
        assert result['azure']['resource_group'] == "myResourceGroup"
        assert result['azure']['resource_type'] == "Microsoft.Compute/virtualMachines"

    def test_parse_activity_log_delete_operation(self, parser):
        """Test parsing activity log delete operation"""
        raw_event = {
            "eventTimestamp": "2025-01-28T11:00:00Z",
            "operationName": {
                "value": "Microsoft.Storage/storageAccounts/delete",
                "localizedValue": "Delete Storage Account"
            },
            "resourceId": "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/mystorageaccount",
            "category": {
                "value": "Administrative"
            },
            "status": {
                "value": "Succeeded"
            },
            "caller": "service-principal-id",
            "correlationId": "delete-corr-id"
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "Delete Storage Account"
        assert 'deletion' in result['event']['type']
        assert result['azure']['resource_name'] == "mystorageaccount"

    def test_parse_activity_log_failed_operation(self, parser):
        """Test parsing activity log failed operation"""
        raw_event = {
            "eventTimestamp": "2025-01-28T12:00:00Z",
            "operationName": {
                "value": "Microsoft.KeyVault/vaults/secrets/write"
            },
            "resourceId": "/subscriptions/sub-123/resourceGroups/rg-secure/providers/Microsoft.KeyVault/vaults/mykeyvault/secrets/mysecret",
            "category": {
                "value": "Administrative"
            },
            "status": {
                "value": "Failed"
            },
            "caller": "unauthorized@company.com",
            "subStatus": {
                "value": "Forbidden"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['outcome'] == "failure"
        assert result['azure']['sub_status'] == "Forbidden"

    def test_parse_activity_log_critical_operation(self, parser):
        """Test parsing critical operation (role assignment)"""
        raw_event = {
            "eventTimestamp": "2025-01-28T13:00:00Z",
            "operationName": {
                "value": "Microsoft.Authorization/roleAssignments/write",
                "localizedValue": "Create Role Assignment"
            },
            "resourceId": "/subscriptions/sub-123/providers/Microsoft.Authorization/roleAssignments/role-123",
            "category": {
                "value": "Administrative"
            },
            "status": {
                "value": "Succeeded"
            },
            "caller": "admin@company.com"
        }

        result = parser.parse(raw_event)

        assert result['azure']['is_critical'] is True

    # ==================== Sign-in Log Tests ====================

    def test_parse_signin_success(self, parser):
        """Test parsing successful Azure AD sign-in"""
        raw_event = {
            "createdDateTime": "2025-01-28T10:30:00Z",
            "userPrincipalName": "john.doe@company.com",
            "userDisplayName": "John Doe",
            "userId": "user-uuid-123",
            "appId": "app-uuid-456",
            "appDisplayName": "Azure Portal",
            "ipAddress": "192.168.1.100",
            "status": {
                "errorCode": "0"
            },
            "location": {
                "countryOrRegion": "US",
                "state": "California",
                "city": "San Francisco",
                "geoCoordinates": {
                    "latitude": 37.7749,
                    "longitude": -122.4194
                }
            },
            "deviceDetail": {
                "browser": "Chrome 120",
                "operatingSystem": "Windows 10",
                "deviceId": "device-123",
                "isManaged": True,
                "isCompliant": True
            },
            "conditionalAccessStatus": "success",
            "isInteractive": True,
            "riskLevelAggregated": "none",
            "correlationId": "signin-corr-id"
        }

        result = parser.parse(raw_event)

        assert result['@timestamp'] == "2025-01-28T10:30:00+00:00"
        assert result['event']['action'] == "sign-in"
        assert result['event']['outcome'] == "success"
        assert result['event']['module'] == "signin_log"
        assert 'authentication' in result['event']['category']
        assert 'start' in result['event']['type']
        assert result['user']['email'] == "john.doe@company.com"
        assert result['user']['name'] == "John Doe"
        assert result['source']['ip'] == "192.168.1.100"
        assert result['source']['geo']['country_iso_code'] == "US"
        assert result['source']['geo']['city_name'] == "San Francisco"
        assert result['user_agent']['name'] == "Chrome 120"
        assert result['azure']['signin']['app_display_name'] == "Azure Portal"
        assert result['azure']['device']['is_compliant'] is True

    def test_parse_signin_failure_invalid_password(self, parser):
        """Test parsing failed sign-in with invalid password"""
        raw_event = {
            "createdDateTime": "2025-01-28T11:00:00Z",
            "userPrincipalName": "jane.doe@company.com",
            "userId": "user-uuid-456",
            "appDisplayName": "Office 365",
            "ipAddress": "10.0.0.1",
            "status": {
                "errorCode": "50126",
                "failureReason": "Invalid username or password"
            },
            "isInteractive": True
        }

        result = parser.parse(raw_event)

        assert result['event']['outcome'] == "failure"
        assert result['event']['reason'] == "invalid_credentials"
        assert 'denied' in result['event']['type']
        assert result['azure']['status']['error_code'] == "50126"
        assert result['azure']['status']['failure_reason'] == "Invalid username or password"

    def test_parse_signin_mfa_required(self, parser):
        """Test parsing sign-in with MFA required"""
        raw_event = {
            "createdDateTime": "2025-01-28T12:00:00Z",
            "userPrincipalName": "user@company.com",
            "ipAddress": "192.168.1.50",
            "status": {
                "errorCode": "50072",
                "failureReason": "Multi-factor authentication required"
            },
            "mfaDetail": {
                "authMethod": "PhoneAppNotification"
            },
            "authenticationDetails": [
                {
                    "authenticationMethod": "Password",
                    "succeeded": True
                },
                {
                    "authenticationMethod": "PhoneAppNotification",
                    "succeeded": False
                }
            ]
        }

        result = parser.parse(raw_event)

        assert result['event']['outcome'] == "failure"
        assert result['event']['reason'] == "mfa_required"
        assert result['azure']['mfa']['auth_method'] == "PhoneAppNotification"

    def test_parse_signin_conditional_access_blocked(self, parser):
        """Test parsing sign-in blocked by conditional access"""
        raw_event = {
            "createdDateTime": "2025-01-28T13:00:00Z",
            "userPrincipalName": "contractor@external.com",
            "ipAddress": "203.0.113.50",
            "status": {
                "errorCode": "53003",
                "failureReason": "Blocked by conditional access"
            },
            "conditionalAccessStatus": "failure",
            "appliedConditionalAccessPolicies": [
                {
                    "id": "policy-123",
                    "displayName": "Block Untrusted Networks",
                    "result": "failure",
                    "enforcedGrantControls": ["Block"]
                }
            ]
        }

        result = parser.parse(raw_event)

        assert result['event']['outcome'] == "failure"
        assert result['event']['reason'] == "conditional_access_blocked"
        assert result['azure']['conditional_access']['status'] == "failure"
        assert len(result['azure']['conditional_access']['policies']) == 1
        assert result['azure']['conditional_access']['policies'][0]['display_name'] == "Block Untrusted Networks"

    def test_parse_signin_risky(self, parser):
        """Test parsing risky sign-in"""
        raw_event = {
            "createdDateTime": "2025-01-28T14:00:00Z",
            "userPrincipalName": "user@company.com",
            "ipAddress": "suspicious-ip",
            "status": {
                "errorCode": "0"
            },
            "riskLevelAggregated": "high",
            "riskState": "atRisk",
            "riskDetail": "Unusual location",
            "riskEventTypes": ["unfamiliarLocation", "suspiciousIPAddress"]
        }

        result = parser.parse(raw_event)

        assert result['event']['outcome'] == "success"
        assert result['user']['risk']['static_level'] == "high"
        assert result['user']['risk']['calculated_level'] == "high"
        assert result['azure']['risk']['state'] == "atRisk"
        assert "unfamiliarLocation" in result['azure']['risk']['event_types']

    # ==================== Audit Log Tests ====================

    def test_parse_audit_log_add_user(self, parser):
        """Test parsing Azure AD audit log - add user"""
        raw_event = {
            "activityDateTime": "2025-01-28T10:30:00Z",
            "activityDisplayName": "Add user",
            "category": "UserManagement",
            "result": "success",
            "initiatedBy": {
                "user": {
                    "userPrincipalName": "admin@company.com",
                    "displayName": "Admin User",
                    "id": "admin-uuid",
                    "ipAddress": "192.168.1.100"
                }
            },
            "targetResources": [
                {
                    "type": "User",
                    "id": "new-user-uuid",
                    "displayName": "New Employee",
                    "userPrincipalName": "new.employee@company.com"
                }
            ],
            "correlationId": "audit-corr-id"
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "Add user"
        assert result['event']['outcome'] == "success"
        assert result['event']['module'] == "audit_log"
        assert 'iam' in result['event']['category']
        assert 'creation' in result['event']['type']
        assert result['user']['email'] == "admin@company.com"
        assert result['user']['target']['name'] == "New Employee"
        assert result['azure']['initiator']['user_principal_name'] == "admin@company.com"
        assert result['azure']['target']['display_name'] == "New Employee"

    def test_parse_audit_log_delete_user(self, parser):
        """Test parsing Azure AD audit log - delete user"""
        raw_event = {
            "activityDateTime": "2025-01-28T11:00:00Z",
            "activityDisplayName": "Delete user",
            "category": "UserManagement",
            "result": "success",
            "initiatedBy": {
                "user": {
                    "userPrincipalName": "admin@company.com",
                    "displayName": "Admin"
                }
            },
            "targetResources": [
                {
                    "type": "User",
                    "id": "deleted-user-uuid",
                    "displayName": "Former Employee"
                }
            ]
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "Delete user"
        assert 'deletion' in result['event']['type']

    def test_parse_audit_log_add_member_to_role(self, parser):
        """Test parsing Azure AD audit log - add member to role"""
        raw_event = {
            "activityDateTime": "2025-01-28T12:00:00Z",
            "activityDisplayName": "Add member to role",
            "category": "RoleManagement",
            "result": "success",
            "initiatedBy": {
                "user": {
                    "userPrincipalName": "admin@company.com"
                }
            },
            "targetResources": [
                {
                    "type": "User",
                    "displayName": "Promoted User"
                },
                {
                    "type": "Role",
                    "displayName": "Global Administrator"
                }
            ],
            "modifiedProperties": [
                {
                    "displayName": "Role.DisplayName",
                    "oldValue": null,
                    "newValue": "Global Administrator"
                }
            ]
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "Add member to role"
        assert 'iam' in result['event']['category']
        assert len(result['azure']['additional_targets']) == 1
        assert result['azure']['additional_targets'][0]['display_name'] == "Global Administrator"
        assert result['azure']['modified_properties'][0]['new_value'] == "Global Administrator"

    def test_parse_audit_log_app_initiated(self, parser):
        """Test parsing audit log initiated by application"""
        raw_event = {
            "activityDateTime": "2025-01-28T13:00:00Z",
            "activityDisplayName": "Update service principal",
            "category": "ApplicationManagement",
            "result": "success",
            "initiatedBy": {
                "app": {
                    "appId": "app-uuid",
                    "displayName": "Provisioning Service"
                }
            },
            "targetResources": [
                {
                    "type": "ServicePrincipal",
                    "displayName": "Target App"
                }
            ]
        }

        result = parser.parse(raw_event)

        assert result['azure']['initiator']['type'] == "app"
        assert result['azure']['initiator']['display_name'] == "Provisioning Service"

    # ==================== Security Alert Tests ====================

    def test_parse_security_alert(self, parser):
        """Test parsing Azure Security Center alert"""
        raw_event = {
            "alertName": "Suspicious authentication activity",
            "alertType": "VM_LoginBruteForceValidCredentials",
            "description": "Analysis detected a successful login following attempts to brute force user credentials",
            "severity": "High",
            "status": "Active",
            "timeGenerated": "2025-01-28T10:30:00Z",
            "resourceId": "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/server01",
            "subscriptionId": "sub-123",
            "compromisedEntity": "server01",
            "intent": "Persistence",
            "entities": [
                {"type": "host", "hostname": "server01"},
                {"type": "ip", "address": "192.168.1.100"}
            ]
        }

        result = parser.parse(raw_event)

        assert result['event']['kind'] == "alert"
        assert result['event']['action'] == "VM_LoginBruteForceValidCredentials"
        assert result['event']['severity'] == "high"
        assert 'intrusion_detection' in result['event']['category']
        assert result['rule']['name'] == "Suspicious authentication activity"
        assert result['azure']['security_alert']['severity'] == "High"
        assert result['azure']['security_alert']['compromised_entity'] == "server01"
        assert result['azure']['security_alert']['intent'] == "Persistence"

    def test_parse_security_alert_medium_severity(self, parser):
        """Test parsing medium severity security alert"""
        raw_event = {
            "alertName": "Suspicious process executed",
            "AlertName": "Suspicious process executed",
            "alertType": "Process_Anomaly",
            "severity": "Medium",
            "status": "New",
            "timeGenerated": "2025-01-28T11:00:00Z",
            "resourceId": "/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/testvm"
        }

        result = parser.parse(raw_event)

        assert result['event']['severity'] == "medium"

    # ==================== NSG Flow Log Tests ====================

    def test_parse_nsg_flow_log_allow(self, parser):
        """Test parsing NSG flow log - allowed traffic"""
        raw_event = {
            "time": "2025-01-28T10:30:00Z",
            "resourceId": "/subscriptions/sub-123/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-web",
            "category": "NetworkSecurityGroupFlowEvent",
            "rule": "AllowHTTPS",
            "flows": [
                {
                    "mac": "00:0D:3A:00:00:01",
                    "flowTuples": [
                        "1706438400,192.168.1.100,10.0.0.5,54321,443,T,I,A,10,5000,8,4000"
                    ]
                }
            ],
            "version": 2
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "nsg_allow"
        assert result['event']['outcome'] == "success"
        assert 'network' in result['event']['category']
        assert 'allowed' in result['event']['type']
        assert result['source']['ip'] == "192.168.1.100"
        assert result['destination']['ip'] == "10.0.0.5"
        assert result['destination']['port'] == 443
        assert result['network']['transport'] == "tcp"
        assert result['network']['direction'] == "inbound"
        assert result['azure']['nsg_flow']['rule_name'] == "AllowHTTPS"

    def test_parse_nsg_flow_log_deny(self, parser):
        """Test parsing NSG flow log - denied traffic"""
        raw_event = {
            "time": "2025-01-28T11:00:00Z",
            "rule": "DenyAll",
            "flows": [
                {
                    "mac": "00:0D:3A:00:00:02",
                    "flowTuples": [
                        "1706442000,10.0.0.50,10.0.0.5,12345,22,T,I,D,5,500,0,0"
                    ]
                }
            ]
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "nsg_deny"
        assert result['event']['outcome'] == "failure"
        assert 'denied' in result['event']['type']
        assert result['destination']['port'] == 22

    def test_parse_nsg_flow_log_multiple_flows(self, parser):
        """Test parsing NSG flow log with multiple flow tuples"""
        raw_event = {
            "time": "2025-01-28T12:00:00Z",
            "rule": "AllowWeb",
            "flows": [
                {
                    "mac": "00:0D:3A:00:00:03",
                    "flowTuples": [
                        "1706445600,192.168.1.1,10.0.0.5,10000,80,T,I,A,100,50000,50,25000",
                        "1706445601,192.168.1.2,10.0.0.5,10001,80,T,I,A,50,25000,25,12500",
                        "1706445602,192.168.1.3,10.0.0.5,10002,80,T,I,A,75,37500,30,15000"
                    ]
                }
            ]
        }

        result = parser.parse(raw_event)

        assert result['azure']['nsg_flow']['flow_count'] == 3
        assert len(result['azure']['nsg_flow']['flows']) == 3
        assert result['source']['ip'] == "192.168.1.1"  # First flow

    # ==================== Resource Log Tests ====================

    def test_parse_resource_log(self, parser):
        """Test parsing Azure resource diagnostic log"""
        raw_event = {
            "time": "2025-01-28T10:30:00Z",
            "resourceId": "/subscriptions/sub-123/resourceGroups/rg-app/providers/Microsoft.Web/sites/mywebapp",
            "category": "AppServiceHTTPLogs",
            "operationName": "Microsoft.Web/sites/log",
            "resultType": "Success",
            "durationMs": 150,
            "callerIpAddress": "192.168.1.100",
            "correlationId": "resource-corr-id",
            "level": "Information",
            "properties": {
                "CsHost": "mywebapp.azurewebsites.net",
                "CsMethod": "GET",
                "CsUri": "/api/health"
            }
        }

        result = parser.parse(raw_event)

        assert result['event']['action'] == "Microsoft.Web/sites/log"
        assert result['event']['outcome'] == "success"
        assert result['event']['module'] == "resource_log"
        assert result['cloud']['provider'] == "azure"
        assert result['azure']['resource_log']['resource_type'] == "Microsoft.Web/sites"
        assert result['azure']['resource_log']['resource_name'] == "mywebapp"
        assert result['azure']['resource_log']['duration_ms'] == 150

    # ==================== Generic Event Tests ====================

    def test_parse_generic_event(self, parser):
        """Test parsing unknown/generic Azure event"""
        raw_event = {
            "time": "2025-01-28T10:30:00Z",
            "someCustomField": "value",
            "anotherField": 123
        }

        result = parser.parse(raw_event)

        assert result['event']['module'] == "generic"
        assert result['event']['outcome'] == "unknown"
        assert result['azure']['event_data'] == raw_event

    # ==================== Validation Tests ====================

    def test_validate_activity_log(self, parser):
        """Test validation of activity log event"""
        event = {
            "operationName": "Microsoft.Compute/virtualMachines/write",
            "resourceId": "/subscriptions/sub-123/..."
        }
        assert parser.validate(event) is True

    def test_validate_signin_log(self, parser):
        """Test validation of sign-in log event"""
        event = {
            "userPrincipalName": "user@company.com",
            "status": {"errorCode": "0"}
        }
        assert parser.validate(event) is True

    def test_validate_audit_log(self, parser):
        """Test validation of audit log event"""
        event = {
            "activityDisplayName": "Add user"
        }
        assert parser.validate(event) is True

    def test_validate_security_alert(self, parser):
        """Test validation of security alert"""
        event = {
            "alertName": "Suspicious activity"
        }
        assert parser.validate(event) is True

    def test_validate_nsg_flow_log(self, parser):
        """Test validation of NSG flow log"""
        event = {
            "rule": "AllowHTTPS",
            "flows": []
        }
        assert parser.validate(event) is True

    def test_validate_resource_log(self, parser):
        """Test validation of resource log"""
        event = {
            "resourceId": "/subscriptions/...",
            "properties": {}
        }
        assert parser.validate(event) is True

    def test_validate_invalid_event(self, parser):
        """Test validation of invalid event"""
        event = {
            "randomField": "value"
        }
        assert parser.validate(event) is False

    def test_validate_event_with_timestamp_only(self, parser):
        """Test validation with timestamp only"""
        event = {
            "time": "2025-01-28T10:30:00Z"
        }
        assert parser.validate(event) is True

    # ==================== Timestamp Tests ====================

    def test_parse_iso_timestamp(self, parser):
        """Test parsing ISO 8601 timestamp"""
        raw_event = {
            "time": "2025-01-28T10:30:00.123Z",
            "operationName": "test",
            "resourceId": "/test"
        }
        result = parser.parse(raw_event)
        assert "2025-01-28" in result['@timestamp']

    def test_parse_timestamp_with_offset(self, parser):
        """Test parsing timestamp with timezone offset"""
        raw_event = {
            "time": "2025-01-28T10:30:00+00:00",
            "operationName": "test",
            "resourceId": "/test"
        }
        result = parser.parse(raw_event)
        assert "2025-01-28" in result['@timestamp']

    def test_parse_empty_timestamp(self, parser):
        """Test parsing event with empty timestamp"""
        raw_event = {
            "time": "",
            "operationName": "test",
            "resourceId": "/test"
        }
        result = parser.parse(raw_event)
        assert '@timestamp' in result

    # ==================== Edge Cases ====================

    def test_parse_event_with_nested_status(self, parser):
        """Test parsing event with nested status object"""
        raw_event = {
            "eventTimestamp": "2025-01-28T10:30:00Z",
            "operationName": {
                "value": "test/action"
            },
            "resourceId": "/subscriptions/sub-123/...",
            "category": {
                "value": "Administrative"
            },
            "status": {
                "value": "Succeeded",
                "localizedValue": "Succeeded"
            }
        }
        result = parser.parse(raw_event)
        assert result['azure']['status'] == "Succeeded"

    def test_parse_event_with_string_status(self, parser):
        """Test parsing event with string status"""
        raw_event = {
            "eventTimestamp": "2025-01-28T10:30:00Z",
            "operationName": "test",
            "resourceId": "/subscriptions/sub-123/...",
            "category": {
                "value": "Administrative"
            },
            "status": "Succeeded"
        }
        result = parser.parse(raw_event)
        assert result['azure']['status'] == "Succeeded"

    def test_extract_subscription_id(self, parser):
        """Test extracting subscription ID from resource ID"""
        resource_id = "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/myRG/providers/Microsoft.Compute/virtualMachines/myVM"
        assert parser._extract_subscription_id(resource_id) == "12345678-1234-1234-1234-123456789012"

    def test_extract_resource_group(self, parser):
        """Test extracting resource group from resource ID"""
        resource_id = "/subscriptions/sub-123/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/myVM"
        assert parser._extract_resource_group(resource_id) == "myResourceGroup"

    def test_extract_resource_type(self, parser):
        """Test extracting resource type from resource ID"""
        resource_id = "/subscriptions/sub-123/resourceGroups/myRG/providers/Microsoft.Compute/virtualMachines/myVM"
        assert parser._extract_resource_type(resource_id) == "Microsoft.Compute/virtualMachines"

    def test_extract_domain_from_email(self, parser):
        """Test extracting domain from email"""
        assert parser._extract_domain_from_email("user@company.com") == "company.com"
        assert parser._extract_domain_from_email("user") is None
        assert parser._extract_domain_from_email("") is None

    def test_parse_signin_log_non_interactive(self, parser):
        """Test parsing non-interactive sign-in"""
        raw_event = {
            "createdDateTime": "2025-01-28T10:30:00Z",
            "userPrincipalName": "service@company.com",
            "status": {"errorCode": "0"},
            "isInteractive": False,
            "clientAppUsed": "Exchange ActiveSync"
        }
        result = parser.parse(raw_event)
        assert result['azure']['signin']['is_interactive'] is False
        assert result['azure']['signin']['client_app_used'] == "Exchange ActiveSync"

    def test_related_fields_population(self, parser):
        """Test that related fields are properly populated"""
        raw_event = {
            "createdDateTime": "2025-01-28T10:30:00Z",
            "userPrincipalName": "user@company.com",
            "userDisplayName": "Test User",
            "ipAddress": "192.168.1.100",
            "status": {"errorCode": "0"}
        }
        result = parser.parse(raw_event)
        assert "192.168.1.100" in result['related']['ip']
        assert "user@company.com" in result['related']['user']
        assert "Test User" in result['related']['user']
