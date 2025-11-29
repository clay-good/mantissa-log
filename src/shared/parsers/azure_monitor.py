"""
Azure Monitor Logs Parser with ECS Normalization

Normalizes Azure Monitor logs to Elastic Common Schema (ECS) format for
unified detection and analysis.

Supports Azure Monitor log types including:
- Activity Logs (Azure Resource Manager operations)
- Azure AD Sign-in Logs (authentication events)
- Azure AD Audit Logs (directory changes)
- Azure AD Risky Sign-ins
- Azure AD Identity Protection
- Azure Resource Logs (diagnostic logs)
- Azure Security Center Alerts
- Azure Key Vault Access Logs
- Azure Storage Logs
- Azure Network Security Group (NSG) Flow Logs

Reference:
- https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema
- https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-azure-monitor-sign-ins-log-schema
- https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-azure-monitor-audit-log-schema
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import re


class BaseParser:
    """Base parser class for ECS normalization"""

    def __init__(self):
        self.source_type = "generic"


class AzureMonitorParser(BaseParser):
    """Parser for Azure Monitor logs with ECS normalization"""

    # Azure operation to ECS category mapping
    OPERATION_CATEGORY_MAP = {
        # Activity Log - Resource operations
        'write': ['configuration'],
        'delete': ['configuration'],
        'action': ['configuration'],
        'read': ['database'],

        # Authentication
        'signin': ['authentication'],
        'signout': ['authentication'],
        'authenticate': ['authentication'],
        'authorize': ['authentication'],

        # IAM/Directory
        'add user': ['iam'],
        'delete user': ['iam'],
        'update user': ['iam'],
        'add member': ['iam'],
        'remove member': ['iam'],
        'add group': ['iam'],
        'delete group': ['iam'],
        'add role': ['iam'],
        'remove role': ['iam'],
        'add application': ['iam'],
        'delete application': ['iam'],
        'consent': ['iam'],

        # Security
        'security': ['intrusion_detection'],
        'alert': ['intrusion_detection'],
        'threat': ['intrusion_detection'],

        # Network
        'network': ['network'],
        'firewall': ['network'],
        'nsg': ['network'],
        'allow': ['network'],
        'deny': ['network'],
    }

    # Critical Azure operations requiring monitoring
    CRITICAL_OPERATIONS = {
        # Subscription/Management Group level
        'microsoft.authorization/roleassignments/write',
        'microsoft.authorization/roledefinitions/write',
        'microsoft.authorization/policyassignments/write',
        'microsoft.authorization/policydefinitions/write',

        # Key Vault
        'microsoft.keyvault/vaults/write',
        'microsoft.keyvault/vaults/delete',
        'microsoft.keyvault/vaults/secrets/write',
        'microsoft.keyvault/vaults/keys/write',
        'microsoft.keyvault/vaults/accesspolicies/write',

        # Storage
        'microsoft.storage/storageaccounts/write',
        'microsoft.storage/storageaccounts/delete',
        'microsoft.storage/storageaccounts/listkeys/action',

        # Compute
        'microsoft.compute/virtualmachines/write',
        'microsoft.compute/virtualmachines/delete',
        'microsoft.compute/virtualmachines/runcommand/action',

        # Network
        'microsoft.network/networksecuritygroups/write',
        'microsoft.network/networksecuritygroups/delete',
        'microsoft.network/networksecuritygroups/securityrules/write',
        'microsoft.network/virtualnetworks/write',
        'microsoft.network/virtualnetworks/delete',
        'microsoft.network/publicipaddresses/write',

        # SQL
        'microsoft.sql/servers/firewallrules/write',
        'microsoft.sql/servers/write',
        'microsoft.sql/servers/delete',

        # Container
        'microsoft.containerregistry/registries/write',
        'microsoft.kubernetes/connectedclusters/write',
    }

    # Risk levels for Azure AD Identity Protection
    RISK_LEVEL_SEVERITY = {
        'none': 'low',
        'low': 'low',
        'medium': 'medium',
        'high': 'high',
        'hidden': 'medium',
    }

    # Azure AD Sign-in error codes
    SIGNIN_ERROR_CODES = {
        '0': 'success',
        '50126': 'invalid_credentials',
        '50053': 'account_locked',
        '50055': 'password_expired',
        '50057': 'account_disabled',
        '50058': 'silent_signin_failed',
        '50072': 'mfa_required',
        '50074': 'strong_auth_required',
        '50076': 'mfa_required_other_device',
        '50079': 'mfa_registration_required',
        '50105': 'missing_required_claim',
        '50131': 'device_not_compliant',
        '53003': 'conditional_access_blocked',
        '530032': 'security_policy_blocked',
        '700016': 'application_not_found',
    }

    def __init__(self):
        super().__init__()
        self.source_type = "azure_monitor"

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Azure Monitor event and normalize to ECS.

        Args:
            raw_event: Raw Azure Monitor event

        Returns:
            Normalized event in ECS format
        """
        # Detect event type and route to appropriate parser
        if self._is_activity_log(raw_event):
            return self._parse_activity_log(raw_event)
        elif self._is_signin_log(raw_event):
            return self._parse_signin_log(raw_event)
        elif self._is_audit_log(raw_event):
            return self._parse_audit_log(raw_event)
        elif self._is_security_alert(raw_event):
            return self._parse_security_alert(raw_event)
        elif self._is_nsg_flow_log(raw_event):
            return self._parse_nsg_flow_log(raw_event)
        elif self._is_resource_log(raw_event):
            return self._parse_resource_log(raw_event)
        else:
            return self._parse_generic_event(raw_event)

    def _is_activity_log(self, event: Dict[str, Any]) -> bool:
        """Check if event is Azure Activity Log"""
        return (
            'operationName' in event and
            ('resourceId' in event or 'resourceUri' in event) and
            'category' in event and event.get('category', {}).get('value') in (
                'Administrative', 'ServiceHealth', 'ResourceHealth',
                'Alert', 'Autoscale', 'Security', 'Recommendation', 'Policy'
            )
        )

    def _is_signin_log(self, event: Dict[str, Any]) -> bool:
        """Check if event is Azure AD Sign-in Log"""
        return (
            ('signInActivity' in event or 'signInEventTypes' in event) or
            (event.get('category') == 'SignInLogs') or
            (event.get('operationName', '').lower() == 'sign-in activity') or
            ('correlationId' in event and 'userPrincipalName' in event and 'status' in event)
        )

    def _is_audit_log(self, event: Dict[str, Any]) -> bool:
        """Check if event is Azure AD Audit Log"""
        return (
            event.get('category') == 'AuditLogs' or
            ('activityDisplayName' in event and 'targetResources' in event) or
            (event.get('operationName', '').lower() in ('add user', 'delete user', 'update user'))
        )

    def _is_security_alert(self, event: Dict[str, Any]) -> bool:
        """Check if event is Security Center Alert"""
        return (
            'alertName' in event or
            event.get('category') == 'Security' or
            'securityAlert' in event or
            (event.get('operationType') == 'SecurityAlert')
        )

    def _is_nsg_flow_log(self, event: Dict[str, Any]) -> bool:
        """Check if event is NSG Flow Log"""
        return (
            'flows' in event or
            event.get('category') == 'NetworkSecurityGroupFlowEvent' or
            ('rule' in event and 'flowTuples' in event.get('flows', [{}])[0])
        )

    def _is_resource_log(self, event: Dict[str, Any]) -> bool:
        """Check if event is Azure Resource/Diagnostic Log"""
        return (
            'resourceId' in event and
            'properties' in event and
            event.get('category') not in ('SignInLogs', 'AuditLogs', 'Security')
        )

    def _parse_activity_log(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Azure Activity Log"""
        operation_name = raw_event.get('operationName', {})
        if isinstance(operation_name, dict):
            operation = operation_name.get('localizedValue', operation_name.get('value', ''))
        else:
            operation = str(operation_name)

        # Extract resource info
        resource_id = raw_event.get('resourceId', raw_event.get('resourceUri', ''))
        resource_group = self._extract_resource_group(resource_id)
        resource_type = self._extract_resource_type(resource_id)
        resource_name = self._extract_resource_name(resource_id)
        subscription_id = self._extract_subscription_id(resource_id)

        # Extract caller info
        caller = raw_event.get('caller', '')
        claims = raw_event.get('claims', {})
        caller_ip = raw_event.get('callerIpAddress', claims.get('ipaddr', ''))

        # Determine status
        status = raw_event.get('status', {})
        if isinstance(status, dict):
            status_value = status.get('value', status.get('localizedValue', ''))
        else:
            status_value = str(status)

        # Determine outcome
        outcome = self._determine_activity_outcome(status_value, raw_event)

        # Determine category
        category_obj = raw_event.get('category', {})
        if isinstance(category_obj, dict):
            category = category_obj.get('value', '')
        else:
            category = str(category_obj)

        # Get operation category for ECS
        ecs_categories = self._get_operation_category(operation)

        # Check if critical operation
        operation_lower = operation.lower()
        is_critical = any(
            critical_op in operation_lower
            for critical_op in self.CRITICAL_OPERATIONS
        )

        # Build normalized event
        normalized = {
            '@timestamp': self._parse_timestamp(raw_event.get('eventTimestamp', raw_event.get('time', ''))),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ecs_categories,
                'type': self._get_event_type_from_operation(operation),
                'action': operation,
                'outcome': outcome,
                'provider': 'azure',
                'module': 'activity_log',
                'id': raw_event.get('correlationId', raw_event.get('operationId', ''))
            },

            'message': self._build_activity_message(operation, caller, resource_name, resource_type),

            'user': {
                'name': caller,
                'id': claims.get('oid', claims.get('objectidentifier', '')),
                'email': claims.get('upn', claims.get('unique_name', '')),
                'domain': self._extract_domain_from_email(claims.get('upn', caller))
            } if caller else None,

            'source': {
                'ip': caller_ip
            } if caller_ip else None,

            'cloud': {
                'provider': 'azure',
                'account': {
                    'id': subscription_id
                },
                'region': raw_event.get('location', ''),
                'service': {
                    'name': resource_type
                }
            },

            'related': self._build_related_activity(caller, caller_ip, resource_name),

            'azure': {
                'subscription_id': subscription_id,
                'resource_group': resource_group,
                'resource_id': resource_id,
                'resource_type': resource_type,
                'resource_name': resource_name,
                'operation_name': operation,
                'category': category,
                'correlation_id': raw_event.get('correlationId', ''),
                'operation_id': raw_event.get('operationId', ''),
                'level': raw_event.get('level', ''),
                'status': status_value,
                'sub_status': self._get_sub_status(raw_event),
                'is_critical': is_critical,
                'caller': caller,
                'claims': {
                    'object_id': claims.get('oid', ''),
                    'upn': claims.get('upn', ''),
                    'app_id': claims.get('appid', ''),
                    'aud': claims.get('aud', ''),
                    'iss': claims.get('iss', '')
                } if claims else None,
                'properties': raw_event.get('properties', {}),
                'http_request': raw_event.get('httpRequest', {})
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_signin_log(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Azure AD Sign-in Log"""
        # Extract user info
        user_principal_name = raw_event.get('userPrincipalName', '')
        user_display_name = raw_event.get('userDisplayName', '')
        user_id = raw_event.get('userId', raw_event.get('id', ''))

        # Extract status
        status = raw_event.get('status', {})
        error_code = str(status.get('errorCode', '0'))
        failure_reason = status.get('failureReason', '')
        additional_details = status.get('additionalDetails', '')

        # Determine outcome
        outcome = 'success' if error_code == '0' else 'failure'

        # Extract IP and location
        ip_address = raw_event.get('ipAddress', '')
        location = raw_event.get('location', {})
        country = location.get('countryOrRegion', '')
        state = location.get('state', '')
        city = location.get('city', '')
        geo_coords = location.get('geoCoordinates', {})

        # Extract device info
        device_detail = raw_event.get('deviceDetail', {})
        browser = device_detail.get('browser', '')
        os = device_detail.get('operatingSystem', '')
        device_id = device_detail.get('deviceId', '')
        is_managed = device_detail.get('isManaged', False)
        is_compliant = device_detail.get('isCompliant', False)

        # Extract app info
        app_display_name = raw_event.get('appDisplayName', '')
        app_id = raw_event.get('appId', '')
        resource_display_name = raw_event.get('resourceDisplayName', '')

        # Extract risk info
        risk_level = raw_event.get('riskLevelAggregated', raw_event.get('riskLevel', 'none'))
        risk_state = raw_event.get('riskState', '')
        risk_detail = raw_event.get('riskDetail', '')
        risk_event_types = raw_event.get('riskEventTypes', [])

        # Extract conditional access
        conditional_access = raw_event.get('conditionalAccessStatus', '')
        applied_policies = raw_event.get('appliedConditionalAccessPolicies', [])

        # Extract MFA info
        mfa_detail = raw_event.get('mfaDetail', {})
        auth_details = raw_event.get('authenticationDetails', [])

        # Build normalized event
        normalized = {
            '@timestamp': self._parse_timestamp(raw_event.get('createdDateTime', raw_event.get('time', ''))),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['authentication'],
                'type': ['start'] if outcome == 'success' else ['start', 'denied'],
                'action': 'sign-in',
                'outcome': outcome,
                'provider': 'azure',
                'module': 'signin_log',
                'id': raw_event.get('id', raw_event.get('correlationId', '')),
                'reason': self.SIGNIN_ERROR_CODES.get(error_code, failure_reason)
            },

            'message': self._build_signin_message(user_principal_name, outcome, app_display_name, error_code),

            'user': {
                'id': user_id,
                'name': user_display_name,
                'email': user_principal_name,
                'domain': self._extract_domain_from_email(user_principal_name),
                'risk': {
                    'static_level': risk_level,
                    'calculated_level': self.RISK_LEVEL_SEVERITY.get(risk_level.lower(), 'low')
                }
            },

            'source': {
                'ip': ip_address,
                'geo': {
                    'country_iso_code': country,
                    'region_name': state,
                    'city_name': city,
                    'location': {
                        'lat': geo_coords.get('latitude'),
                        'lon': geo_coords.get('longitude')
                    } if geo_coords else None
                } if country or city else None
            } if ip_address else None,

            'user_agent': {
                'name': browser,
                'os': {
                    'name': os
                }
            } if browser or os else None,

            'host': {
                'id': device_id,
                'os': {
                    'name': os
                }
            } if device_id else None,

            'related': self._build_related_signin(user_principal_name, user_display_name, ip_address),

            'azure': {
                'signin': {
                    'user_principal_name': user_principal_name,
                    'user_display_name': user_display_name,
                    'user_id': user_id,
                    'correlation_id': raw_event.get('correlationId', ''),
                    'app_display_name': app_display_name,
                    'app_id': app_id,
                    'resource_display_name': resource_display_name,
                    'resource_id': raw_event.get('resourceId', ''),
                    'client_app_used': raw_event.get('clientAppUsed', ''),
                    'is_interactive': raw_event.get('isInteractive', True),
                    'token_issuer_type': raw_event.get('tokenIssuerType', ''),
                    'processing_time_ms': raw_event.get('processingTimeInMilliseconds', 0)
                },
                'status': {
                    'error_code': error_code,
                    'failure_reason': failure_reason,
                    'additional_details': additional_details
                },
                'location': {
                    'country': country,
                    'state': state,
                    'city': city,
                    'latitude': geo_coords.get('latitude'),
                    'longitude': geo_coords.get('longitude')
                } if location else None,
                'device': {
                    'device_id': device_id,
                    'browser': browser,
                    'operating_system': os,
                    'is_managed': is_managed,
                    'is_compliant': is_compliant,
                    'trust_type': device_detail.get('trustType', '')
                } if device_detail else None,
                'risk': {
                    'level': risk_level,
                    'state': risk_state,
                    'detail': risk_detail,
                    'event_types': risk_event_types
                } if risk_level != 'none' else None,
                'conditional_access': {
                    'status': conditional_access,
                    'policies': [
                        {
                            'id': p.get('id', ''),
                            'display_name': p.get('displayName', ''),
                            'result': p.get('result', ''),
                            'enforcement': p.get('enforcedGrantControls', [])
                        }
                        for p in applied_policies
                    ] if applied_policies else None
                } if conditional_access else None,
                'mfa': {
                    'auth_method': mfa_detail.get('authMethod', ''),
                    'auth_detail': mfa_detail.get('authDetail', ''),
                    'auth_methods': [
                        {
                            'method': a.get('authenticationMethod', ''),
                            'method_detail': a.get('authenticationMethodDetail', ''),
                            'succeeded': a.get('succeeded', False)
                        }
                        for a in auth_details
                    ] if auth_details else None
                } if mfa_detail or auth_details else None
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_audit_log(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Azure AD Audit Log"""
        activity = raw_event.get('activityDisplayName', raw_event.get('operationName', ''))
        category = raw_event.get('category', raw_event.get('loggedByService', ''))
        result = raw_event.get('result', 'success')

        # Extract initiator (who performed the action)
        initiated_by = raw_event.get('initiatedBy', {})
        user_info = initiated_by.get('user', {})
        app_info = initiated_by.get('app', {})

        initiator_upn = user_info.get('userPrincipalName', '')
        initiator_display_name = user_info.get('displayName', app_info.get('displayName', ''))
        initiator_id = user_info.get('id', app_info.get('appId', ''))
        initiator_ip = user_info.get('ipAddress', '')

        # Extract target resources
        target_resources = raw_event.get('targetResources', [])
        target_info = target_resources[0] if target_resources else {}
        target_type = target_info.get('type', '')
        target_display_name = target_info.get('displayName', '')
        target_id = target_info.get('id', '')
        target_upn = target_info.get('userPrincipalName', '')

        # Extract modified properties
        modified_properties = target_info.get('modifiedProperties', [])

        # Determine ECS categorization
        ecs_categories = self._get_audit_category(activity, category)
        ecs_types = self._get_event_type_from_operation(activity)

        # Build normalized event
        normalized = {
            '@timestamp': self._parse_timestamp(raw_event.get('activityDateTime', raw_event.get('time', ''))),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ecs_categories,
                'type': ecs_types,
                'action': activity,
                'outcome': 'success' if result.lower() == 'success' else 'failure',
                'provider': 'azure',
                'module': 'audit_log',
                'id': raw_event.get('id', raw_event.get('correlationId', ''))
            },

            'message': self._build_audit_message(activity, initiator_upn or initiator_display_name, target_display_name),

            'user': {
                'id': initiator_id,
                'name': initiator_display_name,
                'email': initiator_upn,
                'target': {
                    'id': target_id,
                    'name': target_display_name,
                    'email': target_upn
                } if target_type in ('User', 'ServicePrincipal') else None
            },

            'source': {
                'ip': initiator_ip
            } if initiator_ip else None,

            'related': self._build_related_audit(initiator_upn, target_upn, initiator_ip),

            'azure': {
                'audit': {
                    'activity_display_name': activity,
                    'category': category,
                    'result': result,
                    'result_reason': raw_event.get('resultReason', ''),
                    'correlation_id': raw_event.get('correlationId', ''),
                    'logged_by_service': raw_event.get('loggedByService', ''),
                    'operation_type': raw_event.get('operationType', ''),
                    'tenant_id': raw_event.get('tenantId', '')
                },
                'initiator': {
                    'type': 'user' if user_info else 'app',
                    'id': initiator_id,
                    'display_name': initiator_display_name,
                    'user_principal_name': initiator_upn,
                    'ip_address': initiator_ip
                } if initiated_by else None,
                'target': {
                    'type': target_type,
                    'id': target_id,
                    'display_name': target_display_name,
                    'user_principal_name': target_upn,
                    'group_type': target_info.get('groupType', '')
                } if target_info else None,
                'modified_properties': [
                    {
                        'name': p.get('displayName', ''),
                        'old_value': p.get('oldValue', ''),
                        'new_value': p.get('newValue', '')
                    }
                    for p in modified_properties
                ] if modified_properties else None,
                'additional_targets': [
                    {
                        'type': t.get('type', ''),
                        'id': t.get('id', ''),
                        'display_name': t.get('displayName', '')
                    }
                    for t in target_resources[1:]
                ] if len(target_resources) > 1 else None
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_security_alert(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Azure Security Center Alert"""
        alert_name = raw_event.get('alertName', raw_event.get('AlertName', ''))
        alert_type = raw_event.get('alertType', raw_event.get('AlertType', ''))
        description = raw_event.get('description', raw_event.get('Description', ''))
        severity = raw_event.get('severity', raw_event.get('Severity', 'Medium'))
        status = raw_event.get('status', raw_event.get('Status', ''))

        # Extract resource info
        resource_id = raw_event.get('resourceId', raw_event.get('AzureResourceId', ''))
        subscription_id = raw_event.get('subscriptionId', self._extract_subscription_id(resource_id))

        # Extract entities
        entities = raw_event.get('entities', raw_event.get('Entities', []))
        extended_properties = raw_event.get('extendedProperties', raw_event.get('ExtendedProperties', {}))

        # Map severity
        severity_map = {
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'informational': 'low'
        }
        ecs_severity = severity_map.get(severity.lower(), 'medium')

        normalized = {
            '@timestamp': self._parse_timestamp(raw_event.get('timeGenerated', raw_event.get('time', ''))),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'alert',
                'category': ['intrusion_detection'],
                'type': ['indicator'],
                'action': alert_type,
                'outcome': 'success',
                'provider': 'azure',
                'module': 'security_center',
                'id': raw_event.get('alertId', raw_event.get('SystemAlertId', '')),
                'severity': ecs_severity
            },

            'message': f"Security Alert: {alert_name} - {description}",

            'rule': {
                'name': alert_name,
                'description': description,
                'category': alert_type
            },

            'cloud': {
                'provider': 'azure',
                'account': {
                    'id': subscription_id
                }
            },

            'azure': {
                'security_alert': {
                    'alert_name': alert_name,
                    'alert_type': alert_type,
                    'description': description,
                    'severity': severity,
                    'status': status,
                    'resource_id': resource_id,
                    'subscription_id': subscription_id,
                    'vendor_name': raw_event.get('vendorName', 'Azure Security Center'),
                    'product_name': raw_event.get('productName', ''),
                    'compromised_entity': raw_event.get('compromisedEntity', ''),
                    'intent': raw_event.get('intent', ''),
                    'confidence_level': raw_event.get('confidenceLevel', ''),
                    'extended_properties': extended_properties,
                    'entities': entities
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_nsg_flow_log(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse NSG Flow Log"""
        # NSG flow logs have a specific nested structure
        rule = raw_event.get('rule', '')
        flows = raw_event.get('flows', [])

        # Extract first flow tuple for primary event
        flow_tuples = []
        for flow in flows:
            mac = flow.get('mac', '')
            for tuple_data in flow.get('flowTuples', []):
                # Flow tuple format: timestamp,srcIP,dstIP,srcPort,dstPort,protocol,flowDirection,flowState,packetsS2D,bytesS2D,packetsD2S,bytesD2S
                parts = tuple_data.split(',')
                if len(parts) >= 8:
                    flow_tuples.append({
                        'timestamp': parts[0],
                        'source_ip': parts[1],
                        'dest_ip': parts[2],
                        'source_port': parts[3],
                        'dest_port': parts[4],
                        'protocol': 'TCP' if parts[5] == 'T' else 'UDP',
                        'direction': 'inbound' if parts[6] == 'I' else 'outbound',
                        'action': 'allow' if parts[7] == 'A' else 'deny',
                        'mac': mac,
                        'packets_s2d': parts[8] if len(parts) > 8 else None,
                        'bytes_s2d': parts[9] if len(parts) > 9 else None,
                        'packets_d2s': parts[10] if len(parts) > 10 else None,
                        'bytes_d2s': parts[11] if len(parts) > 11 else None
                    })

        primary_flow = flow_tuples[0] if flow_tuples else {}
        action = primary_flow.get('action', 'unknown')

        normalized = {
            '@timestamp': self._parse_timestamp(raw_event.get('time', primary_flow.get('timestamp', ''))),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['network'],
                'type': ['connection', 'allowed' if action == 'allow' else 'denied'],
                'action': f"nsg_{action}",
                'outcome': 'success' if action == 'allow' else 'failure',
                'provider': 'azure',
                'module': 'nsg_flow_log'
            },

            'message': f"NSG {rule}: {action} {primary_flow.get('protocol', '')} from {primary_flow.get('source_ip', '')}:{primary_flow.get('source_port', '')} to {primary_flow.get('dest_ip', '')}:{primary_flow.get('dest_port', '')}",

            'source': {
                'ip': primary_flow.get('source_ip'),
                'port': int(primary_flow.get('source_port', 0)) if primary_flow.get('source_port', '').isdigit() else None
            } if primary_flow.get('source_ip') else None,

            'destination': {
                'ip': primary_flow.get('dest_ip'),
                'port': int(primary_flow.get('dest_port', 0)) if primary_flow.get('dest_port', '').isdigit() else None
            } if primary_flow.get('dest_ip') else None,

            'network': {
                'transport': primary_flow.get('protocol', '').lower(),
                'direction': primary_flow.get('direction'),
                'type': 'ipv4' if primary_flow.get('source_ip', '').count('.') == 3 else 'ipv6'
            } if primary_flow else None,

            'related': {
                'ip': list(set([
                    primary_flow.get('source_ip'),
                    primary_flow.get('dest_ip')
                ])) if primary_flow else []
            },

            'azure': {
                'nsg_flow': {
                    'rule_name': rule,
                    'flow_count': len(flow_tuples),
                    'flows': flow_tuples[:10],  # Limit to 10 flows
                    'resource_id': raw_event.get('resourceId', ''),
                    'mac_address': primary_flow.get('mac', ''),
                    'version': raw_event.get('version', 1)
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_resource_log(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Azure Resource/Diagnostic Log"""
        resource_id = raw_event.get('resourceId', '')
        category = raw_event.get('category', '')
        operation_name = raw_event.get('operationName', '')
        result_type = raw_event.get('resultType', '')
        properties = raw_event.get('properties', {})

        # Determine resource type specific handling
        resource_type = self._extract_resource_type(resource_id)
        resource_name = self._extract_resource_name(resource_id)

        ecs_categories = self._get_operation_category(operation_name)

        normalized = {
            '@timestamp': self._parse_timestamp(raw_event.get('time', '')),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ecs_categories,
                'type': self._get_event_type_from_operation(operation_name),
                'action': operation_name,
                'outcome': 'success' if result_type.lower() in ('success', 'succeeded', '') else 'failure',
                'provider': 'azure',
                'module': 'resource_log',
                'id': raw_event.get('correlationId', '')
            },

            'message': f"Azure {resource_type}: {operation_name}",

            'cloud': {
                'provider': 'azure',
                'account': {
                    'id': self._extract_subscription_id(resource_id)
                },
                'region': raw_event.get('location', ''),
                'service': {
                    'name': resource_type
                }
            },

            'azure': {
                'resource_log': {
                    'resource_id': resource_id,
                    'resource_type': resource_type,
                    'resource_name': resource_name,
                    'resource_group': self._extract_resource_group(resource_id),
                    'category': category,
                    'operation_name': operation_name,
                    'result_type': result_type,
                    'result_signature': raw_event.get('resultSignature', ''),
                    'result_description': raw_event.get('resultDescription', ''),
                    'duration_ms': raw_event.get('durationMs', 0),
                    'caller_ip': raw_event.get('callerIpAddress', ''),
                    'correlation_id': raw_event.get('correlationId', ''),
                    'level': raw_event.get('level', ''),
                    'properties': properties
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_generic_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse generic/unknown Azure event format"""
        timestamp = (
            raw_event.get('time') or
            raw_event.get('timeGenerated') or
            raw_event.get('eventTimestamp') or
            raw_event.get('createdDateTime') or
            ''
        )

        normalized = {
            '@timestamp': self._parse_timestamp(timestamp),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['host'],
                'type': ['info'],
                'action': raw_event.get('operationName', raw_event.get('category', 'unknown')),
                'outcome': 'unknown',
                'provider': 'azure',
                'module': 'generic'
            },

            'azure': {
                'event_data': raw_event
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _get_operation_category(self, operation: str) -> List[str]:
        """Get ECS category from operation name"""
        if not operation:
            return ['host']

        lower_op = operation.lower()

        for keyword, categories in self.OPERATION_CATEGORY_MAP.items():
            if keyword in lower_op:
                return categories

        return ['host']

    def _get_audit_category(self, activity: str, category: str) -> List[str]:
        """Get ECS category for audit log events"""
        lower_activity = activity.lower()

        if 'user' in lower_activity or 'member' in lower_activity or 'group' in lower_activity:
            return ['iam']
        elif 'role' in lower_activity or 'permission' in lower_activity:
            return ['iam']
        elif 'application' in lower_activity or 'service principal' in lower_activity:
            return ['iam']
        elif 'policy' in lower_activity:
            return ['configuration']
        elif 'password' in lower_activity or 'credential' in lower_activity:
            return ['authentication']
        elif 'sign' in lower_activity or 'auth' in lower_activity:
            return ['authentication']
        else:
            return ['configuration']

    def _get_event_type_from_operation(self, operation: str) -> List[str]:
        """Determine ECS event.type from operation"""
        if not operation:
            return ['info']

        lower_op = operation.lower()

        if 'create' in lower_op or 'add' in lower_op or 'register' in lower_op:
            return ['creation']
        elif 'delete' in lower_op or 'remove' in lower_op or 'unregister' in lower_op:
            return ['deletion']
        elif 'update' in lower_op or 'modify' in lower_op or 'change' in lower_op or 'set' in lower_op:
            return ['change']
        elif 'read' in lower_op or 'get' in lower_op or 'list' in lower_op:
            return ['access']
        elif 'start' in lower_op or 'enable' in lower_op:
            return ['start']
        elif 'stop' in lower_op or 'disable' in lower_op:
            return ['end']
        elif 'allow' in lower_op or 'grant' in lower_op:
            return ['allowed']
        elif 'deny' in lower_op or 'revoke' in lower_op or 'block' in lower_op:
            return ['denied']
        elif 'sign' in lower_op:
            return ['start']
        else:
            return ['info']

    def _determine_activity_outcome(self, status: str, event: Dict[str, Any]) -> str:
        """Determine outcome from activity log status"""
        if not status:
            return 'unknown'

        lower_status = status.lower()

        if lower_status in ('succeeded', 'success', 'accepted', 'ok', 'completed'):
            return 'success'
        elif lower_status in ('failed', 'failure', 'error', 'canceled', 'rejected'):
            return 'failure'
        elif lower_status in ('started', 'accepted', 'in progress'):
            return 'unknown'
        else:
            return 'unknown'

    def _extract_subscription_id(self, resource_id: str) -> str:
        """Extract subscription ID from resource ID"""
        if not resource_id:
            return ''

        match = re.search(r'/subscriptions/([^/]+)', resource_id, re.IGNORECASE)
        return match.group(1) if match else ''

    def _extract_resource_group(self, resource_id: str) -> str:
        """Extract resource group from resource ID"""
        if not resource_id:
            return ''

        match = re.search(r'/resourceGroups/([^/]+)', resource_id, re.IGNORECASE)
        return match.group(1) if match else ''

    def _extract_resource_type(self, resource_id: str) -> str:
        """Extract resource type from resource ID"""
        if not resource_id:
            return ''

        # Match provider/type pattern
        match = re.search(r'/providers/([^/]+/[^/]+)', resource_id, re.IGNORECASE)
        return match.group(1) if match else ''

    def _extract_resource_name(self, resource_id: str) -> str:
        """Extract resource name from resource ID"""
        if not resource_id:
            return ''

        # Get the last segment
        parts = resource_id.rstrip('/').split('/')
        return parts[-1] if parts else ''

    def _extract_domain_from_email(self, email: str) -> Optional[str]:
        """Extract domain from email address"""
        if not email or '@' not in email:
            return None
        return email.split('@')[-1]

    def _get_sub_status(self, event: Dict[str, Any]) -> str:
        """Get sub-status from event"""
        sub_status = event.get('subStatus', {})
        if isinstance(sub_status, dict):
            return sub_status.get('value', sub_status.get('localizedValue', ''))
        return str(sub_status) if sub_status else ''

    def _build_activity_message(self, operation: str, caller: str, resource_name: str, resource_type: str) -> str:
        """Build human-readable message for activity log"""
        parts = []
        if caller:
            parts.append(caller)
        parts.append(operation or 'performed action')
        if resource_name and resource_type:
            parts.append(f"on {resource_type} '{resource_name}'")
        elif resource_name:
            parts.append(f"on '{resource_name}'")
        return ' '.join(parts)

    def _build_signin_message(self, upn: str, outcome: str, app_name: str, error_code: str) -> str:
        """Build human-readable message for sign-in event"""
        if outcome == 'success':
            return f"{upn} signed in to {app_name or 'Azure'}"
        else:
            error_desc = self.SIGNIN_ERROR_CODES.get(error_code, f'error {error_code}')
            return f"{upn} failed to sign in to {app_name or 'Azure'}: {error_desc}"

    def _build_audit_message(self, activity: str, initiator: str, target: str) -> str:
        """Build human-readable message for audit log"""
        parts = []
        if initiator:
            parts.append(initiator)
        parts.append(activity or 'performed action')
        if target:
            parts.append(f"on '{target}'")
        return ' '.join(parts)

    def _build_related_activity(self, caller: str, ip: str, resource: str) -> Dict[str, List[str]]:
        """Build related fields for activity log"""
        related = {'user': [], 'ip': []}
        if caller:
            related['user'].append(caller)
        if ip:
            related['ip'].append(ip)
        return {k: v for k, v in related.items() if v}

    def _build_related_signin(self, upn: str, display_name: str, ip: str) -> Dict[str, List[str]]:
        """Build related fields for sign-in log"""
        related = {'user': [], 'ip': []}
        for user in [upn, display_name]:
            if user and user not in related['user']:
                related['user'].append(user)
        if ip:
            related['ip'].append(ip)
        return {k: v for k, v in related.items() if v}

    def _build_related_audit(self, initiator: str, target: str, ip: str) -> Dict[str, List[str]]:
        """Build related fields for audit log"""
        related = {'user': [], 'ip': []}
        for user in [initiator, target]:
            if user and user not in related['user']:
                related['user'].append(user)
        if ip:
            related['ip'].append(ip)
        return {k: v for k, v in related.items() if v}

    def _parse_timestamp(self, timestamp_str: str) -> str:
        """Parse and validate timestamp"""
        if not timestamp_str:
            return datetime.now(timezone.utc).isoformat()

        # Handle various Azure timestamp formats
        formats = [
            '%Y-%m-%dT%H:%M:%S.%f%z',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S%z',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.isoformat()
            except ValueError:
                continue

        # Try ISO format parsing
        try:
            if timestamp_str.endswith('Z'):
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                dt = datetime.fromisoformat(timestamp_str)
            return dt.isoformat()
        except ValueError:
            pass

        # Try Unix timestamp
        try:
            ts = float(timestamp_str)
            if ts > 1e12:  # Milliseconds
                ts = ts / 1000
            return datetime.fromtimestamp(ts, timezone.utc).isoformat()
        except (ValueError, TypeError, OSError):
            pass

        return datetime.now(timezone.utc).isoformat()

    def _remove_none_values(self, data: Any) -> Any:
        """Recursively remove None/empty values from dict"""
        if isinstance(data, dict):
            return {
                k: self._remove_none_values(v)
                for k, v in data.items()
                if v is not None and v != {} and v != [] and v != ''
            }
        elif isinstance(data, list):
            return [self._remove_none_values(item) for item in data if item is not None]
        else:
            return data

    def validate(self, event: Dict[str, Any]) -> bool:
        """
        Validate that event has required Azure Monitor fields.

        Args:
            event: Event to validate

        Returns:
            True if valid, False otherwise
        """
        # Activity Log format
        if 'operationName' in event and ('resourceId' in event or 'resourceUri' in event):
            return True

        # Sign-in Log format
        if 'userPrincipalName' in event and 'status' in event:
            return True

        # Audit Log format
        if 'activityDisplayName' in event or 'operationType' in event:
            return True

        # Security Alert format
        if 'alertName' in event or 'AlertName' in event:
            return True

        # NSG Flow Log format
        if 'flows' in event or 'rule' in event:
            return True

        # Resource Log format
        if 'resourceId' in event and 'properties' in event:
            return True

        # Has timestamp (minimal requirement)
        if 'time' in event or 'timeGenerated' in event or 'eventTimestamp' in event:
            return True

        return False
