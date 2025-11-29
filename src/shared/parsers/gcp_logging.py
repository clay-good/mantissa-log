"""
GCP Cloud Logging Parser with ECS Normalization

Normalizes GCP Cloud Logging entries to Elastic Common Schema (ECS) format for
unified detection and analysis.

Supports GCP log types including:
- Cloud Audit Logs (Admin Activity, Data Access, System Event)
- VPC Flow Logs
- Firewall Logs
- GKE Audit Logs
- Cloud Functions Logs
- IAM Policy Logs
- Cloud Storage Access Logs
- Compute Engine Logs
- Cloud SQL Logs

Reference:
- https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry
- https://cloud.google.com/logging/docs/audit
- https://cloud.google.com/vpc/docs/flow-logs
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import re


class BaseParser:
    """Base parser class for ECS normalization"""

    def __init__(self):
        self.source_type = "generic"


class GCPLoggingParser(BaseParser):
    """Parser for GCP Cloud Logging with ECS normalization"""

    # GCP method to ECS category mapping
    METHOD_CATEGORY_MAP = {
        # IAM/Admin methods
        'setiampolicy': ['iam'],
        'getiampolicy': ['iam'],
        'setorgpolicy': ['iam'],
        'createserviceaccount': ['iam'],
        'deleteserviceaccount': ['iam'],
        'createserviceaccountkey': ['iam'],
        'deleteserviceaccountkey': ['iam'],
        'addbinding': ['iam'],
        'removebinding': ['iam'],

        # Authentication
        'login': ['authentication'],
        'logout': ['authentication'],
        'authenticate': ['authentication'],

        # Compute
        'insert': ['host'],
        'delete': ['host'],
        'start': ['host'],
        'stop': ['host'],
        'reset': ['host'],
        'setmetadata': ['host'],
        'setlabels': ['host'],

        # Network
        'createfirewall': ['network'],
        'deletefirewall': ['network'],
        'updatefirewall': ['network'],
        'createroute': ['network'],
        'deleteroute': ['network'],
        'createvpcnetwork': ['network'],

        # Storage
        'create': ['file'],
        'get': ['file'],
        'update': ['file'],
        'copy': ['file'],
        'move': ['file'],

        # Database
        'query': ['database'],
        'execute': ['database'],
    }

    # Critical GCP operations requiring monitoring
    CRITICAL_OPERATIONS = {
        'google.iam.admin.v1.setiampolicy',
        'google.iam.admin.v1.createserviceaccount',
        'google.iam.admin.v1.createserviceaccountkey',
        'google.cloud.resourcemanager.v3.folders.setiampolicy',
        'google.cloud.resourcemanager.v3.organizations.setiampolicy',
        'google.cloud.resourcemanager.v3.projects.setiampolicy',
        'google.compute.firewalls.insert',
        'google.compute.firewalls.delete',
        'google.compute.instances.setmetadata',
        'google.compute.instances.setsshkeys',
        'google.storage.buckets.setiampolicy',
        'google.storage.buckets.create',
        'google.storage.buckets.delete',
        'google.container.clusters.create',
        'google.container.clusters.delete',
        'google.cloudfunctions.functions.create',
        'google.cloudfunctions.functions.update',
    }

    # Severity mapping
    SEVERITY_MAP = {
        'DEFAULT': 'low',
        'DEBUG': 'low',
        'INFO': 'low',
        'NOTICE': 'low',
        'WARNING': 'medium',
        'ERROR': 'high',
        'CRITICAL': 'critical',
        'ALERT': 'critical',
        'EMERGENCY': 'critical',
    }

    def __init__(self):
        super().__init__()
        self.source_type = "gcp_logging"

    def parse(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse GCP Cloud Logging entry and normalize to ECS.

        Args:
            raw_event: Raw GCP log entry

        Returns:
            Normalized event in ECS format
        """
        # Detect log type and route to appropriate parser
        if self._is_audit_log(raw_event):
            return self._parse_audit_log(raw_event)
        elif self._is_vpc_flow_log(raw_event):
            return self._parse_vpc_flow_log(raw_event)
        elif self._is_firewall_log(raw_event):
            return self._parse_firewall_log(raw_event)
        elif self._is_gke_audit_log(raw_event):
            return self._parse_gke_audit_log(raw_event)
        elif self._is_data_access_log(raw_event):
            return self._parse_data_access_log(raw_event)
        else:
            return self._parse_generic_log(raw_event)

    def _is_audit_log(self, event: Dict[str, Any]) -> bool:
        """Check if event is a Cloud Audit Log"""
        log_name = event.get('logName', '')
        return (
            'cloudaudit.googleapis.com%2Factivity' in log_name or
            'cloudaudit.googleapis.com/activity' in log_name or
            event.get('protoPayload', {}).get('@type') == 'type.googleapis.com/google.cloud.audit.AuditLog'
        )

    def _is_vpc_flow_log(self, event: Dict[str, Any]) -> bool:
        """Check if event is a VPC Flow Log"""
        log_name = event.get('logName', '')
        return (
            'compute.googleapis.com%2Fvpc_flows' in log_name or
            'compute.googleapis.com/vpc_flows' in log_name or
            event.get('resource', {}).get('type') == 'gce_subnetwork'
        )

    def _is_firewall_log(self, event: Dict[str, Any]) -> bool:
        """Check if event is a Firewall Log"""
        log_name = event.get('logName', '')
        return (
            'compute.googleapis.com%2Ffirewall' in log_name or
            'compute.googleapis.com/firewall' in log_name
        )

    def _is_gke_audit_log(self, event: Dict[str, Any]) -> bool:
        """Check if event is a GKE Audit Log"""
        resource_type = event.get('resource', {}).get('type', '')
        return resource_type in ('k8s_cluster', 'gke_cluster')

    def _is_data_access_log(self, event: Dict[str, Any]) -> bool:
        """Check if event is a Data Access Log"""
        log_name = event.get('logName', '')
        return (
            'cloudaudit.googleapis.com%2Fdata_access' in log_name or
            'cloudaudit.googleapis.com/data_access' in log_name
        )

    def _parse_audit_log(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GCP Cloud Audit Log (Admin Activity)"""
        proto_payload = raw_event.get('protoPayload', {})
        resource = raw_event.get('resource', {})
        labels = resource.get('labels', {})

        # Extract method and service
        method_name = proto_payload.get('methodName', '')
        service_name = proto_payload.get('serviceName', '')

        # Extract authentication info
        auth_info = proto_payload.get('authenticationInfo', {})
        principal_email = auth_info.get('principalEmail', '')
        principal_subject = auth_info.get('principalSubject', '')
        service_account_delegation = auth_info.get('serviceAccountDelegationInfo', [])

        # Extract authorization info
        auth_info_list = proto_payload.get('authorizationInfo', [])
        permissions = [a.get('permission', '') for a in auth_info_list]
        resources = [a.get('resource', '') for a in auth_info_list]
        granted = all(a.get('granted', False) for a in auth_info_list) if auth_info_list else True

        # Extract request metadata
        request_metadata = proto_payload.get('requestMetadata', {})
        caller_ip = request_metadata.get('callerIp', '')
        caller_supplied_user_agent = request_metadata.get('callerSuppliedUserAgent', '')
        caller_network = request_metadata.get('callerNetwork', '')
        destination_attributes = request_metadata.get('destinationAttributes', {})

        # Extract request/response
        request = proto_payload.get('request', {})
        response = proto_payload.get('response', {})
        resource_name = proto_payload.get('resourceName', '')

        # Extract status
        status = proto_payload.get('status', {})
        status_code = status.get('code', 0)
        status_message = status.get('message', '')

        # Determine outcome
        outcome = 'success' if status_code == 0 and granted else 'failure'

        # Determine ECS categories
        ecs_categories = self._get_method_category(method_name)

        # Check if critical operation
        full_method = f"{service_name}.{method_name}".lower()
        is_critical = any(
            critical.lower() in full_method
            for critical in self.CRITICAL_OPERATIONS
        )

        # Extract project info
        project_id = labels.get('project_id', '')
        location = labels.get('location', labels.get('zone', labels.get('region', '')))

        # Build normalized event
        normalized = {
            '@timestamp': self._parse_timestamp(raw_event.get('timestamp', raw_event.get('receiveTimestamp', ''))),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ecs_categories,
                'type': self._get_event_type_from_method(method_name),
                'action': method_name,
                'outcome': outcome,
                'provider': 'gcp',
                'module': 'audit_log',
                'id': raw_event.get('insertId', ''),
                'severity': self.SEVERITY_MAP.get(raw_event.get('severity', 'INFO'), 'low')
            },

            'message': self._build_audit_message(method_name, principal_email, resource_name),

            'user': {
                'email': principal_email,
                'name': self._extract_username_from_email(principal_email),
                'id': principal_subject,
                'domain': self._extract_domain_from_email(principal_email)
            } if principal_email else None,

            'source': {
                'ip': caller_ip if caller_ip and caller_ip != 'private' else None,
                'nat': {
                    'ip': caller_ip
                } if caller_ip == 'private' else None
            } if caller_ip else None,

            'user_agent': {
                'original': caller_supplied_user_agent
            } if caller_supplied_user_agent else None,

            'cloud': {
                'provider': 'gcp',
                'project': {
                    'id': project_id
                },
                'region': location,
                'service': {
                    'name': service_name
                }
            },

            'related': self._build_related_audit(principal_email, caller_ip, resource_name),

            'gcp': {
                'audit': {
                    'method_name': method_name,
                    'service_name': service_name,
                    'resource_name': resource_name,
                    'resource_type': resource.get('type', ''),
                    'log_name': raw_event.get('logName', ''),
                    'insert_id': raw_event.get('insertId', ''),
                    'trace': raw_event.get('trace', ''),
                    'span_id': raw_event.get('spanId', ''),
                    'is_critical': is_critical
                },
                'authentication': {
                    'principal_email': principal_email,
                    'principal_subject': principal_subject,
                    'service_account_delegation': [
                        {
                            'principal_email': d.get('principalEmail', ''),
                            'first_party_principal': d.get('firstPartyPrincipal', {})
                        }
                        for d in service_account_delegation
                    ] if service_account_delegation else None
                },
                'authorization': {
                    'permissions': permissions,
                    'resources': resources,
                    'granted': granted
                } if auth_info_list else None,
                'request_metadata': {
                    'caller_ip': caller_ip,
                    'caller_user_agent': caller_supplied_user_agent,
                    'caller_network': caller_network,
                    'destination_ip': destination_attributes.get('ip', ''),
                    'destination_port': destination_attributes.get('port', 0)
                },
                'status': {
                    'code': status_code,
                    'message': status_message
                } if status else None,
                'request': request if request else None,
                'response': response if response else None,
                'labels': labels,
                'project_id': project_id,
                'location': location
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_vpc_flow_log(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GCP VPC Flow Log"""
        json_payload = raw_event.get('jsonPayload', {})
        resource = raw_event.get('resource', {})
        labels = resource.get('labels', {})

        # Extract connection info
        connection = json_payload.get('connection', {})
        src_ip = connection.get('src_ip', '')
        src_port = connection.get('src_port', 0)
        dest_ip = connection.get('dest_ip', '')
        dest_port = connection.get('dest_port', 0)
        protocol = connection.get('protocol', 0)

        # Map protocol number to name
        protocol_map = {6: 'tcp', 17: 'udp', 1: 'icmp'}
        protocol_name = protocol_map.get(protocol, str(protocol))

        # Extract instance info
        src_instance = json_payload.get('src_instance', {})
        dest_instance = json_payload.get('dest_instance', {})
        src_vpc = json_payload.get('src_vpc', {})
        dest_vpc = json_payload.get('dest_vpc', {})

        # Extract geo info
        src_location = json_payload.get('src_location', {})
        dest_location = json_payload.get('dest_location', {})

        # Extract bytes/packets
        bytes_sent = json_payload.get('bytes_sent', 0)
        packets_sent = json_payload.get('packets_sent', 0)

        # Determine direction
        reporter = json_payload.get('reporter', '')

        normalized = {
            '@timestamp': self._parse_timestamp(raw_event.get('timestamp', '')),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['network'],
                'type': ['connection'],
                'action': 'vpc_flow',
                'outcome': 'success',
                'provider': 'gcp',
                'module': 'vpc_flow_log',
                'id': raw_event.get('insertId', '')
            },

            'message': f"VPC Flow: {src_ip}:{src_port} -> {dest_ip}:{dest_port} ({protocol_name})",

            'source': {
                'ip': src_ip,
                'port': src_port,
                'bytes': bytes_sent if reporter == 'SRC' else None,
                'packets': packets_sent if reporter == 'SRC' else None,
                'geo': {
                    'country_iso_code': src_location.get('country', ''),
                    'region_name': src_location.get('region', ''),
                    'city_name': src_location.get('city', '')
                } if src_location else None
            } if src_ip else None,

            'destination': {
                'ip': dest_ip,
                'port': dest_port,
                'bytes': bytes_sent if reporter == 'DEST' else None,
                'packets': packets_sent if reporter == 'DEST' else None,
                'geo': {
                    'country_iso_code': dest_location.get('country', ''),
                    'region_name': dest_location.get('region', ''),
                    'city_name': dest_location.get('city', '')
                } if dest_location else None
            } if dest_ip else None,

            'network': {
                'transport': protocol_name,
                'bytes': bytes_sent,
                'packets': packets_sent,
                'type': 'ipv4' if src_ip and '.' in src_ip else 'ipv6'
            },

            'cloud': {
                'provider': 'gcp',
                'project': {
                    'id': labels.get('project_id', '')
                },
                'region': labels.get('location', labels.get('region', ''))
            },

            'related': {
                'ip': [ip for ip in [src_ip, dest_ip] if ip]
            },

            'gcp': {
                'vpc_flow': {
                    'reporter': reporter,
                    'src_instance': {
                        'project_id': src_instance.get('project_id', ''),
                        'zone': src_instance.get('zone', ''),
                        'vm_name': src_instance.get('vm_name', ''),
                        'region': src_instance.get('region', '')
                    } if src_instance else None,
                    'dest_instance': {
                        'project_id': dest_instance.get('project_id', ''),
                        'zone': dest_instance.get('zone', ''),
                        'vm_name': dest_instance.get('vm_name', ''),
                        'region': dest_instance.get('region', '')
                    } if dest_instance else None,
                    'src_vpc': {
                        'project_id': src_vpc.get('project_id', ''),
                        'vpc_name': src_vpc.get('vpc_name', ''),
                        'subnetwork_name': src_vpc.get('subnetwork_name', '')
                    } if src_vpc else None,
                    'dest_vpc': {
                        'project_id': dest_vpc.get('project_id', ''),
                        'vpc_name': dest_vpc.get('vpc_name', ''),
                        'subnetwork_name': dest_vpc.get('subnetwork_name', '')
                    } if dest_vpc else None,
                    'rtt_msec': json_payload.get('rtt_msec', 0),
                    'start_time': json_payload.get('start_time', ''),
                    'end_time': json_payload.get('end_time', '')
                },
                'subnetwork_id': labels.get('subnetwork_id', ''),
                'subnetwork_name': labels.get('subnetwork_name', ''),
                'project_id': labels.get('project_id', ''),
                'location': labels.get('location', '')
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_firewall_log(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GCP Firewall Log"""
        json_payload = raw_event.get('jsonPayload', {})
        resource = raw_event.get('resource', {})
        labels = resource.get('labels', {})

        # Extract connection info
        connection = json_payload.get('connection', {})
        src_ip = connection.get('src_ip', '')
        src_port = connection.get('src_port', 0)
        dest_ip = connection.get('dest_ip', '')
        dest_port = connection.get('dest_port', 0)
        protocol = connection.get('protocol', 0)

        protocol_map = {6: 'tcp', 17: 'udp', 1: 'icmp'}
        protocol_name = protocol_map.get(protocol, str(protocol))

        # Extract firewall info
        disposition = json_payload.get('disposition', '')
        rule_details = json_payload.get('rule_details', {})
        rule_name = rule_details.get('reference', '')
        rule_direction = rule_details.get('direction', '')
        rule_priority = rule_details.get('priority', 0)
        rule_action = rule_details.get('action', '')

        # Extract instance info
        instance = json_payload.get('instance', {})

        # Determine outcome based on disposition
        outcome = 'success' if disposition.upper() == 'ALLOWED' else 'failure'
        event_type = ['allowed'] if disposition.upper() == 'ALLOWED' else ['denied']

        normalized = {
            '@timestamp': self._parse_timestamp(raw_event.get('timestamp', '')),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['network'],
                'type': event_type,
                'action': f"firewall_{disposition.lower()}",
                'outcome': outcome,
                'provider': 'gcp',
                'module': 'firewall_log',
                'id': raw_event.get('insertId', '')
            },

            'message': f"Firewall {disposition}: {src_ip}:{src_port} -> {dest_ip}:{dest_port} ({protocol_name}) rule: {rule_name}",

            'source': {
                'ip': src_ip,
                'port': src_port
            } if src_ip else None,

            'destination': {
                'ip': dest_ip,
                'port': dest_port
            } if dest_ip else None,

            'network': {
                'transport': protocol_name,
                'direction': 'inbound' if rule_direction.upper() == 'INGRESS' else 'outbound'
            },

            'rule': {
                'name': rule_name,
                'id': rule_details.get('reference', '')
            },

            'cloud': {
                'provider': 'gcp',
                'project': {
                    'id': labels.get('project_id', '')
                }
            },

            'related': {
                'ip': [ip for ip in [src_ip, dest_ip] if ip]
            },

            'gcp': {
                'firewall': {
                    'disposition': disposition,
                    'rule_reference': rule_name,
                    'rule_direction': rule_direction,
                    'rule_priority': rule_priority,
                    'rule_action': rule_action,
                    'rule_network': rule_details.get('network', ''),
                    'rule_ip_ports': rule_details.get('ip_port_info', []),
                    'rule_target_tags': rule_details.get('target_tag', []),
                    'rule_source_ranges': rule_details.get('source_range', []),
                    'instance': {
                        'project_id': instance.get('project_id', ''),
                        'zone': instance.get('zone', ''),
                        'vm_name': instance.get('vm_name', ''),
                        'network_interface': instance.get('network_interface', ''),
                        'region': instance.get('region', '')
                    } if instance else None,
                    'remote_location': {
                        'continent': json_payload.get('remote_location', {}).get('continent', ''),
                        'country': json_payload.get('remote_location', {}).get('country', ''),
                        'region': json_payload.get('remote_location', {}).get('region', ''),
                        'city': json_payload.get('remote_location', {}).get('city', '')
                    } if json_payload.get('remote_location') else None
                },
                'project_id': labels.get('project_id', ''),
                'subnetwork_name': labels.get('subnetwork_name', '')
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_gke_audit_log(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GKE Audit Log"""
        proto_payload = raw_event.get('protoPayload', {})
        resource = raw_event.get('resource', {})
        labels = resource.get('labels', {})

        # Extract method and service
        method_name = proto_payload.get('methodName', '')
        service_name = proto_payload.get('serviceName', '')

        # Extract authentication info
        auth_info = proto_payload.get('authenticationInfo', {})
        principal_email = auth_info.get('principalEmail', '')

        # Extract request metadata
        request_metadata = proto_payload.get('requestMetadata', {})
        caller_ip = request_metadata.get('callerIp', '')

        # Extract Kubernetes-specific info
        resource_name = proto_payload.get('resourceName', '')
        request = proto_payload.get('request', {})
        response = proto_payload.get('response', {})

        # Parse Kubernetes resource info from resource name
        k8s_info = self._parse_k8s_resource_name(resource_name)

        # Determine outcome
        status = proto_payload.get('status', {})
        outcome = 'success' if status.get('code', 0) == 0 else 'failure'

        normalized = {
            '@timestamp': self._parse_timestamp(raw_event.get('timestamp', '')),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['process', 'configuration'],
                'type': self._get_event_type_from_method(method_name),
                'action': method_name,
                'outcome': outcome,
                'provider': 'gcp',
                'module': 'gke_audit_log',
                'id': raw_event.get('insertId', '')
            },

            'message': f"GKE: {principal_email} {method_name} on {resource_name}",

            'user': {
                'email': principal_email,
                'name': self._extract_username_from_email(principal_email)
            } if principal_email else None,

            'source': {
                'ip': caller_ip if caller_ip and caller_ip != 'private' else None
            } if caller_ip else None,

            'cloud': {
                'provider': 'gcp',
                'project': {
                    'id': labels.get('project_id', '')
                },
                'region': labels.get('location', '')
            },

            'orchestrator': {
                'type': 'kubernetes',
                'cluster': {
                    'name': labels.get('cluster_name', '')
                },
                'namespace': k8s_info.get('namespace', ''),
                'resource': {
                    'type': k8s_info.get('resource_type', ''),
                    'name': k8s_info.get('resource_name', '')
                }
            },

            'gcp': {
                'gke': {
                    'cluster_name': labels.get('cluster_name', ''),
                    'cluster_location': labels.get('location', ''),
                    'method_name': method_name,
                    'service_name': service_name,
                    'resource_name': resource_name,
                    'principal_email': principal_email,
                    'caller_ip': caller_ip,
                    'k8s_namespace': k8s_info.get('namespace', ''),
                    'k8s_resource_type': k8s_info.get('resource_type', ''),
                    'k8s_resource_name': k8s_info.get('resource_name', '')
                },
                'project_id': labels.get('project_id', '')
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_data_access_log(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GCP Data Access Log"""
        proto_payload = raw_event.get('protoPayload', {})
        resource = raw_event.get('resource', {})
        labels = resource.get('labels', {})

        # Extract method and service
        method_name = proto_payload.get('methodName', '')
        service_name = proto_payload.get('serviceName', '')
        resource_name = proto_payload.get('resourceName', '')

        # Extract authentication info
        auth_info = proto_payload.get('authenticationInfo', {})
        principal_email = auth_info.get('principalEmail', '')

        # Extract request metadata
        request_metadata = proto_payload.get('requestMetadata', {})
        caller_ip = request_metadata.get('callerIp', '')
        caller_user_agent = request_metadata.get('callerSuppliedUserAgent', '')

        # Extract status
        status = proto_payload.get('status', {})
        outcome = 'success' if status.get('code', 0) == 0 else 'failure'

        # Determine if this is a sensitive data access
        is_sensitive = self._is_sensitive_data_access(method_name, service_name)

        normalized = {
            '@timestamp': self._parse_timestamp(raw_event.get('timestamp', '')),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['database'],
                'type': ['access'],
                'action': method_name,
                'outcome': outcome,
                'provider': 'gcp',
                'module': 'data_access_log',
                'id': raw_event.get('insertId', '')
            },

            'message': f"Data Access: {principal_email} {method_name} on {resource_name}",

            'user': {
                'email': principal_email,
                'name': self._extract_username_from_email(principal_email)
            } if principal_email else None,

            'source': {
                'ip': caller_ip if caller_ip and caller_ip != 'private' else None
            } if caller_ip else None,

            'user_agent': {
                'original': caller_user_agent
            } if caller_user_agent else None,

            'cloud': {
                'provider': 'gcp',
                'project': {
                    'id': labels.get('project_id', '')
                },
                'service': {
                    'name': service_name
                }
            },

            'gcp': {
                'data_access': {
                    'method_name': method_name,
                    'service_name': service_name,
                    'resource_name': resource_name,
                    'principal_email': principal_email,
                    'caller_ip': caller_ip,
                    'is_sensitive': is_sensitive,
                    'num_response_items': proto_payload.get('numResponseItems', 0),
                    'resource_location': proto_payload.get('resourceLocation', {})
                },
                'project_id': labels.get('project_id', '')
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _parse_generic_log(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse generic/unknown GCP log entry"""
        resource = raw_event.get('resource', {})
        labels = resource.get('labels', {})

        # Try to get message from various payload types
        message = ''
        if 'textPayload' in raw_event:
            message = raw_event['textPayload']
        elif 'jsonPayload' in raw_event:
            message = raw_event['jsonPayload'].get('message', str(raw_event['jsonPayload']))
        elif 'protoPayload' in raw_event:
            message = raw_event['protoPayload'].get('methodName', 'GCP Event')

        normalized = {
            '@timestamp': self._parse_timestamp(raw_event.get('timestamp', '')),
            'ecs.version': '8.0.0',

            'event': {
                'kind': 'event',
                'category': ['host'],
                'type': ['info'],
                'action': 'log_entry',
                'outcome': 'unknown',
                'provider': 'gcp',
                'module': 'generic',
                'id': raw_event.get('insertId', ''),
                'severity': self.SEVERITY_MAP.get(raw_event.get('severity', 'INFO'), 'low')
            },

            'message': message[:1000] if message else 'GCP Log Entry',

            'cloud': {
                'provider': 'gcp',
                'project': {
                    'id': labels.get('project_id', '')
                }
            },

            'gcp': {
                'log_entry': {
                    'log_name': raw_event.get('logName', ''),
                    'resource_type': resource.get('type', ''),
                    'severity': raw_event.get('severity', ''),
                    'trace': raw_event.get('trace', ''),
                    'span_id': raw_event.get('spanId', ''),
                    'labels': labels
                }
            },

            '_raw': raw_event
        }

        return self._remove_none_values(normalized)

    def _get_method_category(self, method_name: str) -> List[str]:
        """Get ECS category from method name"""
        if not method_name:
            return ['host']

        lower_method = method_name.lower()

        for keyword, categories in self.METHOD_CATEGORY_MAP.items():
            if keyword in lower_method:
                return categories

        # Default categorization based on method prefixes
        if 'iam' in lower_method or 'policy' in lower_method:
            return ['iam']
        elif 'compute' in lower_method or 'instance' in lower_method:
            return ['host']
        elif 'storage' in lower_method or 'bucket' in lower_method:
            return ['file']
        elif 'network' in lower_method or 'firewall' in lower_method or 'vpc' in lower_method:
            return ['network']
        elif 'sql' in lower_method or 'database' in lower_method or 'bigquery' in lower_method:
            return ['database']
        else:
            return ['configuration']

    def _get_event_type_from_method(self, method: str) -> List[str]:
        """Determine ECS event.type from method name"""
        if not method:
            return ['info']

        lower_method = method.lower()

        if 'create' in lower_method or 'insert' in lower_method or 'add' in lower_method:
            return ['creation']
        elif 'delete' in lower_method or 'remove' in lower_method:
            return ['deletion']
        elif 'update' in lower_method or 'patch' in lower_method or 'set' in lower_method:
            return ['change']
        elif 'get' in lower_method or 'list' in lower_method or 'read' in lower_method:
            return ['access']
        elif 'start' in lower_method or 'enable' in lower_method:
            return ['start']
        elif 'stop' in lower_method or 'disable' in lower_method:
            return ['end']
        else:
            return ['info']

    def _extract_username_from_email(self, email: str) -> Optional[str]:
        """Extract username from email address"""
        if not email or '@' not in email:
            return None
        return email.split('@')[0]

    def _extract_domain_from_email(self, email: str) -> Optional[str]:
        """Extract domain from email address"""
        if not email or '@' not in email:
            return None
        return email.split('@')[-1]

    def _parse_k8s_resource_name(self, resource_name: str) -> Dict[str, str]:
        """Parse Kubernetes resource name from GKE audit log"""
        result = {
            'namespace': '',
            'resource_type': '',
            'resource_name': ''
        }

        if not resource_name:
            return result

        # Pattern: projects/.../locations/.../clusters/.../k8s/namespaces/NAMESPACE/TYPE/NAME
        parts = resource_name.split('/')
        if 'namespaces' in parts:
            ns_idx = parts.index('namespaces')
            if len(parts) > ns_idx + 1:
                result['namespace'] = parts[ns_idx + 1]
            if len(parts) > ns_idx + 2:
                result['resource_type'] = parts[ns_idx + 2]
            if len(parts) > ns_idx + 3:
                result['resource_name'] = parts[ns_idx + 3]

        return result

    def _is_sensitive_data_access(self, method_name: str, service_name: str) -> bool:
        """Determine if data access is sensitive"""
        sensitive_patterns = [
            'secrets', 'keys', 'credentials', 'passwords',
            'privatekey', 'certificate', 'token', 'apikey'
        ]

        lower_method = method_name.lower()
        lower_service = service_name.lower()

        return any(
            pattern in lower_method or pattern in lower_service
            for pattern in sensitive_patterns
        )

    def _build_audit_message(self, method: str, principal: str, resource: str) -> str:
        """Build human-readable message for audit log"""
        parts = []
        if principal:
            parts.append(principal)
        parts.append(method or 'performed action')
        if resource:
            parts.append(f"on {resource}")
        return ' '.join(parts)

    def _build_related_audit(self, principal: str, ip: str, resource: str) -> Dict[str, List[str]]:
        """Build related fields for audit log"""
        related = {'user': [], 'ip': []}
        if principal:
            related['user'].append(principal)
        if ip and ip != 'private':
            related['ip'].append(ip)
        return {k: v for k, v in related.items() if v}

    def _parse_timestamp(self, timestamp_str: str) -> str:
        """Parse and validate timestamp"""
        if not timestamp_str:
            return datetime.now(timezone.utc).isoformat()

        # Handle GCP timestamp formats
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

        # Handle nanosecond precision (GCP uses this)
        try:
            # Remove nanoseconds beyond microseconds
            if '.' in timestamp_str:
                base, frac = timestamp_str.rsplit('.', 1)
                # Keep only 6 digits for microseconds
                if 'Z' in frac:
                    frac = frac.replace('Z', '')[:6] + 'Z'
                elif '+' in frac:
                    frac_part, tz_part = frac.split('+')
                    frac = frac_part[:6] + '+' + tz_part
                else:
                    frac = frac[:6]
                timestamp_str = f"{base}.{frac}"
            return self._parse_timestamp(timestamp_str)
        except Exception:
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
        Validate that event has required GCP Cloud Logging fields.

        Args:
            event: Event to validate

        Returns:
            True if valid, False otherwise
        """
        # Must have timestamp
        if not event.get('timestamp') and not event.get('receiveTimestamp'):
            return False

        # Must have logName or be a valid log entry structure
        if 'logName' in event:
            return True

        # Check for payload types
        if any(key in event for key in ['protoPayload', 'jsonPayload', 'textPayload']):
            return True

        # Check for resource
        if 'resource' in event and 'type' in event.get('resource', {}):
            return True

        return False
