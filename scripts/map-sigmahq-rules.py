#!/usr/bin/env python3
"""Map SigmaHQ rules to Mantissa Log table schemas.

This script scans imported SigmaHQ rules and identifies field mappings
that need to be added to the Sigma pipeline configuration.
"""

import sys
import re
from pathlib import Path
from collections import defaultdict
from typing import Dict, Set, List, Optional

import yaml


# Table and field mappings (copied from sigma_pipeline to avoid import issues)
TABLE_MAPPINGS = {
    # AWS
    ("aws", "cloudtrail"): "cloudtrail",
    ("aws", "vpcflowlogs"): "vpc_flow_logs",
    ("aws", "guardduty"): "guardduty_findings",
    ("aws", "s3"): "s3_access_logs",

    # GCP
    ("gcp", "gcp.audit"): "gcp_audit_logs",
    ("gcp", "vpc"): "gcp_vpc_flow_logs",
    ("gcp", "google_workspace.admin"): "google_workspace_admin_logs",

    # Azure
    ("azure", "activitylogs"): "azure_activity_logs",
    ("azure", "auditlogs"): "azure_audit_logs",
    ("azure", "signinlogs"): "azure_signin_logs",
    ("azure", "pim"): "azure_pim_logs",
    ("azure", "riskdetection"): "azure_risk_detection",

    # M365
    ("m365", "audit"): "m365_audit_logs",
    ("m365", "exchange"): "m365_exchange_logs",
    ("m365", "threat_detection"): "m365_threat_detection",
    ("m365", "threat_management"): "m365_threat_management",

    # Identity
    ("okta", "okta"): "okta_system_logs",
    ("cisco", "duo"): "duo_auth_logs",

    # Applications
    ("kubernetes", "audit"): "k8s_audit_logs",
    ("github", "audit"): "github_audit_logs",
}

CLOUDTRAIL_FIELD_MAPPINGS = {
    # Top-level fields
    "eventName": "eventname",
    "eventSource": "eventsource",
    "eventType": "eventtype",
    "errorCode": "errorcode",
    "errorMessage": "errormessage",
    "sourceIPAddress": "sourceipaddress",
    "userAgent": "useragent",
    "requestParameters": "requestparameters",
    "responseElements": "responseelements",
    "additionalEventData": "additionaleventdata",
    "eventTime": "eventtime",

    # userIdentity nested fields
    "userIdentity.principalId": "useridentity.principalid",
    "userIdentity.type": "useridentity.type",
    "userIdentity.arn": "useridentity.arn",
    "userIdentity.userName": "useridentity.username",
    "userIdentity.sessionContext.sessionIssuer.type": "useridentity.sessioncontext.sessionissuer.type",

    # additionalEventData nested fields
    "additionalEventData.MFAUsed": "additionaleventdata.mfaused",

    # requestParameters nested fields
    "requestParameters.attribute": "requestparameters.attribute",
    "requestParameters.bucketName": "requestparameters.bucketname",
    "requestParameters.configRuleName": "requestparameters.configrulename",
    "requestParameters.containerDefinitions.command": "requestparameters.containerdefinitions.command",
    "requestParameters.detectorId": "requestparameters.detectorid",
    "requestParameters.groupId": "requestparameters.groupid",
    "requestParameters.layers": "requestparameters.layers",
    "requestParameters.name": "requestparameters.name",
    "requestParameters.serialNumber": "requestparameters.serialnumber",
    "requestParameters.userName": "requestparameters.username",
    "requestParameters.volumeId": "requestparameters.volumeid",
    "requestParameters.DeleteFlowLogsRequest.FlowLogId": "requestparameters.deleteflowlogsrequest.flowlogid",

    # responseElements nested fields
    "responseElements.ConsoleLogin": "responseelements.consolelogin",
    "responseElements.accessKey.accessKeyId": "responseelements.accesskey.accesskeyid",
    "responseElements.command.status": "responseelements.command.status",
    "responseElements.pendingModifiedValues.masterUserPassword": "responseelements.pendingmodifiedvalues.masteruserpassword",
    "responseElements.publiclyAccessible": "responseelements.publiclyaccessible",
}

VPC_FLOW_FIELD_MAPPINGS = {
    "srcaddr": "srcaddr",
    "dstaddr": "dstaddr",
    "srcport": "srcport",
    "dstport": "dstport",
    "protocol": "protocol",
    "packets": "packets",
    "bytes": "bytes",
    "start": "start_time",
    "end": "end_time",
    "action": "action",
    "log-status": "log_status",
}

GUARDDUTY_FIELD_MAPPINGS = {
    "id": "id",
    "type": "type",
    "severity": "severity",
    "title": "title",
    "description": "description",
    "resource.instanceDetails.instanceId": "resource.instancedetails.instanceid",
    "resource.instanceDetails.imageId": "resource.instancedetails.imageid",
    "service.action.actionType": "service.action.actiontype",
    "service.action.networkConnectionAction.remoteIpDetails.ipAddressV4": "service.action.networkconnectionaction.remoteipdetails.ipaddressv4",
}


def get_table_name(product: str, service: str) -> Optional[str]:
    """Get Mantissa table name for a given logsource."""
    return TABLE_MAPPINGS.get((product, service))


AZURE_ACTIVITYLOGS_FIELD_MAPPINGS = {
    "eventName": "eventname",
    "eventSource": "eventsource",
    "operationName": "operationname",
    "properties.message": "properties.message",
}

AZURE_AUDITLOGS_FIELD_MAPPINGS = {
    "activityType": "activitytype",
    "additionalDetails.additionalInfo": "additionaldetails.additionalinfo",
    "properties.message": "properties.message",
    "targetResources.type": "targetresources.type",
}

AZURE_SIGNINLOGS_FIELD_MAPPINGS = {
    "conditionalAccessStatus": "conditionalaccessstatus",
    "properties.message": "properties.message",
    "userAgent": "useragent",
}

AZURE_PIM_FIELD_MAPPINGS = {
    "riskEventType": "riskeventtype",
}

AZURE_RISKDETECTION_FIELD_MAPPINGS = {
    "riskEventType": "riskeventtype",
}

GCP_AUDIT_FIELD_MAPPINGS = {
    "data.protoPayload.authorizationInfo.granted": "data.protopayload.authorizationinfo.granted",
    "data.protoPayload.authorizationInfo.permission": "data.protopayload.authorizationinfo.permission",
    "data.protoPayload.logName": "data.protopayload.logname",
    "data.protoPayload.methodName": "data.protopayload.methodname",
    "data.protoPayload.resource.type": "data.protopayload.resource.type",
    "data.protoPayload.serviceName": "data.protopayload.servicename",
    "gcp.audit.method_name": "gcp.audit.method_name",
}

GOOGLE_WORKSPACE_ADMIN_FIELD_MAPPINGS = {
    "eventName": "eventname",
    "eventService": "eventservice",
}

M365_EXCHANGE_FIELD_MAPPINGS = {
    "eventName": "eventname",
    "eventSource": "eventsource",
}

M365_THREAT_DETECTION_FIELD_MAPPINGS = {
    "eventName": "eventname",
    "eventSource": "eventsource",
}

M365_THREAT_MANAGEMENT_FIELD_MAPPINGS = {
    "eventName": "eventname",
    "eventSource": "eventsource",
}

OKTA_FIELD_MAPPINGS = {
    "actor.alternateid": "actor.alternateid",
    "debugContext.debugData.requestUri": "debugcontext.debugdata.requesturi",
    "debugcontext.debugdata.behaviors": "debugcontext.debugdata.behaviors",
    "debugcontext.debugdata.logonlysecuritydata": "debugcontext.debugdata.logonlysecuritydata",
    "outcome.reason": "outcome.reason",
    "outcome.result": "outcome.result",
    "securityContext.isProxy": "securitycontext.isproxy",
    "securitycontext.isproxy": "securitycontext.isproxy",
    "target.displayname": "target.displayname",
}

KUBERNETES_AUDIT_FIELD_MAPPINGS = {
    "apiGroup": "apigroup",
    "hostPath": "hostpath",
    "objectRef.apiGroup": "objectref.apigroup",
    "objectRef.namespace": "objectref.namespace",
    "objectRef.resource": "objectref.resource",
    "objectRef.subresource": "objectref.subresource",
    "responseStatus.code": "responsestatus.code",
}


def get_field_mapping(product: str, service: str, field: str) -> str:
    """Get mapped field name for a given logsource and field."""
    # AWS
    if (product, service) == ("aws", "cloudtrail"):
        return CLOUDTRAIL_FIELD_MAPPINGS.get(field, field)
    elif (product, service) == ("aws", "vpcflowlogs"):
        return VPC_FLOW_FIELD_MAPPINGS.get(field, field)
    elif (product, service) == ("aws", "guardduty"):
        return GUARDDUTY_FIELD_MAPPINGS.get(field, field)

    # Azure
    elif (product, service) == ("azure", "activitylogs"):
        return AZURE_ACTIVITYLOGS_FIELD_MAPPINGS.get(field, field)
    elif (product, service) == ("azure", "auditlogs"):
        return AZURE_AUDITLOGS_FIELD_MAPPINGS.get(field, field)
    elif (product, service) == ("azure", "signinlogs"):
        return AZURE_SIGNINLOGS_FIELD_MAPPINGS.get(field, field)
    elif (product, service) == ("azure", "pim"):
        return AZURE_PIM_FIELD_MAPPINGS.get(field, field)
    elif (product, service) == ("azure", "riskdetection"):
        return AZURE_RISKDETECTION_FIELD_MAPPINGS.get(field, field)

    # GCP
    elif (product, service) == ("gcp", "gcp.audit"):
        return GCP_AUDIT_FIELD_MAPPINGS.get(field, field)
    elif (product, service) == ("gcp", "google_workspace.admin"):
        return GOOGLE_WORKSPACE_ADMIN_FIELD_MAPPINGS.get(field, field)

    # M365
    elif (product, service) == ("m365", "exchange"):
        return M365_EXCHANGE_FIELD_MAPPINGS.get(field, field)
    elif (product, service) == ("m365", "threat_detection"):
        return M365_THREAT_DETECTION_FIELD_MAPPINGS.get(field, field)
    elif (product, service) == ("m365", "threat_management"):
        return M365_THREAT_MANAGEMENT_FIELD_MAPPINGS.get(field, field)

    # Identity
    elif (product, service) == ("okta", "okta"):
        return OKTA_FIELD_MAPPINGS.get(field, field)

    # Applications
    elif (product, service) == ("kubernetes", "audit"):
        return KUBERNETES_AUDIT_FIELD_MAPPINGS.get(field, field)

    else:
        return field


def extract_fields_from_rule(rule_dict: dict) -> Set[str]:
    """Extract all field names used in a Sigma rule."""
    fields = set()

    def extract_from_dict(d: dict):
        """Recursively extract field names from dictionary."""
        for key, value in d.items():
            # Skip known non-field keys
            if key in ['condition', 'timeframe']:
                continue

            # Field names (not starting with uppercase or special chars)
            if isinstance(key, str) and not key[0].isupper() and '.' in key:
                fields.add(key.split('|')[0])  # Remove modifiers
            elif isinstance(key, str) and not key[0].isupper() and key not in [
                'selection', 'filter', 'keywords', 'condition', 'timeframe'
            ]:
                # Check if it looks like a field name
                if not key.startswith('selection_') and not key.startswith('filter_'):
                    fields.add(key.split('|')[0])

            # Recurse into nested dictionaries
            if isinstance(value, dict):
                extract_from_dict(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        extract_from_dict(item)

    if 'detection' in rule_dict:
        extract_from_dict(rule_dict['detection'])

    if 'fields' in rule_dict:
        for field in rule_dict['fields']:
            fields.add(field.split('|')[0])

    return fields


def analyze_rules(rules_dir: Path) -> Dict[str, Dict[str, Set[str]]]:
    """Analyze all rules and group fields by logsource."""
    logsource_fields = defaultdict(lambda: defaultdict(set))

    rule_files = list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))

    for rule_file in rule_files:
        try:
            with open(rule_file) as f:
                rule_dict = yaml.safe_load(f)

            if not rule_dict or 'logsource' not in rule_dict:
                continue

            logsource = rule_dict['logsource']
            product = logsource.get('product', 'unknown')
            service = logsource.get('service', 'unknown')

            fields = extract_fields_from_rule(rule_dict)

            logsource_key = f"{product}/{service}"
            logsource_fields[logsource_key]['product'] = product
            logsource_fields[logsource_key]['service'] = service
            logsource_fields[logsource_key]['fields'].update(fields)

        except Exception as e:
            print(f"Warning: Failed to analyze {rule_file}: {e}", file=sys.stderr)

    return logsource_fields


def check_field_mappings(product: str, service: str, fields: Set[str]) -> List[str]:
    """Check which fields are not yet mapped."""
    unmapped = []

    for field in sorted(fields):
        mapped = get_field_mapping(product, service, field)
        if mapped == field:  # No mapping found
            # Check if it's a simple lowercase field (likely already correct)
            if not re.match(r'^[a-z][a-z0-9_]*$', field):
                unmapped.append(field)

    return unmapped


def main():
    """Main analysis script."""
    repo_root = Path(__file__).parent.parent
    rules_dir = repo_root / "rules" / "sigma"

    if not rules_dir.exists():
        print(f"Error: Rules directory not found: {rules_dir}")
        sys.exit(1)

    print("Analyzing Sigma rules for field mappings...\n")

    logsource_fields = analyze_rules(rules_dir)

    print(f"Found {len(logsource_fields)} logsource types\n")
    print("="*80)

    # Analyze each logsource
    for logsource_key, data in sorted(logsource_fields.items()):
        product = data['product']
        service = data['service']
        fields = data['fields']

        print(f"\nLogsource: {logsource_key}")
        print(f"  Product: {product}")
        print(f"  Service: {service}")
        print(f"  Total fields: {len(fields)}")

        # Check table mapping
        table = get_table_name(product, service)
        if table:
            print(f"  Table: {table} ✓")
        else:
            print(f"  Table: NOT MAPPED ✗")

        # Check field mappings
        unmapped = check_field_mappings(product, service, fields)

        if unmapped:
            print(f"  Unmapped fields ({len(unmapped)}):")
            for field in unmapped[:10]:  # Show first 10
                print(f"    - {field}")
            if len(unmapped) > 10:
                print(f"    ... and {len(unmapped) - 10} more")
        else:
            print(f"  All fields mapped ✓")

    # Generate mapping suggestions
    print("\n" + "="*80)
    print("FIELD MAPPING SUGGESTIONS")
    print("="*80)

    for logsource_key, data in sorted(logsource_fields.items()):
        product = data['product']
        service = data['service']
        fields = data['fields']

        unmapped = check_field_mappings(product, service, fields)

        if unmapped:
            print(f"\n# {logsource_key}")
            print(f"{service.upper()}_FIELD_MAPPINGS = {{")
            for field in sorted(unmapped):
                # Suggest lowercase mapping
                suggested = field.lower().replace('.', '_')
                print(f'    "{field}": "{suggested}",')
            print("}")

    print("\n" + "="*80)
    print("Add these mappings to src/shared/detection/sigma_pipeline.py")
    print("="*80)


if __name__ == "__main__":
    main()
