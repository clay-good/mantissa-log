"""Sigma pipeline configuration for Mantissa Log table and field mappings.

This module provides custom Sigma pipelines to map Sigma logsources and field names
to Mantissa Log's specific table and column schemas.
"""

from typing import Dict, List, Optional

try:
    from sigma.processing.transformations import (
        FieldMappingTransformation,
        DetectionItemFailureTransformation,
        RuleFailureTransformation,
    )
    from sigma.processing.conditions import (
        LogsourceCondition,
        IncludeFieldCondition,
        ExcludeFieldCondition,
    )
    from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
    SIGMA_AVAILABLE = True
except ImportError:
    SIGMA_AVAILABLE = False
    ProcessingPipeline = None
    ProcessingItem = None


class MantissaLogPipeline:
    """Sigma pipeline configuration for Mantissa Log table and field mappings."""

    # Table mapping from Sigma logsources to Mantissa tables
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

    # Field mappings for AWS CloudTrail
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

    # Field mappings for AWS VPC Flow Logs
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

    # Field mappings for AWS GuardDuty
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

    # Field mappings for Azure Activity Logs
    AZURE_ACTIVITYLOGS_FIELD_MAPPINGS = {
        "eventName": "eventname",
        "eventSource": "eventsource",
        "operationName": "operationname",
        "properties.message": "properties.message",
    }

    # Field mappings for Azure Audit Logs
    AZURE_AUDITLOGS_FIELD_MAPPINGS = {
        "activityType": "activitytype",
        "additionalDetails.additionalInfo": "additionaldetails.additionalinfo",
        "properties.message": "properties.message",
        "targetResources.type": "targetresources.type",
    }

    # Field mappings for Azure Sign-in Logs
    AZURE_SIGNINLOGS_FIELD_MAPPINGS = {
        "conditionalAccessStatus": "conditionalaccessstatus",
        "properties.message": "properties.message",
        "userAgent": "useragent",
    }

    # Field mappings for Azure PIM
    AZURE_PIM_FIELD_MAPPINGS = {
        "riskEventType": "riskeventtype",
    }

    # Field mappings for Azure Risk Detection
    AZURE_RISKDETECTION_FIELD_MAPPINGS = {
        "riskEventType": "riskeventtype",
    }

    # Field mappings for GCP Audit Logs
    GCP_AUDIT_FIELD_MAPPINGS = {
        "data.protoPayload.authorizationInfo.granted": "data.protopayload.authorizationinfo.granted",
        "data.protoPayload.authorizationInfo.permission": "data.protopayload.authorizationinfo.permission",
        "data.protoPayload.logName": "data.protopayload.logname",
        "data.protoPayload.methodName": "data.protopayload.methodname",
        "data.protoPayload.resource.type": "data.protopayload.resource.type",
        "data.protoPayload.serviceName": "data.protopayload.servicename",
        "gcp.audit.method_name": "gcp.audit.method_name",
    }

    # Field mappings for Google Workspace Admin
    GOOGLE_WORKSPACE_ADMIN_FIELD_MAPPINGS = {
        "eventName": "eventname",
        "eventService": "eventservice",
    }

    # Field mappings for M365 Exchange
    M365_EXCHANGE_FIELD_MAPPINGS = {
        "eventName": "eventname",
        "eventSource": "eventsource",
    }

    # Field mappings for M365 Threat Detection
    M365_THREAT_DETECTION_FIELD_MAPPINGS = {
        "eventName": "eventname",
        "eventSource": "eventsource",
    }

    # Field mappings for M365 Threat Management
    M365_THREAT_MANAGEMENT_FIELD_MAPPINGS = {
        "eventName": "eventname",
        "eventSource": "eventsource",
    }

    # Field mappings for Okta
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

    # Field mappings for Kubernetes Audit
    KUBERNETES_AUDIT_FIELD_MAPPINGS = {
        "apiGroup": "apigroup",
        "hostPath": "hostpath",
        "objectRef.apiGroup": "objectref.apigroup",
        "objectRef.namespace": "objectref.namespace",
        "objectRef.resource": "objectref.resource",
        "objectRef.subresource": "objectref.subresource",
        "responseStatus.code": "responsestatus.code",
    }

    @classmethod
    def create_pipeline(cls, backend: str = "athena") -> Optional[ProcessingPipeline]:
        """Create a Sigma processing pipeline for Mantissa Log.

        Args:
            backend: Backend type (athena, bigquery, synapse)

        Returns:
            ProcessingPipeline configured for Mantissa Log

        Raises:
            ImportError: If Sigma is not available
        """
        if not SIGMA_AVAILABLE:
            raise ImportError("Sigma processing pipeline requires pySigma to be installed")

        processing_items = []

        # CloudTrail field mappings
        processing_items.append(
            ProcessingItem(
                identifier="mantissa-cloudtrail-field-mapping",
                transformation=FieldMappingTransformation(cls.CLOUDTRAIL_FIELD_MAPPINGS),
                rule_conditions=[
                    LogsourceCondition(product="aws", service="cloudtrail")
                ],
            )
        )

        # VPC Flow Logs field mappings
        processing_items.append(
            ProcessingItem(
                identifier="mantissa-vpcflow-field-mapping",
                transformation=FieldMappingTransformation(cls.VPC_FLOW_FIELD_MAPPINGS),
                rule_conditions=[
                    LogsourceCondition(product="aws", service="vpcflowlogs")
                ],
            )
        )

        # GuardDuty field mappings
        processing_items.append(
            ProcessingItem(
                identifier="mantissa-guardduty-field-mapping",
                transformation=FieldMappingTransformation(cls.GUARDDUTY_FIELD_MAPPINGS),
                rule_conditions=[
                    LogsourceCondition(product="aws", service="guardduty")
                ],
            )
        )

        # Azure field mappings
        processing_items.extend([
            ProcessingItem(
                identifier="mantissa-azure-activitylogs-field-mapping",
                transformation=FieldMappingTransformation(cls.AZURE_ACTIVITYLOGS_FIELD_MAPPINGS),
                rule_conditions=[LogsourceCondition(product="azure", service="activitylogs")],
            ),
            ProcessingItem(
                identifier="mantissa-azure-auditlogs-field-mapping",
                transformation=FieldMappingTransformation(cls.AZURE_AUDITLOGS_FIELD_MAPPINGS),
                rule_conditions=[LogsourceCondition(product="azure", service="auditlogs")],
            ),
            ProcessingItem(
                identifier="mantissa-azure-signinlogs-field-mapping",
                transformation=FieldMappingTransformation(cls.AZURE_SIGNINLOGS_FIELD_MAPPINGS),
                rule_conditions=[LogsourceCondition(product="azure", service="signinlogs")],
            ),
            ProcessingItem(
                identifier="mantissa-azure-pim-field-mapping",
                transformation=FieldMappingTransformation(cls.AZURE_PIM_FIELD_MAPPINGS),
                rule_conditions=[LogsourceCondition(product="azure", service="pim")],
            ),
            ProcessingItem(
                identifier="mantissa-azure-riskdetection-field-mapping",
                transformation=FieldMappingTransformation(cls.AZURE_RISKDETECTION_FIELD_MAPPINGS),
                rule_conditions=[LogsourceCondition(product="azure", service="riskdetection")],
            ),
        ])

        # GCP field mappings
        processing_items.extend([
            ProcessingItem(
                identifier="mantissa-gcp-audit-field-mapping",
                transformation=FieldMappingTransformation(cls.GCP_AUDIT_FIELD_MAPPINGS),
                rule_conditions=[LogsourceCondition(product="gcp", service="gcp.audit")],
            ),
            ProcessingItem(
                identifier="mantissa-gworkspace-admin-field-mapping",
                transformation=FieldMappingTransformation(cls.GOOGLE_WORKSPACE_ADMIN_FIELD_MAPPINGS),
                rule_conditions=[LogsourceCondition(product="gcp", service="google_workspace.admin")],
            ),
        ])

        # M365 field mappings
        processing_items.extend([
            ProcessingItem(
                identifier="mantissa-m365-exchange-field-mapping",
                transformation=FieldMappingTransformation(cls.M365_EXCHANGE_FIELD_MAPPINGS),
                rule_conditions=[LogsourceCondition(product="m365", service="exchange")],
            ),
            ProcessingItem(
                identifier="mantissa-m365-threat-detection-field-mapping",
                transformation=FieldMappingTransformation(cls.M365_THREAT_DETECTION_FIELD_MAPPINGS),
                rule_conditions=[LogsourceCondition(product="m365", service="threat_detection")],
            ),
            ProcessingItem(
                identifier="mantissa-m365-threat-management-field-mapping",
                transformation=FieldMappingTransformation(cls.M365_THREAT_MANAGEMENT_FIELD_MAPPINGS),
                rule_conditions=[LogsourceCondition(product="m365", service="threat_management")],
            ),
        ])

        # Identity provider field mappings
        processing_items.extend([
            ProcessingItem(
                identifier="mantissa-okta-field-mapping",
                transformation=FieldMappingTransformation(cls.OKTA_FIELD_MAPPINGS),
                rule_conditions=[LogsourceCondition(product="okta", service="okta")],
            ),
        ])

        # Application field mappings
        processing_items.extend([
            ProcessingItem(
                identifier="mantissa-kubernetes-audit-field-mapping",
                transformation=FieldMappingTransformation(cls.KUBERNETES_AUDIT_FIELD_MAPPINGS),
                rule_conditions=[LogsourceCondition(product="kubernetes", service="audit")],
            ),
        ])

        return ProcessingPipeline(
            name="mantissa-log-pipeline",
            priority=50,
            items=processing_items,
        )

    @classmethod
    def get_table_name(cls, product: str, service: str) -> Optional[str]:
        """Get Mantissa table name for a given logsource.

        Args:
            product: Sigma product (e.g., 'aws', 'gcp')
            service: Sigma service (e.g., 'cloudtrail', 'vpcflowlogs')

        Returns:
            Table name or None if not found
        """
        return cls.TABLE_MAPPINGS.get((product, service))

    @classmethod
    def get_field_mapping(cls, product: str, service: str, field: str) -> str:
        """Get mapped field name for a given logsource and field.

        Args:
            product: Sigma product
            service: Sigma service
            field: Original Sigma field name

        Returns:
            Mapped field name or original if no mapping exists
        """
        # AWS
        if (product, service) == ("aws", "cloudtrail"):
            return cls.CLOUDTRAIL_FIELD_MAPPINGS.get(field, field)
        elif (product, service) == ("aws", "vpcflowlogs"):
            return cls.VPC_FLOW_FIELD_MAPPINGS.get(field, field)
        elif (product, service) == ("aws", "guardduty"):
            return cls.GUARDDUTY_FIELD_MAPPINGS.get(field, field)

        # Azure
        elif (product, service) == ("azure", "activitylogs"):
            return cls.AZURE_ACTIVITYLOGS_FIELD_MAPPINGS.get(field, field)
        elif (product, service) == ("azure", "auditlogs"):
            return cls.AZURE_AUDITLOGS_FIELD_MAPPINGS.get(field, field)
        elif (product, service) == ("azure", "signinlogs"):
            return cls.AZURE_SIGNINLOGS_FIELD_MAPPINGS.get(field, field)
        elif (product, service) == ("azure", "pim"):
            return cls.AZURE_PIM_FIELD_MAPPINGS.get(field, field)
        elif (product, service) == ("azure", "riskdetection"):
            return cls.AZURE_RISKDETECTION_FIELD_MAPPINGS.get(field, field)

        # GCP
        elif (product, service) == ("gcp", "gcp.audit"):
            return cls.GCP_AUDIT_FIELD_MAPPINGS.get(field, field)
        elif (product, service) == ("gcp", "google_workspace.admin"):
            return cls.GOOGLE_WORKSPACE_ADMIN_FIELD_MAPPINGS.get(field, field)

        # M365
        elif (product, service) == ("m365", "exchange"):
            return cls.M365_EXCHANGE_FIELD_MAPPINGS.get(field, field)
        elif (product, service) == ("m365", "threat_detection"):
            return cls.M365_THREAT_DETECTION_FIELD_MAPPINGS.get(field, field)
        elif (product, service) == ("m365", "threat_management"):
            return cls.M365_THREAT_MANAGEMENT_FIELD_MAPPINGS.get(field, field)

        # Identity
        elif (product, service) == ("okta", "okta"):
            return cls.OKTA_FIELD_MAPPINGS.get(field, field)

        # Applications
        elif (product, service) == ("kubernetes", "audit"):
            return cls.KUBERNETES_AUDIT_FIELD_MAPPINGS.get(field, field)

        else:
            return field

    @classmethod
    def add_custom_mapping(
        cls,
        product: str,
        service: str,
        table_name: str,
        field_mappings: Optional[Dict[str, str]] = None
    ) -> None:
        """Add custom table and field mappings.

        Args:
            product: Sigma product name
            service: Sigma service name
            table_name: Mantissa table name
            field_mappings: Optional dictionary of field mappings
        """
        cls.TABLE_MAPPINGS[(product, service)] = table_name

        if field_mappings:
            # Store custom field mappings (extend this as needed)
            # For now, we'll need to extend the class with custom mapping dictionaries
            pass


def get_mantissa_pipeline(backend: str = "athena") -> Optional[ProcessingPipeline]:
    """Get Sigma processing pipeline configured for Mantissa Log.

    Args:
        backend: Backend type (athena, bigquery, synapse)

    Returns:
        ProcessingPipeline or None if Sigma not available
    """
    if not SIGMA_AVAILABLE:
        return None

    return MantissaLogPipeline.create_pipeline(backend)


def get_table_for_logsource(product: str, service: str) -> Optional[str]:
    """Helper function to get table name for a logsource.

    Args:
        product: Sigma product
        service: Sigma service

    Returns:
        Table name or None
    """
    return MantissaLogPipeline.get_table_name(product, service)
