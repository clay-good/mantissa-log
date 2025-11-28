"""GuardDuty findings parser."""

import json
from typing import Dict, List

from .base import ParsedEvent, Parser, ParserError, handle_parse_errors, validate_required_fields
from .registry import register_parser


@register_parser
class GuardDutyParser(Parser):
    """Parser for AWS GuardDuty findings."""

    @property
    def log_type(self) -> str:
        return "guardduty"

    @property
    def required_fields(self) -> List[str]:
        return ["id", "type", "severity", "createdAt"]

    def validate(self, raw_event: str) -> bool:
        """Validate GuardDuty finding structure.

        Args:
            raw_event: Raw GuardDuty finding as JSON string

        Returns:
            True if valid GuardDuty finding
        """
        try:
            data = json.loads(raw_event)
            return all(field in data for field in self.required_fields)
        except (json.JSONDecodeError, TypeError):
            return False

    @handle_parse_errors
    @validate_required_fields
    def parse(self, raw_event: str) -> ParsedEvent:
        """Parse GuardDuty finding into normalized format.

        Args:
            raw_event: Raw GuardDuty finding as JSON string

        Returns:
            ParsedEvent with normalized fields

        Raises:
            ParserError: If parsing fails
        """
        data = json.loads(raw_event)

        timestamp = self.normalize_timestamp(data["createdAt"])
        finding_type = data["type"]
        severity = data["severity"]
        finding_id = data["id"]

        source_ip, destination_ip = self._extract_network_info(data)
        user = self._extract_principal(data)

        severity_level = self._map_severity(severity)

        metadata = {
            "finding_id": finding_id,
            "finding_type": finding_type,
            "severity": severity,
            "severity_level": severity_level,
            "title": data.get("title"),
            "description": data.get("description"),
            "account_id": data.get("accountId"),
            "region": data.get("region"),
            "partition": data.get("partition"),
            "arn": data.get("arn"),
            "schema_version": data.get("schemaVersion"),
            "resource": self._extract_resource_info(data),
            "service": self._extract_service_info(data),
            "updated_at": data.get("updatedAt"),
        }

        return ParsedEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=destination_ip,
            user=user,
            action=f"guardduty_finding_{finding_type}",
            result="failure",
            service="guardduty",
            raw_event=data,
            metadata=metadata,
        )

    def _extract_network_info(self, finding: Dict) -> tuple:
        """Extract source and destination IP from finding.

        Args:
            finding: GuardDuty finding dictionary

        Returns:
            Tuple of (source_ip, destination_ip)
        """
        source_ip = None
        dest_ip = None

        service = finding.get("service", {})
        action = service.get("action", {})

        if "networkConnectionAction" in action:
            network = action["networkConnectionAction"]
            source_ip = self.safe_get(network, "remoteIpDetails.ipAddressV4")
            dest_ip = self.safe_get(network, "localIpDetails.ipAddressV4")

        elif "awsApiCallAction" in action:
            api_call = action["awsApiCallAction"]
            source_ip = self.safe_get(api_call, "remoteIpDetails.ipAddressV4")

        elif "portProbeAction" in action:
            port_probe = action["portProbeAction"]
            if "portProbeDetails" in port_probe:
                details = port_probe["portProbeDetails"]
                if details and len(details) > 0:
                    source_ip = self.safe_get(
                        details[0], "remoteIpDetails.ipAddressV4"
                    )

        return source_ip, dest_ip

    def _extract_principal(self, finding: Dict) -> str:
        """Extract user/principal from finding.

        Args:
            finding: GuardDuty finding dictionary

        Returns:
            Principal identifier or None
        """
        service = finding.get("service", {})
        action = service.get("action", {})

        if "awsApiCallAction" in action:
            api_call = action["awsApiCallAction"]
            user_type = self.safe_get(
                api_call, "userDetails.userIdentity.type", "Unknown"
            )
            if user_type == "IAMUser":
                return self.safe_get(api_call, "userDetails.userIdentity.userName")
            elif user_type == "AssumedRole":
                return self.safe_get(api_call, "userDetails.userIdentity.arn")

        resource = finding.get("resource", {})
        if "accessKeyDetails" in resource:
            return self.safe_get(resource, "accessKeyDetails.userName")

        return None

    def _extract_resource_info(self, finding: Dict) -> Dict:
        """Extract resource information from finding.

        Args:
            finding: GuardDuty finding dictionary

        Returns:
            Dictionary of resource information
        """
        resource = finding.get("resource", {})
        resource_type = resource.get("resourceType")

        resource_info = {
            "type": resource_type,
        }

        if resource_type == "Instance":
            instance_details = resource.get("instanceDetails", {})
            resource_info.update(
                {
                    "instance_id": instance_details.get("instanceId"),
                    "instance_type": instance_details.get("instanceType"),
                    "availability_zone": instance_details.get("availabilityZone"),
                    "image_id": instance_details.get("imageId"),
                    "tags": instance_details.get("tags", []),
                }
            )

        elif resource_type == "AccessKey":
            access_key_details = resource.get("accessKeyDetails", {})
            resource_info.update(
                {
                    "access_key_id": access_key_details.get("accessKeyId"),
                    "principal_id": access_key_details.get("principalId"),
                    "user_name": access_key_details.get("userName"),
                    "user_type": access_key_details.get("userType"),
                }
            )

        elif resource_type == "S3Bucket":
            s3_bucket_details = resource.get("s3BucketDetails", [])
            if s3_bucket_details:
                resource_info.update(
                    {
                        "bucket_name": s3_bucket_details[0].get("name"),
                        "bucket_arn": s3_bucket_details[0].get("arn"),
                        "bucket_type": s3_bucket_details[0].get("type"),
                    }
                )

        return resource_info

    def _extract_service_info(self, finding: Dict) -> Dict:
        """Extract service information from finding.

        Args:
            finding: GuardDuty finding dictionary

        Returns:
            Dictionary of service information
        """
        service = finding.get("service", {})

        service_info = {
            "archived": service.get("archived"),
            "count": service.get("count"),
            "detector_id": service.get("detectorId"),
            "event_first_seen": service.get("eventFirstSeen"),
            "event_last_seen": service.get("eventLastSeen"),
            "resource_role": service.get("resourceRole"),
            "service_name": service.get("serviceName"),
        }

        if "action" in service:
            action = service["action"]
            action_type = action.get("actionType")
            service_info["action_type"] = action_type

        return service_info

    def _map_severity(self, severity: float) -> str:
        """Map numeric severity to level.

        Args:
            severity: Numeric severity (0-10)

        Returns:
            Severity level string
        """
        if severity >= 7.0:
            return "HIGH"
        elif severity >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
