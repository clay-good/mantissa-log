"""CloudTrail log parser."""

import json
from typing import Dict, List, Optional, Tuple

from .base import ParsedEvent, Parser, ParserError, handle_parse_errors, validate_required_fields
from .registry import register_parser


@register_parser
class CloudTrailParser(Parser):
    """Parser for AWS CloudTrail events."""

    @property
    def log_type(self) -> str:
        return "cloudtrail"

    @property
    def required_fields(self) -> List[str]:
        return ["eventTime", "eventName", "eventSource"]

    def validate(self, raw_event: str) -> bool:
        """Validate CloudTrail event structure.

        Args:
            raw_event: Raw CloudTrail event as JSON string

        Returns:
            True if valid CloudTrail event
        """
        try:
            data = json.loads(raw_event)
            return all(field in data for field in self.required_fields)
        except (json.JSONDecodeError, TypeError):
            return False

    @handle_parse_errors
    @validate_required_fields
    def parse(self, raw_event: str) -> ParsedEvent:
        """Parse CloudTrail event into normalized format.

        Args:
            raw_event: Raw CloudTrail event as JSON string

        Returns:
            ParsedEvent with normalized fields

        Raises:
            ParserError: If parsing fails
        """
        data = json.loads(raw_event)

        if data.get("eventName") == "Digest":
            raise ParserError(
                "Skipping CloudTrail digest file",
                parser_name=self.log_type,
                raw_event=raw_event,
            )

        timestamp = self.normalize_timestamp(data["eventTime"])
        user, user_type = self._extract_user_identity(data.get("userIdentity", {}))
        source_ip = data.get("sourceIPAddress")
        action = data["eventName"]
        result = self._determine_result(data)
        service = data["eventSource"].split(".")[0]

        metadata = {
            "event_type": data.get("eventType", "Unknown"),
            "user_type": user_type,
            "aws_region": data.get("awsRegion"),
            "user_agent": data.get("userAgent"),
            "request_id": data.get("requestID"),
            "event_id": data.get("eventID"),
            "error_code": data.get("errorCode"),
            "error_message": data.get("errorMessage"),
            "recipient_account_id": data.get("recipientAccountId"),
            "resources": self._extract_resources(data),
        }

        if "requestParameters" in data:
            metadata["request_parameters"] = data["requestParameters"]

        if "responseElements" in data:
            metadata["response_elements"] = data["responseElements"]

        if self._is_auth_event(action):
            metadata["is_auth_event"] = True
            if "additionalEventData" in data:
                metadata["mfa_used"] = data["additionalEventData"].get("MFAUsed", "No")

        return ParsedEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=None,
            user=user,
            action=action,
            result=result,
            service=service,
            raw_event=data,
            metadata=metadata,
        )

    def _extract_user_identity(self, identity: Dict) -> Tuple[str, str]:
        """Extract user name and type from userIdentity field.

        Args:
            identity: userIdentity dictionary

        Returns:
            Tuple of (user_name, user_type)
        """
        identity_type = identity.get("type", "Unknown")

        if identity_type == "Root":
            return "root", "Root"

        if identity_type == "IAMUser":
            return identity.get("userName", "Unknown"), "IAMUser"

        if identity_type == "AssumedRole":
            arn = identity.get("arn", "")
            session_context = identity.get("sessionContext", {})
            session_issuer = session_context.get("sessionIssuer", {})

            role_name = session_issuer.get("userName", "")
            if not role_name and arn:
                parts = arn.split("/")
                if len(parts) >= 2:
                    role_name = parts[1]

            return role_name or "Unknown", "AssumedRole"

        if identity_type == "FederatedUser":
            return identity.get("userName", "Unknown"), "FederatedUser"

        if identity_type == "AWSService":
            return identity.get("invokedBy", "Unknown"), "AWSService"

        if identity_type == "AWSAccount":
            return identity.get("accountId", "Unknown"), "AWSAccount"

        return "Unknown", identity_type

    def _determine_result(self, event: Dict) -> str:
        """Determine if event succeeded or failed.

        Args:
            event: CloudTrail event dictionary

        Returns:
            'success', 'failure', or 'unknown'
        """
        if "errorCode" in event:
            return "failure"

        if event.get("eventType") == "AwsApiCall":
            return "success"

        if event.get("eventName") == "ConsoleLogin":
            response_elements = event.get("responseElements", {})
            if isinstance(response_elements, dict):
                if response_elements.get("ConsoleLogin") == "Success":
                    return "success"
                if response_elements.get("ConsoleLogin") == "Failure":
                    return "failure"

        return "success" if "errorCode" not in event else "unknown"

    def _is_auth_event(self, event_name: str) -> bool:
        """Check if event is authentication-related.

        Args:
            event_name: CloudTrail event name

        Returns:
            True if authentication event
        """
        auth_events = {
            "ConsoleLogin",
            "AssumeRole",
            "AssumeRoleWithSAML",
            "AssumeRoleWithWebIdentity",
            "GetSessionToken",
            "GetFederationToken",
            "CreateAccessKey",
            "UpdateAccessKey",
            "DeleteAccessKey",
            "ChangePassword",
            "CreateUser",
            "DeleteUser",
            "EnableMFADevice",
            "DeactivateMFADevice",
        }
        return event_name in auth_events

    def _extract_resources(self, event: Dict) -> List[Dict]:
        """Extract resource information from event.

        Args:
            event: CloudTrail event dictionary

        Returns:
            List of resource dictionaries
        """
        resources = event.get("resources", [])
        if not resources:
            return []

        return [
            {
                "arn": resource.get("ARN"),
                "account_id": resource.get("accountId"),
                "type": resource.get("type"),
            }
            for resource in resources
        ]
