"""Generic webhook alert handler with response handling and retry support."""

import hashlib
import hmac
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Pattern, Union

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .base import AlertHandler
from ...detection.alert_generator import Alert

logger = logging.getLogger(__name__)


class RetryStrategy(Enum):
    """Retry strategies for failed webhook calls."""
    NONE = "none"
    FIXED = "fixed"
    EXPONENTIAL = "exponential"


class ResponseAction(Enum):
    """Actions to take based on webhook response."""
    SUCCESS = "success"
    RETRY = "retry"
    FAIL = "fail"
    CALLBACK = "callback"


@dataclass
class WebhookResponse:
    """Parsed webhook response."""
    success: bool
    status_code: int
    raw_body: str
    parsed_body: Optional[Dict[str, Any]] = None
    headers: Dict[str, str] = field(default_factory=dict)
    response_time_ms: float = 0
    error_message: Optional[str] = None
    external_id: Optional[str] = None
    external_url: Optional[str] = None


@dataclass
class ResponseMapping:
    """Mapping for extracting data from webhook responses."""
    field_path: str  # JSON path like "data.id" or "result.ticket_number"
    target: str  # Where to store: external_id, external_url, error_message
    transform: Optional[Callable[[Any], str]] = None


@dataclass
class RetryConfig:
    """Configuration for webhook retries."""
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    max_retries: int = 3
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 60.0
    retry_on_status_codes: List[int] = field(default_factory=lambda: [429, 500, 502, 503, 504])
    retry_on_timeout: bool = True


@dataclass
class ResponseHandlerConfig:
    """Configuration for response handling."""
    success_status_codes: List[int] = field(default_factory=lambda: [200, 201, 202, 204])
    success_body_pattern: Optional[str] = None  # Regex pattern to match in response body
    error_body_pattern: Optional[str] = None  # Regex pattern indicating error
    field_mappings: List[ResponseMapping] = field(default_factory=list)
    on_success_callback: Optional[Callable[[Alert, WebhookResponse], None]] = None
    on_failure_callback: Optional[Callable[[Alert, WebhookResponse], None]] = None


class WebhookHandler(AlertHandler):
    """Enhanced handler for sending alerts to generic HTTP webhooks.

    Features:
    - Configurable retry strategies with exponential backoff
    - Response parsing and field extraction
    - Custom field mapping for external IDs and URLs
    - Signature-based authentication (HMAC)
    - Request/response logging
    - Callback hooks for success/failure handling
    """

    def __init__(
        self,
        webhook_url: str,
        headers: Optional[Dict[str, str]] = None,
        method: str = "POST",
        timeout: int = 30,
        payload_format: str = "json",
        payload_template: Optional[Dict[str, Any]] = None,
        field_mapping: Optional[Dict[str, str]] = None,
        retry_config: Optional[RetryConfig] = None,
        response_config: Optional[ResponseHandlerConfig] = None,
        signing_secret: Optional[str] = None,
        signing_header: str = "X-Webhook-Signature",
        signing_algorithm: str = "sha256"
    ):
        """Initialize webhook handler.

        Args:
            webhook_url: Webhook URL
            headers: Optional custom headers
            method: HTTP method (POST, PUT, PATCH)
            timeout: Request timeout in seconds
            payload_format: Payload format ('json' or 'form')
            payload_template: Custom payload template with {{field}} placeholders
            field_mapping: Map alert fields to custom payload fields
            retry_config: Retry configuration
            response_config: Response handling configuration
            signing_secret: Secret for HMAC signature
            signing_header: Header name for signature
            signing_algorithm: Hash algorithm for signature (sha256, sha1)
        """
        self.webhook_url = webhook_url
        self.headers = headers or {"Content-Type": "application/json"}
        self.method = method.upper()
        self.timeout = timeout
        self.payload_format = payload_format
        self.payload_template = payload_template
        self.field_mapping = field_mapping or {}
        self.retry_config = retry_config or RetryConfig()
        self.response_config = response_config or ResponseHandlerConfig()
        self.signing_secret = signing_secret
        self.signing_header = signing_header
        self.signing_algorithm = signing_algorithm

        # Setup session with retry
        self._session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create requests session with retry adapter.

        Returns:
            Configured session
        """
        session = requests.Session()

        if self.retry_config.strategy != RetryStrategy.NONE:
            retry = Retry(
                total=self.retry_config.max_retries,
                backoff_factor=self.retry_config.base_delay_seconds,
                status_forcelist=self.retry_config.retry_on_status_codes,
                allowed_methods=["POST", "PUT", "PATCH"]
            )
            adapter = HTTPAdapter(max_retries=retry)
            session.mount("http://", adapter)
            session.mount("https://", adapter)

        return session

    def validate_config(self) -> bool:
        """Validate webhook configuration.

        Returns:
            True if configuration is valid
        """
        return bool(
            self.webhook_url and
            self.webhook_url.startswith(("http://", "https://")) and
            self.method in ["POST", "PUT", "PATCH"]
        )

    def send(self, alert: Alert) -> bool:
        """Send alert to webhook with retry and response handling.

        Args:
            alert: Alert to send

        Returns:
            True if successful
        """
        response = self.send_with_response(alert)
        return response.success

    def send_with_response(self, alert: Alert) -> WebhookResponse:
        """Send alert and return detailed response.

        Args:
            alert: Alert to send

        Returns:
            WebhookResponse with parsed details
        """
        payload = self.format_alert(alert)
        headers = self._prepare_headers(payload)

        start_time = time.time()
        last_error = None

        for attempt in range(self.retry_config.max_retries + 1):
            try:
                response = self._make_request(payload, headers)
                response_time = (time.time() - start_time) * 1000

                webhook_response = self._parse_response(response, response_time)

                # Check if response indicates success
                action = self._determine_action(webhook_response)

                if action == ResponseAction.SUCCESS:
                    logger.info(
                        f"Webhook success for alert {alert.id}: "
                        f"status={webhook_response.status_code}, "
                        f"time={webhook_response.response_time_ms:.0f}ms"
                    )
                    if self.response_config.on_success_callback:
                        self.response_config.on_success_callback(alert, webhook_response)
                    return webhook_response

                elif action == ResponseAction.RETRY:
                    if attempt < self.retry_config.max_retries:
                        delay = self._calculate_delay(attempt)
                        logger.warning(
                            f"Webhook retry {attempt + 1}/{self.retry_config.max_retries} "
                            f"for alert {alert.id} after {delay:.1f}s"
                        )
                        time.sleep(delay)
                        continue

                # If we get here, it's a failure
                logger.error(
                    f"Webhook failed for alert {alert.id}: "
                    f"status={webhook_response.status_code}, "
                    f"error={webhook_response.error_message}"
                )
                if self.response_config.on_failure_callback:
                    self.response_config.on_failure_callback(alert, webhook_response)
                return webhook_response

            except requests.exceptions.Timeout as e:
                last_error = f"Timeout after {self.timeout}s"
                if self.retry_config.retry_on_timeout and attempt < self.retry_config.max_retries:
                    delay = self._calculate_delay(attempt)
                    logger.warning(f"Webhook timeout, retrying in {delay:.1f}s")
                    time.sleep(delay)
                    continue

            except requests.exceptions.RequestException as e:
                last_error = str(e)
                logger.error(f"Webhook request error: {e}")

        # All retries exhausted
        response_time = (time.time() - start_time) * 1000
        failed_response = WebhookResponse(
            success=False,
            status_code=0,
            raw_body="",
            response_time_ms=response_time,
            error_message=last_error or "Max retries exhausted"
        )

        if self.response_config.on_failure_callback:
            self.response_config.on_failure_callback(alert, failed_response)

        return failed_response

    def _prepare_headers(self, payload: Dict) -> Dict[str, str]:
        """Prepare request headers including signature.

        Args:
            payload: Request payload

        Returns:
            Headers dict
        """
        headers = self.headers.copy()

        # Add signature if configured
        if self.signing_secret:
            payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
            signature = self._generate_signature(payload_bytes)
            headers[self.signing_header] = signature

        return headers

    def _generate_signature(self, payload: bytes) -> str:
        """Generate HMAC signature for payload.

        Args:
            payload: Request payload bytes

        Returns:
            Signature string
        """
        if self.signing_algorithm == "sha256":
            digest = hmac.new(
                self.signing_secret.encode(),
                payload,
                hashlib.sha256
            ).hexdigest()
        else:  # sha1
            digest = hmac.new(
                self.signing_secret.encode(),
                payload,
                hashlib.sha1
            ).hexdigest()

        return f"{self.signing_algorithm}={digest}"

    def _make_request(self, payload: Dict, headers: Dict) -> requests.Response:
        """Make HTTP request.

        Args:
            payload: Request payload
            headers: Request headers

        Returns:
            Response object
        """
        if self.payload_format == "json":
            kwargs = {"json": payload}
        else:
            kwargs = {"data": payload}

        return self._session.request(
            method=self.method,
            url=self.webhook_url,
            headers=headers,
            timeout=self.timeout,
            **kwargs
        )

    def _parse_response(self, response: requests.Response, response_time: float) -> WebhookResponse:
        """Parse webhook response.

        Args:
            response: HTTP response
            response_time: Response time in milliseconds

        Returns:
            Parsed WebhookResponse
        """
        raw_body = response.text

        # Try to parse JSON body
        parsed_body = None
        try:
            parsed_body = response.json()
        except (json.JSONDecodeError, ValueError):
            pass

        # Extract mapped fields
        external_id = None
        external_url = None
        error_message = None

        for mapping in self.response_config.field_mappings:
            value = self._extract_field(parsed_body, mapping.field_path)
            if value is not None:
                if mapping.transform:
                    value = mapping.transform(value)
                else:
                    value = str(value)

                if mapping.target == "external_id":
                    external_id = value
                elif mapping.target == "external_url":
                    external_url = value
                elif mapping.target == "error_message":
                    error_message = value

        # Check for error patterns in body
        if self.response_config.error_body_pattern and not error_message:
            pattern = re.compile(self.response_config.error_body_pattern, re.IGNORECASE)
            match = pattern.search(raw_body)
            if match:
                error_message = match.group(0) if match.groups() == () else match.group(1)

        # Determine success
        success = response.status_code in self.response_config.success_status_codes

        # Check success pattern if configured
        if success and self.response_config.success_body_pattern:
            pattern = re.compile(self.response_config.success_body_pattern, re.IGNORECASE)
            success = bool(pattern.search(raw_body))

        return WebhookResponse(
            success=success,
            status_code=response.status_code,
            raw_body=raw_body,
            parsed_body=parsed_body,
            headers=dict(response.headers),
            response_time_ms=response_time,
            error_message=error_message,
            external_id=external_id,
            external_url=external_url
        )

    def _extract_field(self, data: Optional[Dict], path: str) -> Any:
        """Extract field from nested dict using dot notation.

        Args:
            data: Data dict
            path: Field path like "data.id" or "result.ticket.number"

        Returns:
            Field value or None
        """
        if not data or not path:
            return None

        parts = path.split(".")
        current = data

        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list) and part.isdigit():
                idx = int(part)
                if 0 <= idx < len(current):
                    current = current[idx]
                else:
                    return None
            else:
                return None

        return current

    def _determine_action(self, response: WebhookResponse) -> ResponseAction:
        """Determine action based on response.

        Args:
            response: Webhook response

        Returns:
            Action to take
        """
        if response.success:
            return ResponseAction.SUCCESS

        if response.status_code in self.retry_config.retry_on_status_codes:
            return ResponseAction.RETRY

        return ResponseAction.FAIL

    def _calculate_delay(self, attempt: int) -> float:
        """Calculate retry delay.

        Args:
            attempt: Attempt number (0-based)

        Returns:
            Delay in seconds
        """
        if self.retry_config.strategy == RetryStrategy.FIXED:
            return self.retry_config.base_delay_seconds

        # Exponential backoff: base * 2^attempt
        delay = self.retry_config.base_delay_seconds * (2 ** attempt)
        return min(delay, self.retry_config.max_delay_seconds)

    def format_alert(self, alert: Alert) -> Dict:
        """Format alert as webhook payload.

        Args:
            alert: Alert to format

        Returns:
            Alert payload
        """
        # Use custom template if provided
        if self.payload_template:
            return self._apply_template(alert)

        # Standard webhook payload format
        payload = {
            "event_type": "security_alert",
            "timestamp": alert.timestamp.isoformat(),
            "alert": {
                "id": alert.id,
                "severity": alert.severity,
                "title": alert.title,
                "description": alert.description,
                "rule_id": alert.rule_id,
                "rule_name": alert.rule_name,
                "tags": alert.tags,
            },
            "metadata": alert.metadata or {},
        }

        # Add MITRE ATT&CK if present
        if alert.mitre_attack:
            payload["alert"]["mitre_attack"] = alert.mitre_attack

        # Add enrichment if present
        if alert.enrichment:
            payload["alert"]["enrichment"] = alert.enrichment

        # Add results summary
        if alert.results:
            payload["results"] = {
                "count": len(alert.results),
                "samples": alert.results[:5]  # First 5 results
            }

        # Apply field mapping
        if self.field_mapping:
            payload = self._apply_field_mapping(payload, alert)

        return payload

    def _apply_template(self, alert: Alert) -> Dict:
        """Apply custom payload template.

        Args:
            alert: Alert to format

        Returns:
            Templated payload
        """
        import copy
        payload = copy.deepcopy(self.payload_template)
        return self._replace_placeholders(payload, alert)

    def _replace_placeholders(self, obj: Any, alert: Alert) -> Any:
        """Recursively replace {{field}} placeholders.

        Args:
            obj: Object to process
            alert: Alert with values

        Returns:
            Processed object
        """
        if isinstance(obj, str):
            # Replace placeholders like {{id}}, {{severity}}, {{title}}
            def replacer(match):
                field = match.group(1)
                if hasattr(alert, field):
                    value = getattr(alert, field)
                    if isinstance(value, datetime):
                        return value.isoformat()
                    return str(value) if value is not None else ""
                return match.group(0)

            return re.sub(r"\{\{(\w+)\}\}", replacer, obj)

        elif isinstance(obj, dict):
            return {k: self._replace_placeholders(v, alert) for k, v in obj.items()}

        elif isinstance(obj, list):
            return [self._replace_placeholders(item, alert) for item in obj]

        return obj

    def _apply_field_mapping(self, payload: Dict, alert: Alert) -> Dict:
        """Apply custom field mapping.

        Args:
            payload: Base payload
            alert: Alert with values

        Returns:
            Mapped payload
        """
        for source, target in self.field_mapping.items():
            # Get source value from alert
            if hasattr(alert, source):
                value = getattr(alert, source)

                # Set target in payload using dot notation
                parts = target.split(".")
                current = payload
                for part in parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                current[parts[-1]] = value

        return payload

    def test_connection(self) -> WebhookResponse:
        """Test webhook connection with a minimal payload.

        Returns:
            WebhookResponse from test
        """
        test_alert = Alert(
            id=f"test-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            title="Webhook Connection Test",
            description="This is a test message to verify webhook connectivity.",
            severity="info",
            rule_id="test-connection",
            rule_name="Connection Test",
            timestamp=datetime.now(timezone.utc),
            results=[],
            tags=["test"],
            metadata={"test": True}
        )

        return self.send_with_response(test_alert)


# Convenience function for creating common webhook configurations
def create_webhook_with_retry(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    max_retries: int = 3,
    timeout: int = 30
) -> WebhookHandler:
    """Create webhook handler with standard retry configuration.

    Args:
        url: Webhook URL
        headers: Custom headers
        max_retries: Maximum retry attempts
        timeout: Request timeout

    Returns:
        Configured WebhookHandler
    """
    return WebhookHandler(
        webhook_url=url,
        headers=headers,
        timeout=timeout,
        retry_config=RetryConfig(
            strategy=RetryStrategy.EXPONENTIAL,
            max_retries=max_retries,
            base_delay_seconds=1.0,
            max_delay_seconds=30.0
        )
    )


def create_signed_webhook(
    url: str,
    secret: str,
    header_name: str = "X-Signature",
    algorithm: str = "sha256"
) -> WebhookHandler:
    """Create webhook handler with HMAC signature.

    Args:
        url: Webhook URL
        secret: Signing secret
        header_name: Header name for signature
        algorithm: Hash algorithm

    Returns:
        Configured WebhookHandler
    """
    return WebhookHandler(
        webhook_url=url,
        signing_secret=secret,
        signing_header=header_name,
        signing_algorithm=algorithm
    )
