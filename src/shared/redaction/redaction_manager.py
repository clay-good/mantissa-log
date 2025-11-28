"""
Redaction Configuration Manager

Manages PII/PHI redaction configurations per user and per integration.
Stores configurations in DynamoDB and provides audit trail.
"""

import os
import json
import boto3
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from .redactor import (
    Redactor,
    RedactionType,
    IntegrationRedactionConfig,
    redact_for_integration
)


class RedactionManager:
    """
    Manages redaction configurations and audit trail.

    Features:
    - Per-integration redaction rules
    - Global user redaction settings
    - Audit trail of redactions
    - Configuration CRUD operations
    """

    def __init__(self, table_name: Optional[str] = None):
        """
        Initialize redaction manager.

        Args:
            table_name: DynamoDB table name
        """
        self.table_name = table_name or os.environ.get(
            'REDACTION_CONFIG_TABLE',
            'mantissa-log-redaction-config'
        )

        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(self.table_name)

    def get_integration_config(
        self,
        user_id: str,
        integration_id: str
    ) -> Optional[IntegrationRedactionConfig]:
        """
        Get redaction configuration for a specific integration.

        Args:
            user_id: User ID
            integration_id: Integration ID

        Returns:
            IntegrationRedactionConfig or None
        """
        try:
            response = self.table.get_item(
                Key={
                    'pk': f'user#{user_id}',
                    'sk': f'integration#{integration_id}'
                }
            )

            if 'Item' not in response:
                # Return default config if none exists
                return self._get_default_config(integration_id, 'unknown')

            item = response['Item']
            return IntegrationRedactionConfig.from_dict(item['config'])

        except Exception as e:
            print(f'Error retrieving redaction config: {e}')
            return self._get_default_config(integration_id, 'unknown')

    def save_integration_config(
        self,
        user_id: str,
        config: IntegrationRedactionConfig
    ):
        """
        Save redaction configuration for an integration.

        Args:
            user_id: User ID
            config: Integration redaction config
        """
        try:
            timestamp = datetime.utcnow().isoformat() + 'Z'

            item = {
                'pk': f'user#{user_id}',
                'sk': f'integration#{config.integration_id}',
                'user_id': user_id,
                'integration_id': config.integration_id,
                'integration_type': config.integration_type,
                'config': config.to_dict(),
                'updated_at': timestamp
            }

            self.table.put_item(Item=item)

        except Exception as e:
            print(f'Error saving redaction config: {e}')
            raise

    def get_user_configs(
        self,
        user_id: str
    ) -> List[IntegrationRedactionConfig]:
        """
        Get all redaction configurations for a user.

        Args:
            user_id: User ID

        Returns:
            List of IntegrationRedactionConfig
        """
        from boto3.dynamodb.conditions import Key

        try:
            response = self.table.query(
                KeyConditionExpression=
                    Key('pk').eq(f'user#{user_id}') &
                    Key('sk').begins_with('integration#')
            )

            configs = []
            for item in response.get('Items', []):
                config = IntegrationRedactionConfig.from_dict(item['config'])
                configs.append(config)

            return configs

        except Exception as e:
            print(f'Error retrieving user configs: {e}')
            return []

    def delete_integration_config(
        self,
        user_id: str,
        integration_id: str
    ):
        """
        Delete redaction configuration for an integration.

        Args:
            user_id: User ID
            integration_id: Integration ID
        """
        try:
            self.table.delete_item(
                Key={
                    'pk': f'user#{user_id}',
                    'sk': f'integration#{integration_id}'
                }
            )
        except Exception as e:
            print(f'Error deleting redaction config: {e}')

    def log_redaction(
        self,
        user_id: str,
        integration_id: str,
        alert_id: str,
        redaction_summary: Dict[str, Any]
    ):
        """
        Log a redaction event for audit trail.

        Args:
            user_id: User ID
            integration_id: Integration ID
            alert_id: Alert ID
            redaction_summary: Summary of what was redacted
        """
        try:
            timestamp = datetime.utcnow().isoformat() + 'Z'

            item = {
                'pk': f'user#{user_id}',
                'sk': f'audit#{timestamp}#{alert_id}',
                'user_id': user_id,
                'integration_id': integration_id,
                'alert_id': alert_id,
                'timestamp': timestamp,
                'redaction_summary': redaction_summary,
                'ttl': int((datetime.utcnow().timestamp())) + (90 * 24 * 60 * 60)  # 90 days
            }

            self.table.put_item(Item=item)

        except Exception as e:
            print(f'Error logging redaction: {e}')
            # Don't fail the alert if audit logging fails
            pass

    def get_redaction_audit_trail(
        self,
        user_id: str,
        integration_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get redaction audit trail.

        Args:
            user_id: User ID
            integration_id: Optional integration filter
            limit: Maximum records to return

        Returns:
            List of audit records
        """
        from boto3.dynamodb.conditions import Key

        try:
            response = self.table.query(
                KeyConditionExpression=
                    Key('pk').eq(f'user#{user_id}') &
                    Key('sk').begins_with('audit#'),
                Limit=limit,
                ScanIndexForward=False  # Most recent first
            )

            audit_records = response.get('Items', [])

            # Filter by integration if specified
            if integration_id:
                audit_records = [
                    r for r in audit_records
                    if r.get('integration_id') == integration_id
                ]

            return audit_records

        except Exception as e:
            print(f'Error retrieving audit trail: {e}')
            return []

    def redact_alert_for_integration(
        self,
        user_id: str,
        integration_id: str,
        integration_type: str,
        alert_payload: Dict[str, Any],
        alert_id: str,
        log_audit: bool = True
    ) -> Dict[str, Any]:
        """
        Redact an alert payload for a specific integration.

        Args:
            user_id: User ID
            integration_id: Integration ID
            integration_type: Integration type
            alert_payload: Alert payload to redact
            alert_id: Alert ID for audit trail
            log_audit: Whether to log the redaction

        Returns:
            Redacted alert payload
        """
        # Get redaction config for this integration
        config = self.get_integration_config(user_id, integration_id)

        if not config:
            # Use default config
            config = self._get_default_config(integration_id, integration_type)

        # Redact the payload
        redacted_payload = redact_for_integration(alert_payload, config)

        # Log audit trail if enabled
        if log_audit and config.enabled:
            # Get summary of what was redacted
            redactor = config.create_redactor()
            summary = redactor.get_redaction_summary(alert_payload)

            if summary['redaction_counts']:
                self.log_redaction(
                    user_id=user_id,
                    integration_id=integration_id,
                    alert_id=alert_id,
                    redaction_summary=summary
                )

        return redacted_payload

    def _get_default_config(
        self,
        integration_id: str,
        integration_type: str
    ) -> IntegrationRedactionConfig:
        """
        Get default redaction configuration.

        Args:
            integration_id: Integration ID
            integration_type: Integration type

        Returns:
            Default IntegrationRedactionConfig
        """
        # Default: Enable all standard patterns except IP addresses
        default_patterns = {
            RedactionType.EMAIL,
            RedactionType.PHONE,
            RedactionType.SSN,
            RedactionType.CREDIT_CARD,
            RedactionType.AWS_KEY
        }

        # Preserve standard metadata fields
        preserve_fields = {
            'alert_id',
            'rule_id',
            'rule_name',
            'detection_name',
            'severity',
            'timestamp',
            'event_count',
            'query_id',
            'execution_id'
        }

        return IntegrationRedactionConfig(
            integration_id=integration_id,
            integration_type=integration_type,
            enabled=True,
            enabled_patterns=default_patterns,
            preserve_fields=preserve_fields
        )

    def get_redaction_statistics(
        self,
        user_id: str,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Get redaction statistics for a user.

        Args:
            user_id: User ID
            days: Number of days to look back

        Returns:
            Redaction statistics
        """
        from boto3.dynamodb.conditions import Key
        from datetime import timedelta

        try:
            # Calculate start date
            start_date = datetime.utcnow() - timedelta(days=days)
            start_timestamp = start_date.isoformat() + 'Z'

            response = self.table.query(
                KeyConditionExpression=
                    Key('pk').eq(f'user#{user_id}') &
                    Key('sk').between(
                        f'audit#{start_timestamp}',
                        f'audit#9999-99-99'
                    )
            )

            audit_records = response.get('Items', [])

            # Aggregate statistics
            stats = {
                'total_redactions': len(audit_records),
                'redaction_counts_by_type': {},
                'integrations_with_redactions': set(),
                'total_fields_redacted': 0
            }

            for record in audit_records:
                summary = record.get('redaction_summary', {})

                # Add to integration set
                stats['integrations_with_redactions'].add(record.get('integration_id'))

                # Aggregate by pattern type
                for pattern_type, count in summary.get('redaction_counts', {}).items():
                    stats['redaction_counts_by_type'][pattern_type] = \
                        stats['redaction_counts_by_type'].get(pattern_type, 0) + count

                # Count fields
                stats['total_fields_redacted'] += len(summary.get('fields_with_pii', []))

            # Convert set to list for JSON serialization
            stats['integrations_with_redactions'] = list(stats['integrations_with_redactions'])

            return stats

        except Exception as e:
            print(f'Error getting redaction statistics: {e}')
            return {
                'total_redactions': 0,
                'redaction_counts_by_type': {},
                'integrations_with_redactions': [],
                'total_fields_redacted': 0
            }


def ensure_redacted_alert(
    user_id: str,
    integration_id: str,
    integration_type: str,
    alert_payload: Dict[str, Any],
    alert_id: str
) -> Dict[str, Any]:
    """
    Convenience function to ensure an alert is properly redacted.

    Args:
        user_id: User ID
        integration_id: Integration ID
        integration_type: Integration type
        alert_payload: Alert payload
        alert_id: Alert ID

    Returns:
        Redacted alert payload
    """
    manager = RedactionManager()

    return manager.redact_alert_for_integration(
        user_id=user_id,
        integration_id=integration_id,
        integration_type=integration_type,
        alert_payload=alert_payload,
        alert_id=alert_id
    )
