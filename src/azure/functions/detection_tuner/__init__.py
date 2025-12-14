"""
Detection Tuner Azure Function.

Timer-triggered Azure Function that runs weekly to analyze detection rules
and create tuning recommendations.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import azure.functions as func
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

logger = logging.getLogger(__name__)

# Lazy imports for shared modules
_tuning_module = None


def _get_tuning_module():
    """Lazy import tuning module."""
    global _tuning_module
    if _tuning_module is None:
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../..'))
        from shared.detection.tuning import (
            TuningConfig,
            TuningAnalyzer,
        )
        _tuning_module = {
            'TuningConfig': TuningConfig,
            'TuningAnalyzer': TuningAnalyzer,
        }
    return _tuning_module


class AzureDetectionTuner:
    """Handles scheduled detection tuning analysis for Azure."""

    def __init__(self):
        """Initialize with Azure clients."""
        # Cosmos DB
        cosmos_endpoint = os.environ.get('COSMOS_ENDPOINT')
        cosmos_key = os.environ.get('COSMOS_KEY')

        if cosmos_endpoint and cosmos_key:
            self.cosmos_client = CosmosClient(cosmos_endpoint, cosmos_key)
        else:
            # Use managed identity
            credential = DefaultAzureCredential()
            self.cosmos_client = CosmosClient(cosmos_endpoint, credential=credential)

        self.database = self.cosmos_client.get_database_client(
            os.environ.get('COSMOS_DATABASE', 'mantissa-log')
        )
        self.rules_container = self.database.get_container_client('rules')
        self.alerts_container = self.database.get_container_client('alerts')
        self.feedback_container = self.database.get_container_client('tuning_feedback')
        self.runs_container = self.database.get_container_client('tuning_runs')

        self.config = self._load_config()

        # Get tuning classes
        tuning = _get_tuning_module()

        # Initialize feedback tracker
        self.feedback_tracker = AzureFeedbackTracker(
            feedback_container=self.feedback_container,
            jira_config=self._get_jira_config(),
            suppress_rejected_days=self.config.suppress_rejected_days,
            max_rejections_before_permanent=self.config.max_rejections_before_permanent,
            stale_ticket_days=self.config.stale_ticket_days
        )

        # Initialize analyzer
        self.analyzer = tuning['TuningAnalyzer'](
            config=self.config,
            feedback_tracker=self.feedback_tracker
        )

    def _load_config(self):
        """Load tuning configuration from Cosmos DB."""
        tuning = _get_tuning_module()

        try:
            settings_container = self.database.get_container_client('settings')
            config_doc = settings_container.read_item(
                item='detection_tuning',
                partition_key='settings'
            )
            return tuning['TuningConfig'].from_dict(config_doc.get('config', {}))
        except Exception as e:
            logger.warning(f"Failed to load config from Cosmos DB: {e}")

        return tuning['TuningConfig'].from_environment()

    def _get_jira_config(self) -> Dict[str, Any]:
        """Get Jira configuration from Key Vault."""
        try:
            vault_url = os.environ.get('KEY_VAULT_URL')
            if not vault_url:
                return {}

            credential = DefaultAzureCredential()
            secret_client = SecretClient(vault_url=vault_url, credential=credential)

            secret = secret_client.get_secret('jira-integration')
            return json.loads(secret.value)
        except Exception as e:
            logger.warning(f"Failed to get Jira config: {e}")
            return {}

    def run_analysis(self) -> Dict[str, Any]:
        """Run weekly detection tuning analysis."""
        logger.info("Starting detection tuning analysis")

        if not self.config.enabled:
            logger.info("Detection tuning is disabled")
            return {'message': 'Detection tuning is disabled'}

        try:
            # Poll existing tickets for feedback
            feedback_results = self.feedback_tracker.poll_and_process_tickets()
            logger.info(f"Feedback poll results: {feedback_results}")

            # Get enabled rules
            rules = self._get_enabled_rules()
            logger.info(f"Found {len(rules)} enabled rules to analyze")

            # Analyze each rule
            analysis_results = []
            tickets_created = 0

            for rule in rules:
                result = self._analyze_rule(rule)
                analysis_results.append(result)

                # Create tickets for high confidence recommendations
                if result.has_high_confidence_recommendations():
                    for rec in result.get_high_confidence_recommendations():
                        ticket_key = self._create_jira_ticket(result, rec)
                        if ticket_key:
                            tickets_created += 1
                            logger.info(f"Created ticket {ticket_key} for {rule['id']}")

            # Build and store summary
            summary = self._build_summary(analysis_results, tickets_created, feedback_results)
            self._store_analysis_run(summary)

            logger.info(f"Analysis complete: {summary}")
            return summary

        except Exception as e:
            logger.error(f"Error in detection tuning: {e}")
            import traceback
            traceback.print_exc()
            return {'error': str(e)}

    def _get_enabled_rules(self) -> List[Dict[str, Any]]:
        """Get all enabled detection rules from Cosmos DB."""
        rules = []

        try:
            query = "SELECT * FROM c WHERE c.enabled = true"
            items = self.rules_container.query_items(
                query=query,
                enable_cross_partition_query=True
            )

            for item in items:
                rules.append(item)

        except Exception as e:
            logger.error(f"Failed to get enabled rules: {e}")

        return rules

    def _analyze_rule(self, rule: Dict[str, Any]):
        """Analyze a single rule."""
        rule_id = rule.get('id', 'unknown')
        rule_name = rule.get('name', rule.get('title', rule_id))

        # Get alerts
        alerts = self._get_rule_alerts(rule_id)

        return self.analyzer.analyze_rule(
            rule_id=rule_id,
            rule_name=rule_name,
            rule_metadata=rule,
            alerts=alerts
        )

    def _get_rule_alerts(self, rule_id: str) -> List[Dict[str, Any]]:
        """Get alerts for a rule from Cosmos DB."""
        alerts = []

        try:
            start_date = (
                datetime.utcnow() - timedelta(days=self.config.analysis_window_days)
            ).isoformat() + 'Z'

            query = """
            SELECT * FROM c
            WHERE c.rule_id = @rule_id
              AND c.timestamp >= @start_date
            """

            parameters = [
                {'name': '@rule_id', 'value': rule_id},
                {'name': '@start_date', 'value': start_date}
            ]

            items = self.alerts_container.query_items(
                query=query,
                parameters=parameters,
                enable_cross_partition_query=True,
                max_item_count=10000
            )

            for item in items:
                alerts.append(item)

        except Exception as e:
            logger.error(f"Failed to get alerts for rule {rule_id}: {e}")

        return alerts

    def _create_jira_ticket(self, analysis_result, recommendation) -> Optional[str]:
        """Create a Jira ticket for a recommendation."""
        import requests

        jira_config = self._get_jira_config()
        if not jira_config or not self.config.create_jira_tickets:
            return None

        try:
            # Check if ticket exists
            if self._ticket_exists(recommendation.recommendation_id):
                return None

            # Generate ticket content
            ticket_content = self.analyzer.generate_jira_ticket_body(
                analysis_result,
                recommendation
            )

            url = jira_config['url'].rstrip('/')
            email = jira_config['email']
            api_token = jira_config['api_token']

            issue_data = {
                'fields': {
                    'project': {'key': self.config.jira_project_key},
                    'summary': ticket_content['summary'],
                    'description': {
                        'type': 'doc',
                        'version': 1,
                        'content': [
                            {
                                'type': 'paragraph',
                                'content': [
                                    {'type': 'text', 'text': ticket_content['description']}
                                ]
                            }
                        ]
                    },
                    'issuetype': {'name': self.config.jira_issue_type},
                    'labels': self.config.jira_labels
                }
            }

            response = requests.post(
                f'{url}/rest/api/3/issue',
                auth=(email, api_token),
                json=issue_data,
                timeout=30
            )
            response.raise_for_status()

            issue = response.json()
            ticket_key = issue['key']

            # Record ticket creation
            self.feedback_tracker.record_ticket_created(
                recommendation_id=recommendation.recommendation_id,
                rule_id=recommendation.rule_id,
                recommendation_type=recommendation.recommendation_type.value,
                jira_ticket_key=ticket_key
            )

            return ticket_key

        except Exception as e:
            logger.error(f"Failed to create Jira ticket: {e}")
            return None

    def _ticket_exists(self, recommendation_id: str) -> bool:
        """Check if a ticket already exists for this recommendation."""
        try:
            query = """
            SELECT VALUE COUNT(1) FROM c
            WHERE c.recommendation_id = @rec_id AND c.status = 'open'
            """

            items = list(self.feedback_container.query_items(
                query=query,
                parameters=[{'name': '@rec_id', 'value': recommendation_id}],
                enable_cross_partition_query=True
            ))

            return items and items[0] > 0

        except Exception as e:
            logger.warning(f"Failed to check existing tickets: {e}")
            return False

    def _build_summary(
        self,
        results: List,
        tickets_created: int,
        feedback_results: Dict[str, int]
    ) -> Dict[str, Any]:
        """Build summary of analysis run."""
        high_confidence_count = sum(
            len(r.get_high_confidence_recommendations())
            for r in results
        )

        return {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'rules_analyzed': len(results),
            'rules_skipped': sum(1 for r in results if r.skipped),
            'total_recommendations': sum(len(r.recommendations) for r in results),
            'high_confidence_recommendations': high_confidence_count,
            'tickets_created': tickets_created,
            'feedback_poll': feedback_results,
            'config': {
                'analysis_window_days': self.config.analysis_window_days,
                'min_alerts_for_analysis': self.config.min_alerts_for_analysis
            }
        }

    def _store_analysis_run(self, summary: Dict[str, Any]) -> None:
        """Store analysis run summary in Cosmos DB."""
        try:
            self.runs_container.create_item({
                'id': summary['timestamp'],
                'partition_key': 'analysis_run',
                **summary
            })
        except Exception as e:
            logger.warning(f"Failed to store analysis run: {e}")


class AzureFeedbackTracker:
    """Cosmos DB-backed feedback tracker for Azure."""

    def __init__(
        self,
        feedback_container,
        jira_config: Dict[str, Any],
        suppress_rejected_days: int = 90,
        max_rejections_before_permanent: int = 3,
        stale_ticket_days: int = 30
    ):
        """Initialize Azure feedback tracker."""
        self.container = feedback_container
        self.jira_config = jira_config
        self.suppress_rejected_days = suppress_rejected_days
        self.max_rejections_before_permanent = max_rejections_before_permanent
        self.stale_ticket_days = stale_ticket_days

    def record_ticket_created(
        self,
        recommendation_id: str,
        rule_id: str,
        recommendation_type: str,
        jira_ticket_key: str
    ) -> None:
        """Record that a Jira ticket was created."""
        now = datetime.utcnow().isoformat() + 'Z'

        try:
            self.container.create_item({
                'id': jira_ticket_key,
                'partition_key': rule_id,
                'recommendation_id': recommendation_id,
                'rule_id': rule_id,
                'recommendation_type': recommendation_type,
                'jira_ticket_key': jira_ticket_key,
                'status': 'open',
                'created_at': now
            })
        except Exception as e:
            logger.error(f"Failed to record ticket creation: {e}")

    def is_rule_suppressed(self, rule_id: str, recommendation_type: Optional[str] = None) -> bool:
        """Check if a rule is suppressed."""
        try:
            if recommendation_type:
                query = """
                SELECT * FROM c
                WHERE c.rule_id = @rule_id
                  AND c.recommendation_type = @rec_type
                  AND c.type = 'suppression'
                """
                params = [
                    {'name': '@rule_id', 'value': rule_id},
                    {'name': '@rec_type', 'value': recommendation_type}
                ]
            else:
                query = """
                SELECT * FROM c
                WHERE c.rule_id = @rule_id AND c.type = 'suppression'
                """
                params = [{'name': '@rule_id', 'value': rule_id}]

            items = list(self.container.query_items(
                query=query,
                parameters=params,
                enable_cross_partition_query=True
            ))

            for item in items:
                if item.get('permanent'):
                    return True
                suppressed_until = item.get('suppressed_until', '')
                if suppressed_until:
                    until_dt = datetime.fromisoformat(suppressed_until.replace('Z', ''))
                    if datetime.utcnow() < until_dt:
                        return True

            return False

        except Exception as e:
            logger.error(f"Failed to check suppression: {e}")
            return False

    def poll_and_process_tickets(self) -> Dict[str, int]:
        """Poll open tickets and process resolutions."""
        import requests

        results = {
            'checked': 0,
            'accepted': 0,
            'rejected': 0,
            'ignored': 0,
            'still_open': 0,
            'errors': 0
        }

        if not self.jira_config:
            return {'skipped': True}

        try:
            # Get open tickets
            query = "SELECT * FROM c WHERE c.status = 'open'"
            tickets = list(self.container.query_items(
                query=query,
                enable_cross_partition_query=True
            ))

            for ticket in tickets:
                jira_key = ticket.get('jira_ticket_key')
                if not jira_key:
                    continue

                results['checked'] += 1

                try:
                    # Check Jira status
                    url = self.jira_config['url'].rstrip('/')
                    response = requests.get(
                        f'{url}/rest/api/3/issue/{jira_key}',
                        auth=(self.jira_config['email'], self.jira_config['api_token']),
                        timeout=10
                    )

                    if response.status_code == 404:
                        results['errors'] += 1
                        continue

                    response.raise_for_status()
                    issue = response.json()

                    status_category = issue['fields']['status']['statusCategory']['name'].lower()
                    resolution = issue['fields'].get('resolution', {}).get('name') if issue['fields'].get('resolution') else None

                    feedback_type = None

                    if status_category == 'done':
                        if resolution and resolution.lower() in ['done', 'fixed', 'resolved']:
                            feedback_type = 'accepted'
                            results['accepted'] += 1
                        elif resolution and resolution.lower() in ["won't do", 'declined', 'rejected']:
                            feedback_type = 'rejected'
                            results['rejected'] += 1
                            self._apply_suppression(ticket['rule_id'], ticket['recommendation_type'])
                        else:
                            feedback_type = 'accepted'
                            results['accepted'] += 1
                    else:
                        # Check for stale tickets
                        created_at = ticket.get('created_at', '')
                        if created_at:
                            created_dt = datetime.fromisoformat(created_at.replace('Z', ''))
                            if (datetime.utcnow() - created_dt).days >= self.stale_ticket_days:
                                feedback_type = 'ignored'
                                results['ignored'] += 1
                            else:
                                results['still_open'] += 1
                        else:
                            results['still_open'] += 1

                    if feedback_type:
                        ticket['status'] = 'resolved'
                        ticket['feedback_type'] = feedback_type
                        ticket['resolved_at'] = datetime.utcnow().isoformat() + 'Z'
                        self.container.upsert_item(ticket)

                except Exception as e:
                    logger.error(f"Error processing ticket {jira_key}: {e}")
                    results['errors'] += 1

        except Exception as e:
            logger.error(f"Failed to poll tickets: {e}")
            results['errors'] += 1

        return results

    def _apply_suppression(self, rule_id: str, recommendation_type: str) -> None:
        """Apply suppression after rejection."""
        try:
            doc_id = f'suppression-{rule_id}-{recommendation_type}'

            # Try to get existing suppression
            try:
                existing = self.container.read_item(item=doc_id, partition_key=rule_id)
                current_count = existing.get('rejection_count', 0)
            except Exception:
                existing = None
                current_count = 0

            new_count = current_count + 1
            permanent = new_count >= self.max_rejections_before_permanent

            if permanent:
                suppressed_until = '9999-12-31T23:59:59Z'
            else:
                suppressed_until = (
                    datetime.utcnow() + timedelta(days=self.suppress_rejected_days)
                ).isoformat() + 'Z'

            suppression_doc = {
                'id': doc_id,
                'partition_key': rule_id,
                'type': 'suppression',
                'rule_id': rule_id,
                'recommendation_type': recommendation_type,
                'suppressed_until': suppressed_until,
                'permanent': permanent,
                'rejection_count': new_count,
                'updated_at': datetime.utcnow().isoformat() + 'Z'
            }

            self.container.upsert_item(suppression_doc)

        except Exception as e:
            logger.error(f"Failed to apply suppression: {e}")


# Global tuner instance
_tuner = None


def get_tuner() -> AzureDetectionTuner:
    """Get or create tuner instance."""
    global _tuner
    if _tuner is None:
        _tuner = AzureDetectionTuner()
    return _tuner


def main(timer: func.TimerRequest) -> None:
    """
    Azure Function entry point for timer trigger.

    Configured to run weekly via function.json.
    """
    if timer.past_due:
        logger.info('Timer is past due!')

    tuner = get_tuner()
    result = tuner.run_analysis()

    logger.info(f"Detection tuning completed: {result}")
