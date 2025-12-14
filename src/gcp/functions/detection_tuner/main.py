"""
Detection Tuner Cloud Function for GCP.

Scheduled Cloud Function that runs weekly to analyze detection rules
and create tuning recommendations.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import functions_framework
from google.cloud import firestore, bigquery, secretmanager

logging.basicConfig(level=logging.INFO)
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
            FeedbackTracker,
        )
        _tuning_module = {
            'TuningConfig': TuningConfig,
            'TuningAnalyzer': TuningAnalyzer,
            'FeedbackTracker': FeedbackTracker,
        }
    return _tuning_module


class GCPDetectionTuner:
    """Handles scheduled detection tuning analysis for GCP."""

    def __init__(self):
        """Initialize with GCP clients."""
        self.firestore_client = firestore.Client()
        self.bigquery_client = bigquery.Client()
        self.secrets_client = secretmanager.SecretManagerServiceClient()

        self.project_id = os.environ.get('GCP_PROJECT', 'mantissa-log')
        self.config = self._load_config()

        # Get tuning classes
        tuning = _get_tuning_module()

        # Initialize feedback tracker
        self.feedback_tracker = self._create_feedback_tracker(tuning)

        # Initialize analyzer
        self.analyzer = tuning['TuningAnalyzer'](
            config=self.config,
            feedback_tracker=self.feedback_tracker
        )

    def _load_config(self):
        """Load tuning configuration from Firestore."""
        tuning = _get_tuning_module()

        try:
            doc_ref = self.firestore_client.collection('settings').document('detection_tuning')
            doc = doc_ref.get()

            if doc.exists:
                return tuning['TuningConfig'].from_dict(doc.to_dict().get('config', {}))
        except Exception as e:
            logger.warning(f"Failed to load config from Firestore: {e}")

        return tuning['TuningConfig'].from_environment()

    def _create_feedback_tracker(self, tuning):
        """Create feedback tracker with Firestore backend."""
        jira_config = self._get_jira_config()

        return GCPFeedbackTracker(
            firestore_client=self.firestore_client,
            jira_config=jira_config,
            suppress_rejected_days=self.config.suppress_rejected_days,
            max_rejections_before_permanent=self.config.max_rejections_before_permanent,
            stale_ticket_days=self.config.stale_ticket_days
        )

    def _get_jira_config(self) -> Dict[str, Any]:
        """Get Jira configuration from Secret Manager."""
        try:
            secret_name = os.environ.get(
                'JIRA_SECRET_NAME',
                f'projects/{self.project_id}/secrets/jira-integration/versions/latest'
            )

            response = self.secrets_client.access_secret_version(name=secret_name)
            return json.loads(response.payload.data.decode('utf-8'))
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

            # Get enabled rules from Firestore
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
        """Get all enabled detection rules from Firestore."""
        rules = []

        try:
            rules_ref = self.firestore_client.collection('rules')
            query = rules_ref.where('enabled', '==', True)

            for doc in query.stream():
                rule_data = doc.to_dict()
                rule_data['id'] = doc.id
                rules.append(rule_data)

        except Exception as e:
            logger.error(f"Failed to get enabled rules: {e}")

        return rules

    def _analyze_rule(self, rule: Dict[str, Any]):
        """Analyze a single rule."""
        rule_id = rule.get('id', 'unknown')
        rule_name = rule.get('name', rule.get('title', rule_id))

        # Get alerts from BigQuery
        alerts = self._get_rule_alerts(rule_id)

        return self.analyzer.analyze_rule(
            rule_id=rule_id,
            rule_name=rule_name,
            rule_metadata=rule,
            alerts=alerts
        )

    def _get_rule_alerts(self, rule_id: str) -> List[Dict[str, Any]]:
        """Get alerts for a rule from BigQuery."""
        alerts = []

        try:
            dataset = os.environ.get('BIGQUERY_DATASET', 'mantissa_log')
            start_date = (
                datetime.utcnow() - timedelta(days=self.config.analysis_window_days)
            ).strftime('%Y-%m-%d')

            query = f"""
            SELECT *
            FROM `{self.project_id}.{dataset}.alerts`
            WHERE rule_id = @rule_id
              AND DATE(timestamp) >= @start_date
            LIMIT 10000
            """

            job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter('rule_id', 'STRING', rule_id),
                    bigquery.ScalarQueryParameter('start_date', 'DATE', start_date),
                ]
            )

            query_job = self.bigquery_client.query(query, job_config=job_config)
            results = query_job.result()

            for row in results:
                alerts.append(dict(row))

        except Exception as e:
            logger.error(f"Failed to get alerts from BigQuery for rule {rule_id}: {e}")

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
            tickets_ref = self.firestore_client.collection('tuning_feedback')
            query = tickets_ref.where('recommendation_id', '==', recommendation_id).where('status', '==', 'open')

            docs = list(query.limit(1).stream())
            return len(docs) > 0

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
        """Store analysis run summary in Firestore."""
        try:
            doc_ref = self.firestore_client.collection('tuning_runs').document()
            doc_ref.set({
                **summary,
                'created_at': firestore.SERVER_TIMESTAMP
            })
        except Exception as e:
            logger.warning(f"Failed to store analysis run: {e}")


class GCPFeedbackTracker:
    """Firestore-backed feedback tracker for GCP."""

    def __init__(
        self,
        firestore_client,
        jira_config: Dict[str, Any],
        suppress_rejected_days: int = 90,
        max_rejections_before_permanent: int = 3,
        stale_ticket_days: int = 30
    ):
        """Initialize GCP feedback tracker."""
        self.db = firestore_client
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
            doc_ref = self.db.collection('tuning_feedback').document(jira_ticket_key)
            doc_ref.set({
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
            suppressions_ref = self.db.collection('tuning_suppressions')

            if recommendation_type:
                doc = suppressions_ref.document(f'{rule_id}:{recommendation_type}').get()
                if doc.exists:
                    data = doc.to_dict()
                    if data.get('permanent'):
                        return True
                    suppressed_until = data.get('suppressed_until', '')
                    if suppressed_until:
                        until_dt = datetime.fromisoformat(suppressed_until.replace('Z', ''))
                        if datetime.utcnow() < until_dt:
                            return True
            else:
                query = suppressions_ref.where('rule_id', '==', rule_id)
                for doc in query.stream():
                    data = doc.to_dict()
                    if data.get('permanent'):
                        return True
                    suppressed_until = data.get('suppressed_until', '')
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
            tickets_ref = self.db.collection('tuning_feedback')
            query = tickets_ref.where('status', '==', 'open')

            for doc in query.stream():
                ticket = doc.to_dict()
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
                        doc.reference.update({
                            'status': 'resolved',
                            'feedback_type': feedback_type,
                            'resolved_at': datetime.utcnow().isoformat() + 'Z'
                        })

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
            doc_id = f'{rule_id}:{recommendation_type}'
            doc_ref = self.db.collection('tuning_suppressions').document(doc_id)
            doc = doc_ref.get()

            current_count = 0
            if doc.exists:
                current_count = doc.to_dict().get('rejection_count', 0)

            new_count = current_count + 1
            permanent = new_count >= self.max_rejections_before_permanent

            if permanent:
                suppressed_until = '9999-12-31T23:59:59Z'
            else:
                suppressed_until = (
                    datetime.utcnow() + timedelta(days=self.suppress_rejected_days)
                ).isoformat() + 'Z'

            doc_ref.set({
                'rule_id': rule_id,
                'recommendation_type': recommendation_type,
                'suppressed_until': suppressed_until,
                'permanent': permanent,
                'rejection_count': new_count,
                'updated_at': datetime.utcnow().isoformat() + 'Z'
            })

        except Exception as e:
            logger.error(f"Failed to apply suppression: {e}")


# Global tuner instance
_tuner = None


def get_tuner() -> GCPDetectionTuner:
    """Get or create tuner instance."""
    global _tuner
    if _tuner is None:
        _tuner = GCPDetectionTuner()
    return _tuner


@functions_framework.cloud_event
def detection_tuner_scheduled(cloud_event):
    """
    Cloud Function entry point for scheduled execution.

    Triggered by Cloud Scheduler via Pub/Sub.
    """
    tuner = get_tuner()
    result = tuner.run_analysis()

    logger.info(f"Detection tuning completed: {result}")
    return result


@functions_framework.http
def detection_tuner_http(request):
    """
    HTTP entry point for manual triggering.

    GET /detection-tuner - Run analysis
    """
    tuner = get_tuner()
    result = tuner.run_analysis()

    return json.dumps(result), 200, {'Content-Type': 'application/json'}
