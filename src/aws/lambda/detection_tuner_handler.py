"""
Detection Tuner Lambda Handler

Scheduled Lambda function that runs weekly to analyze detection rules
and create Jira tickets for HIGH CONFIDENCE tuning recommendations.
"""

import os
import json
import logging
import boto3
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from shared.detection.tuning import (
    TuningConfig,
    TuningAnalyzer,
    AnalysisResult,
    TuningRecommendation,
    FeedbackTracker
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class DetectionTunerHandler:
    """Handles scheduled detection tuning analysis."""

    def __init__(self):
        """Initialize handler with AWS clients."""
        self.dynamodb = boto3.resource('dynamodb')
        self.secretsmanager = boto3.client('secretsmanager')
        self.athena = boto3.client('athena')

        # Load configuration
        self.config = self._load_config()

        # Initialize components
        self.feedback_tracker = FeedbackTracker(
            table_name=os.environ.get('TUNING_FEEDBACK_TABLE'),
            jira_config=self._get_jira_config(),
            suppress_rejected_days=self.config.suppress_rejected_days,
            max_rejections_before_permanent=self.config.max_rejections_before_permanent,
            stale_ticket_days=self.config.stale_ticket_days
        )

        self.analyzer = TuningAnalyzer(
            config=self.config,
            feedback_tracker=self.feedback_tracker
        )

    def _load_config(self) -> TuningConfig:
        """Load tuning configuration."""
        # Try to load from DynamoDB settings
        try:
            settings_table = self.dynamodb.Table(
                os.environ.get('SETTINGS_TABLE', 'mantissa-log-settings')
            )

            response = settings_table.get_item(
                Key={'pk': 'settings', 'sk': 'detection_tuning'}
            )

            if 'Item' in response:
                return TuningConfig.from_dict(response['Item'].get('config', {}))

        except Exception as e:
            logger.warning(f"Failed to load config from DynamoDB: {e}")

        # Fall back to environment
        return TuningConfig.from_environment()

    def _get_jira_config(self) -> Dict[str, Any]:
        """Get Jira configuration from Secrets Manager."""
        try:
            secret_id = os.environ.get(
                'JIRA_SECRET_ID',
                'mantissa-log/integrations/jira'
            )

            response = self.secretsmanager.get_secret_value(SecretId=secret_id)
            return json.loads(response['SecretString'])

        except Exception as e:
            logger.warning(f"Failed to get Jira config: {e}")
            return {}

    def handle(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """
        Handle scheduled tuning analysis.

        Args:
            event: Lambda event (from EventBridge)
            context: Lambda context

        Returns:
            Response with analysis summary
        """
        logger.info("Starting detection tuning analysis")

        if not self.config.enabled:
            logger.info("Detection tuning is disabled")
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'Detection tuning is disabled'})
            }

        try:
            # First, poll existing tickets for feedback
            feedback_results = self._poll_ticket_feedback()
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

                # Create tickets for HIGH CONFIDENCE recommendations
                if result.has_high_confidence_recommendations():
                    for rec in result.get_high_confidence_recommendations():
                        ticket_key = self._create_jira_ticket(result, rec)
                        if ticket_key:
                            tickets_created += 1
                            logger.info(f"Created ticket {ticket_key} for {rule['id']}")

            # Log results
            summary = self._build_summary(analysis_results, tickets_created, feedback_results)
            self._store_analysis_run(summary)

            logger.info(f"Analysis complete: {summary}")

            return {
                'statusCode': 200,
                'body': json.dumps(summary)
            }

        except Exception as e:
            logger.error(f"Error in detection tuning: {e}")
            import traceback
            traceback.print_exc()

            return {
                'statusCode': 500,
                'body': json.dumps({'error': str(e)})
            }

    def _poll_ticket_feedback(self) -> Dict[str, int]:
        """Poll existing tickets for feedback."""
        if not self.feedback_tracker.jira_config:
            logger.info("No Jira config, skipping feedback poll")
            return {'skipped': True}

        return self.feedback_tracker.poll_and_process_tickets()

    def _get_enabled_rules(self) -> List[Dict[str, Any]]:
        """Get all enabled detection rules from DynamoDB."""
        rules = []

        try:
            rules_table = self.dynamodb.Table(
                os.environ.get('RULES_TABLE', 'mantissa-log-rules')
            )

            # Scan for enabled rules
            response = rules_table.scan(
                FilterExpression='enabled = :enabled',
                ExpressionAttributeValues={':enabled': True}
            )

            rules = response.get('Items', [])

            # Handle pagination
            while 'LastEvaluatedKey' in response:
                response = rules_table.scan(
                    FilterExpression='enabled = :enabled',
                    ExpressionAttributeValues={':enabled': True},
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
                rules.extend(response.get('Items', []))

        except Exception as e:
            logger.error(f"Failed to get enabled rules: {e}")

        return rules

    def _analyze_rule(self, rule: Dict[str, Any]) -> AnalysisResult:
        """Analyze a single rule."""
        rule_id = rule.get('id', rule.get('rule_id', 'unknown'))
        rule_name = rule.get('name', rule.get('title', rule_id))

        # Get alerts for this rule
        alerts = self._get_rule_alerts(rule_id)

        # Run analysis
        return self.analyzer.analyze_rule(
            rule_id=rule_id,
            rule_name=rule_name,
            rule_metadata=rule,
            alerts=alerts
        )

    def _get_rule_alerts(self, rule_id: str) -> List[Dict[str, Any]]:
        """Get alerts for a rule from the last N days."""
        alerts = []

        try:
            alerts_table = self.dynamodb.Table(
                os.environ.get('ALERTS_TABLE', 'mantissa-log-alerts')
            )

            # Calculate time window
            start_date = (
                datetime.utcnow() - timedelta(days=self.config.analysis_window_days)
            ).isoformat() + 'Z'

            # Query alerts (assumes GSI on rule_id)
            response = alerts_table.query(
                IndexName='rule-id-index',
                KeyConditionExpression='rule_id = :rule_id AND created_at >= :start',
                ExpressionAttributeValues={
                    ':rule_id': rule_id,
                    ':start': start_date
                },
                Limit=10000  # Cap at 10k alerts per rule
            )

            alerts = response.get('Items', [])

        except Exception as e:
            logger.warning(f"Failed to get alerts for rule {rule_id}: {e}")

            # Try Athena fallback if DynamoDB query fails
            alerts = self._get_alerts_from_athena(rule_id)

        return alerts

    def _get_alerts_from_athena(self, rule_id: str) -> List[Dict[str, Any]]:
        """Get alerts from Athena as fallback."""
        try:
            database = os.environ.get('ATHENA_DATABASE', 'mantissa_log')
            output_location = os.environ.get('ATHENA_OUTPUT', 's3://mantissa-log-query-results/')

            start_date = (
                datetime.utcnow() - timedelta(days=self.config.analysis_window_days)
            ).strftime('%Y-%m-%d')

            query = f"""
            SELECT *
            FROM alerts
            WHERE rule_id = '{rule_id}'
              AND date >= '{start_date}'
            LIMIT 10000
            """

            # Start query
            response = self.athena.start_query_execution(
                QueryString=query,
                QueryExecutionContext={'Database': database},
                ResultConfiguration={'OutputLocation': output_location}
            )

            query_id = response['QueryExecutionId']

            # Wait for completion (with timeout)
            import time
            for _ in range(60):  # 60 second timeout
                status = self.athena.get_query_execution(QueryExecutionId=query_id)
                state = status['QueryExecution']['Status']['State']

                if state == 'SUCCEEDED':
                    break
                elif state in ['FAILED', 'CANCELLED']:
                    return []

                time.sleep(1)
            else:
                return []

            # Get results
            results = []
            paginator = self.athena.get_paginator('get_query_results')

            for page in paginator.paginate(QueryExecutionId=query_id):
                rows = page['ResultSet']['Rows']

                if not results and rows:
                    headers = [col.get('VarCharValue', '') for col in rows[0]['Data']]
                    rows = rows[1:]

                for row in rows:
                    result = {}
                    for i, col in enumerate(row['Data']):
                        if i < len(headers):
                            result[headers[i]] = col.get('VarCharValue')
                    results.append(result)

            return results

        except Exception as e:
            logger.error(f"Failed to get alerts from Athena: {e}")
            return []

    def _create_jira_ticket(
        self,
        analysis_result: AnalysisResult,
        recommendation: TuningRecommendation
    ) -> Optional[str]:
        """Create a Jira ticket for a recommendation."""
        jira_config = self._get_jira_config()
        if not jira_config or not self.config.create_jira_tickets:
            logger.info("Jira not configured, skipping ticket creation")
            return None

        try:
            # Check if similar ticket exists
            if self._ticket_exists_for_recommendation(recommendation.recommendation_id):
                logger.info(f"Ticket already exists for {recommendation.recommendation_id}")
                return None

            # Generate ticket content
            ticket_content = self.analyzer.generate_jira_ticket_body(
                analysis_result,
                recommendation
            )

            # Create ticket
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
                                    {
                                        'type': 'text',
                                        'text': ticket_content['description']
                                    }
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

    def _ticket_exists_for_recommendation(self, recommendation_id: str) -> bool:
        """Check if a ticket already exists for this recommendation."""
        try:
            table = self.dynamodb.Table(
                os.environ.get('TUNING_FEEDBACK_TABLE', 'mantissa-log-tuning-feedback')
            )

            # Check for existing ticket with this recommendation ID
            response = table.scan(
                FilterExpression='recommendation_id = :rec_id AND #status = :status',
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':rec_id': recommendation_id,
                    ':status': 'open'
                },
                Limit=1
            )

            return len(response.get('Items', [])) > 0

        except Exception as e:
            logger.warning(f"Failed to check existing tickets: {e}")
            return False

    def _build_summary(
        self,
        results: List[AnalysisResult],
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
        """Store analysis run summary in DynamoDB."""
        try:
            table = self.dynamodb.Table(
                os.environ.get('TUNING_FEEDBACK_TABLE', 'mantissa-log-tuning-feedback')
            )

            table.put_item(
                Item={
                    'pk': 'analysis-run',
                    'sk': summary['timestamp'],
                    **summary,
                    'ttl': int((datetime.utcnow() + timedelta(days=90)).timestamp())
                }
            )

        except Exception as e:
            logger.warning(f"Failed to store analysis run: {e}")


# Lambda handler
handler = DetectionTunerHandler()


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """AWS Lambda entry point."""
    return handler.handle(event, context)
