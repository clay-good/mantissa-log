"""Detection engine for executing detection rules and generating alerts."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import re
import warnings

from .rule import DetectionRule, RuleLoader

try:
    from .executors.base import QueryExecutor as NewQueryExecutor
    from .executors.athena import AthenaQueryExecutor as NewAthenaQueryExecutor
    EXECUTORS_AVAILABLE = True
except ImportError:
    EXECUTORS_AVAILABLE = False
    NewQueryExecutor = None
    NewAthenaQueryExecutor = None


@dataclass
class DetectionResult:
    """Result of a detection rule execution."""

    rule_id: str
    rule_name: str
    severity: str
    triggered: bool
    timestamp: datetime
    results: List[Dict[str, Any]] = field(default_factory=list)
    alert_title: str = ""
    alert_body: str = ""
    suppression_key: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format.

        Returns:
            Dictionary representation
        """
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "triggered": self.triggered,
            "timestamp": self.timestamp.isoformat(),
            "results": self.results,
            "alert_title": self.alert_title,
            "alert_body": self.alert_body,
            "suppression_key": self.suppression_key,
            "error": self.error,
        }


class QueryExecutor:
    """DEPRECATED: Base class for query execution against data stores.

    This class is deprecated. Use executors.base.QueryExecutor instead.
    """

    def __init__(self):
        warnings.warn(
            "QueryExecutor in engine.py is deprecated. "
            "Use executors.base.QueryExecutor instead.",
            DeprecationWarning,
            stacklevel=2
        )

    def execute_query(self, query: str) -> List[Dict[str, Any]]:
        """Execute a query and return results.

        Args:
            query: SQL query to execute

        Returns:
            List of result rows as dictionaries
        """
        raise NotImplementedError("Subclasses must implement execute_query")

    def validate_query(self, query: str) -> bool:
        """Validate query before execution.

        Args:
            query: Query to validate

        Returns:
            True if query is valid and safe
        """
        # Basic validation
        query_upper = query.upper().strip()

        # Must be SELECT
        if not query_upper.startswith("SELECT"):
            return False

        # No dangerous keywords
        dangerous = ["DROP", "DELETE", "TRUNCATE", "INSERT", "UPDATE",
                    "CREATE", "ALTER", "GRANT", "REVOKE", "EXEC"]

        for keyword in dangerous:
            if re.search(r'\b' + keyword + r'\b', query_upper):
                return False

        return True


class AthenaQueryExecutor(QueryExecutor):
    """DEPRECATED: Query executor for AWS Athena.

    This class is deprecated. Use executors.athena.AthenaQueryExecutor instead.
    """

    def __init__(self, database: str, output_location: str, region: str = "us-east-1"):
        """Initialize Athena executor.

        Args:
            database: Athena database name
            output_location: S3 location for query results
            region: AWS region
        """
        self.database = database
        self.output_location = output_location
        self.region = region
        self.client = None

    def _get_client(self):
        """Get or create Athena client.

        Returns:
            Boto3 Athena client
        """
        if self.client is None:
            try:
                import boto3
                self.client = boto3.client('athena', region_name=self.region)
            except ImportError:
                raise ImportError("boto3 is required for Athena executor")
        return self.client

    def execute_query(self, query: str, timeout: int = 60) -> List[Dict[str, Any]]:
        """Execute query against Athena.

        Args:
            query: SQL query
            timeout: Query timeout in seconds

        Returns:
            List of result rows
        """
        if not self.validate_query(query):
            raise ValueError("Invalid or unsafe query")

        client = self._get_client()

        # Start query execution
        response = client.start_query_execution(
            QueryString=query,
            QueryExecutionContext={'Database': self.database},
            ResultConfiguration={'OutputLocation': self.output_location}
        )

        query_execution_id = response['QueryExecutionId']

        # Wait for query to complete
        import time
        start_time = time.time()
        while time.time() - start_time < timeout:
            status = client.get_query_execution(QueryExecutionId=query_execution_id)
            state = status['QueryExecution']['Status']['State']

            if state == 'SUCCEEDED':
                break
            elif state in ['FAILED', 'CANCELLED']:
                reason = status['QueryExecution']['Status'].get('StateChangeReason', 'Unknown')
                raise RuntimeError(f"Query {state}: {reason}")

            time.sleep(1)
        else:
            raise TimeoutError(f"Query execution timed out after {timeout} seconds")

        # Get results
        results = []
        paginator = client.get_paginator('get_query_results')

        for page in paginator.paginate(QueryExecutionId=query_execution_id):
            rows = page['ResultSet']['Rows']

            # Skip header row
            if not results and rows:
                headers = [col['VarCharValue'] for col in rows[0]['Data']]
                rows = rows[1:]
            else:
                headers = [col['VarCharValue'] for col in page['ResultSet']['Rows'][0]['Data']]

            # Parse rows
            for row in rows:
                result_dict = {}
                for i, col in enumerate(row['Data']):
                    result_dict[headers[i]] = col.get('VarCharValue')
                results.append(result_dict)

        return results


class DetectionEngine:
    """Main detection engine that executes rules and generates alerts.

    Supports multi-cloud execution via query executor abstraction.
    """

    def __init__(
        self,
        rule_loader: RuleLoader,
        query_executor: QueryExecutor,
        state_manager: Optional[Any] = None,
        cloud_provider: Optional[str] = None,
        sigma_converter: Optional[Any] = None
    ):
        """Initialize detection engine.

        Args:
            rule_loader: RuleLoader instance
            query_executor: QueryExecutor instance
            state_manager: StateManager for deduplication (optional)
            cloud_provider: Cloud provider (aws, gcp, azure) for Sigma conversion
            sigma_converter: SigmaRuleConverter instance (optional)
        """
        self.rule_loader = rule_loader
        self.query_executor = query_executor
        self.state_manager = state_manager
        self.cloud_provider = cloud_provider or self._detect_cloud_provider()
        self.sigma_converter = sigma_converter

        # Initialize Sigma converter if not provided
        if self.sigma_converter is None and self.cloud_provider:
            try:
                from .sigma_converter import SigmaRuleConverter
                backend_type = self._get_backend_type(self.cloud_provider)
                self.sigma_converter = SigmaRuleConverter(backend_type=backend_type)
            except ImportError:
                # Sigma support not available
                self.sigma_converter = None

    def _detect_cloud_provider(self) -> str:
        """Detect cloud provider from executor type"""
        executor_class = self.query_executor.__class__.__name__

        if 'Athena' in executor_class:
            return 'aws'
        elif 'BigQuery' in executor_class:
            return 'gcp'
        elif 'Synapse' in executor_class:
            return 'azure'

        return 'aws'  # Default

    def _get_backend_type(self, cloud_provider: str) -> str:
        """Map cloud provider to Sigma backend type"""
        mapping = {
            'aws': 'athena',
            'gcp': 'bigquery',
            'azure': 'synapse'
        }
        return mapping.get(cloud_provider, 'athena')

    def execute_rule(
        self,
        rule: DetectionRule,
        time_window_start: Optional[datetime] = None,
        time_window_end: Optional[datetime] = None
    ) -> DetectionResult:
        """Execute a single detection rule.

        Args:
            rule: DetectionRule to execute
            time_window_start: Start of time window (defaults to 1 hour ago)
            time_window_end: End of time window (defaults to now)

        Returns:
            DetectionResult
        """
        # Default time window
        if time_window_end is None:
            time_window_end = datetime.utcnow()

        if time_window_start is None:
            # Parse interval from rule schedule
            interval = self._parse_interval(rule.schedule.interval)
            time_window_start = time_window_end - interval

        # Generate query
        try:
            query = rule.get_query(time_window_start, time_window_end)
        except Exception as e:
            return DetectionResult(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                triggered=False,
                timestamp=datetime.utcnow(),
                error=f"Failed to generate query: {str(e)}"
            )

        # Execute query
        try:
            results = self.query_executor.execute_query(query)
        except Exception as e:
            return DetectionResult(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                triggered=False,
                timestamp=datetime.utcnow(),
                error=f"Query execution failed: {str(e)}"
            )

        # Evaluate threshold
        triggered = rule.evaluate_threshold(results)

        # Generate alert content if triggered
        alert_title = ""
        alert_body = ""
        suppression_key = None

        if triggered:
            try:
                alert_content = rule.generate_alert_content(results)
                alert_title = alert_content["title"]
                alert_body = alert_content["body"]

                # Generate suppression key
                if results and rule.suppression:
                    suppression_key = rule.get_suppression_key(results[0])
            except Exception as e:
                return DetectionResult(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    triggered=False,
                    timestamp=datetime.utcnow(),
                    error=f"Failed to generate alert: {str(e)}"
                )

        return DetectionResult(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            triggered=triggered,
            timestamp=datetime.utcnow(),
            results=results,
            alert_title=alert_title,
            alert_body=alert_body,
            suppression_key=suppression_key
        )

    def execute_all_rules(
        self,
        time_window_start: Optional[datetime] = None,
        time_window_end: Optional[datetime] = None
    ) -> List[DetectionResult]:
        """Execute all enabled rules.

        Args:
            time_window_start: Start of time window
            time_window_end: End of time window

        Returns:
            List of DetectionResults
        """
        rules = self.rule_loader.get_enabled_rules()
        results = []

        for rule in rules:
            result = self.execute_rule(rule, time_window_start, time_window_end)
            results.append(result)

        return results

    def execute_rule_by_id(
        self,
        rule_id: str,
        time_window_start: Optional[datetime] = None,
        time_window_end: Optional[datetime] = None
    ) -> Optional[DetectionResult]:
        """Execute a specific rule by ID.

        Args:
            rule_id: Rule identifier
            time_window_start: Start of time window
            time_window_end: End of time window

        Returns:
            DetectionResult or None if rule not found
        """
        rule = self.rule_loader.get_rule_by_id(rule_id)
        if not rule:
            return None

        return self.execute_rule(rule, time_window_start, time_window_end)

    def get_triggered_alerts(
        self,
        results: List[DetectionResult],
        check_suppression: bool = True
    ) -> List[DetectionResult]:
        """Filter results to only triggered alerts.

        Args:
            results: List of DetectionResults
            check_suppression: Whether to check suppression

        Returns:
            List of triggered alerts
        """
        triggered = [r for r in results if r.triggered and not r.error]

        if not check_suppression or not self.state_manager:
            return triggered

        # Check suppression
        non_suppressed = []
        for result in triggered:
            if result.suppression_key:
                if not self.state_manager.is_suppressed(result.suppression_key):
                    non_suppressed.append(result)
                    # Mark as suppressed
                    rule = self.rule_loader.get_rule_by_id(result.rule_id)
                    if rule and rule.suppression:
                        duration = self._parse_interval(rule.suppression.duration)
                        self.state_manager.suppress_alert(
                            result.suppression_key,
                            duration
                        )
            else:
                non_suppressed.append(result)

        return non_suppressed

    def _parse_interval(self, interval_str: str) -> timedelta:
        """Parse interval string to timedelta.

        Args:
            interval_str: Interval string (e.g., '5m', '1h', '24h')

        Returns:
            timedelta object
        """
        match = re.match(r'^(\d+)([smhd])$', interval_str)
        if not match:
            raise ValueError(f"Invalid interval format: {interval_str}")

        value = int(match.group(1))
        unit = match.group(2)

        if unit == 's':
            return timedelta(seconds=value)
        elif unit == 'm':
            return timedelta(minutes=value)
        elif unit == 'h':
            return timedelta(hours=value)
        elif unit == 'd':
            return timedelta(days=value)
        else:
            raise ValueError(f"Unknown time unit: {unit}")
