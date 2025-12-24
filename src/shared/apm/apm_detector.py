"""APM Detection Engine.

Specialized detection engine for Application Performance Monitoring (APM) patterns
including latency spikes, error rate increases, service availability, and cascade failures.

Unlike security detection rules that look for specific events, APM detection often
requires aggregate functions (p95, p99, rate, count) and baseline comparisons.
"""

import logging
import os
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)


@dataclass
class APMDetectionResult:
    """Result of an APM detection rule evaluation."""

    rule_id: str
    rule_name: str
    triggered: bool
    severity: str
    services_affected: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    dashboard_link: Optional[str] = None
    trace_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "triggered": self.triggered,
            "severity": self.severity,
            "services_affected": self.services_affected,
            "metrics": self.metrics,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
            "dashboard_link": self.dashboard_link,
            "trace_ids": self.trace_ids,
        }


@dataclass
class APMRule:
    """Represents an APM detection rule."""

    id: str
    title: str
    description: str
    level: str
    logsource: Dict[str, str]
    detection: Dict[str, Any]
    fields: List[str]
    tags: List[str]
    falsepositives: List[str]
    timeframe: str = "5m"
    baseline_comparison: bool = False
    enabled: bool = True

    @classmethod
    def from_dict(cls, rule_dict: Dict[str, Any]) -> "APMRule":
        """Create APMRule from dictionary (parsed YAML)."""
        detection = rule_dict.get("detection", {})
        return cls(
            id=rule_dict.get("id", ""),
            title=rule_dict.get("title", ""),
            description=rule_dict.get("description", ""),
            level=rule_dict.get("level", "medium"),
            logsource=rule_dict.get("logsource", {}),
            detection=detection,
            fields=rule_dict.get("fields", []),
            tags=rule_dict.get("tags", []),
            falsepositives=rule_dict.get("falsepositives", []),
            timeframe=detection.get("timeframe", "5m"),
            baseline_comparison=detection.get("baseline_comparison", False),
            enabled=rule_dict.get("status", "stable") != "disabled",
        )


class APMDetector:
    """APM-specific detection engine.

    Supports:
    - Aggregate functions (p95, p99, rate, count, avg)
    - Baseline comparisons
    - Time-window analysis
    - Service dependency analysis
    """

    def __init__(
        self,
        query_executor: Optional[Any] = None,
        baseline_store: Optional[Any] = None,
        dashboard_base_url: str = "",
    ):
        """Initialize APM detector.

        Args:
            query_executor: Callable to execute Athena/BigQuery queries
            baseline_store: Store for baseline metrics
            dashboard_base_url: Base URL for dashboard links in alerts
        """
        self.query_executor = query_executor
        self.baseline_store = baseline_store
        self.dashboard_base_url = dashboard_base_url
        self.rules: Dict[str, APMRule] = {}

    def load_apm_rules(self, rules_path: str) -> List[APMRule]:
        """Load APM detection rules from directory.

        Args:
            rules_path: Path to APM rules directory

        Returns:
            List of loaded APM rules
        """
        rules = []
        rules_dir = Path(rules_path)

        if not rules_dir.exists():
            logger.warning(f"APM rules path does not exist: {rules_path}")
            return rules

        # Load all YAML files
        yaml_files = list(rules_dir.glob("**/*.yml")) + list(rules_dir.glob("**/*.yaml"))

        for yaml_file in yaml_files:
            # Skip README files
            if yaml_file.name.lower() == "readme.md":
                continue

            try:
                with open(yaml_file, 'r') as f:
                    rule_dict = yaml.safe_load(f)

                if not rule_dict:
                    continue

                # Verify it's an APM rule
                logsource = rule_dict.get("logsource", {})
                if logsource.get("product") != "apm":
                    continue

                rule = APMRule.from_dict(rule_dict)
                rules.append(rule)
                self.rules[rule.id] = rule
                logger.debug(f"Loaded APM rule: {rule.id}")

            except yaml.YAMLError as e:
                logger.warning(f"Invalid YAML in {yaml_file}: {e}")
            except Exception as e:
                logger.warning(f"Error loading APM rule {yaml_file}: {e}")

        logger.info(f"Loaded {len(rules)} APM detection rules from {rules_path}")
        return rules

    def evaluate_latency_rule(
        self,
        rule: APMRule,
        start_time: datetime,
        end_time: datetime,
    ) -> APMDetectionResult:
        """Evaluate a latency-based detection rule.

        Args:
            rule: APM rule to evaluate
            start_time: Start of evaluation window
            end_time: End of evaluation window

        Returns:
            Detection result
        """
        result = APMDetectionResult(
            rule_id=rule.id,
            rule_name=rule.title,
            triggered=False,
            severity=rule.level,
        )

        try:
            # Build and execute query for latency metrics
            query = self._build_latency_query(rule, start_time, end_time)

            if self.query_executor:
                query_results = self.query_executor(query)
            else:
                # Mock results for testing
                query_results = []

            # Evaluate detection condition
            triggered_services = []
            for row in query_results:
                service_name = row.get("service_name", "unknown")
                operation_name = row.get("operation_name", "")
                p95_latency = row.get("p95_duration_ms", 0)

                # Default threshold: p95 > 2000ms
                threshold = self._extract_threshold(rule.detection, "p95", 2000)

                if p95_latency > threshold:
                    triggered_services.append(service_name)
                    result.metrics[f"{service_name}:{operation_name}"] = {
                        "p95_duration_ms": p95_latency,
                        "avg_duration_ms": row.get("avg_duration_ms", 0),
                        "request_count": row.get("request_count", 0),
                    }

            if triggered_services:
                result.triggered = True
                result.services_affected = list(set(triggered_services))
                result.details["threshold_ms"] = threshold
                result.dashboard_link = self._build_dashboard_link(
                    "latency", triggered_services, start_time, end_time
                )

        except Exception as e:
            logger.error(f"Error evaluating latency rule {rule.id}: {e}")
            result.details["error"] = str(e)

        return result

    def evaluate_error_rate_rule(
        self,
        rule: APMRule,
        start_time: datetime,
        end_time: datetime,
    ) -> APMDetectionResult:
        """Evaluate an error rate detection rule.

        Args:
            rule: APM rule to evaluate
            start_time: Start of evaluation window
            end_time: End of evaluation window

        Returns:
            Detection result
        """
        result = APMDetectionResult(
            rule_id=rule.id,
            rule_name=rule.title,
            triggered=False,
            severity=rule.level,
        )

        try:
            # Build and execute query for error rates
            query = self._build_error_rate_query(rule, start_time, end_time)

            if self.query_executor:
                query_results = self.query_executor(query)
            else:
                query_results = []

            # Evaluate detection condition
            triggered_services = []
            error_details = {}

            for row in query_results:
                service_name = row.get("service_name", "unknown")
                error_count = row.get("error_count", 0)
                total_count = row.get("total_count", 0)

                if total_count == 0:
                    continue

                error_rate = error_count / total_count

                # Default threshold: error_rate > 5%
                threshold = self._extract_threshold(rule.detection, "error_rate", 0.05)

                if error_rate > threshold:
                    triggered_services.append(service_name)
                    error_details[service_name] = {
                        "error_count": error_count,
                        "total_count": total_count,
                        "error_rate": round(error_rate * 100, 2),
                    }

            if triggered_services:
                result.triggered = True
                result.services_affected = list(set(triggered_services))
                result.metrics = error_details
                result.details["threshold_percent"] = threshold * 100
                result.dashboard_link = self._build_dashboard_link(
                    "errors", triggered_services, start_time, end_time
                )

                # Get sample trace IDs for investigation
                if self.query_executor:
                    result.trace_ids = self._get_error_trace_ids(
                        triggered_services, start_time, end_time
                    )

        except Exception as e:
            logger.error(f"Error evaluating error rate rule {rule.id}: {e}")
            result.details["error"] = str(e)

        return result

    def evaluate_availability_rule(
        self,
        rule: APMRule,
        start_time: datetime,
        end_time: datetime,
    ) -> APMDetectionResult:
        """Evaluate a service availability detection rule.

        Args:
            rule: APM rule to evaluate
            start_time: Start of evaluation window
            end_time: End of evaluation window

        Returns:
            Detection result
        """
        result = APMDetectionResult(
            rule_id=rule.id,
            rule_name=rule.title,
            triggered=False,
            severity=rule.level,
        )

        if not rule.baseline_comparison:
            result.details["error"] = "Availability rules require baseline comparison"
            return result

        try:
            # Get current request rates
            query = self._build_availability_query(rule, start_time, end_time)

            if self.query_executor:
                current_rates = self.query_executor(query)
            else:
                current_rates = []

            # Get baseline rates from store
            if self.baseline_store:
                baseline_rates = self.baseline_store.get_service_baselines(
                    start_time, end_time
                )
            else:
                baseline_rates = {}

            # Compare current to baseline
            down_services = []
            availability_details = {}

            for row in current_rates:
                service_name = row.get("service_name", "unknown")
                current_rate = row.get("request_rate", 0)

                baseline = baseline_rates.get(service_name, {})
                baseline_rate = baseline.get("avg_rate", 0)

                if baseline_rate > 1:  # Only check services with meaningful baseline
                    # Service considered down if rate < 10% of baseline
                    if current_rate < (baseline_rate * 0.1):
                        down_services.append(service_name)
                        availability_details[service_name] = {
                            "current_rate": current_rate,
                            "baseline_rate": baseline_rate,
                            "last_seen": row.get("last_seen", "unknown"),
                        }

            if down_services:
                result.triggered = True
                result.services_affected = down_services
                result.metrics = availability_details
                result.dashboard_link = self._build_dashboard_link(
                    "availability", down_services, start_time, end_time
                )

        except Exception as e:
            logger.error(f"Error evaluating availability rule {rule.id}: {e}")
            result.details["error"] = str(e)

        return result

    def evaluate_cascade_failure_rule(
        self,
        rule: APMRule,
        start_time: datetime,
        end_time: datetime,
    ) -> APMDetectionResult:
        """Evaluate a cascade failure detection rule.

        Args:
            rule: APM rule to evaluate
            start_time: Start of evaluation window
            end_time: End of evaluation window

        Returns:
            Detection result
        """
        result = APMDetectionResult(
            rule_id=rule.id,
            rule_name=rule.title,
            triggered=False,
            severity=rule.level,
        )

        try:
            # Get services with elevated error rates
            error_query = self._build_error_rate_query(rule, start_time, end_time)

            if self.query_executor:
                error_results = self.query_executor(error_query)
            else:
                error_results = []

            # Filter services with error rate > 10%
            elevated_error_services = {}
            for row in error_results:
                service_name = row.get("service_name", "unknown")
                error_count = row.get("error_count", 0)
                total_count = row.get("total_count", 0)

                if total_count > 0:
                    error_rate = error_count / total_count
                    if error_rate > 0.1:
                        elevated_error_services[service_name] = error_rate

            # Check if services are in dependency chain
            if len(elevated_error_services) >= 3:
                # Get service dependencies
                if self.query_executor:
                    dependencies = self._get_service_dependencies(start_time, end_time)
                else:
                    dependencies = {}

                # Find connected services with errors
                connected_services = self._find_connected_error_services(
                    elevated_error_services.keys(),
                    dependencies
                )

                if len(connected_services) >= 3:
                    result.triggered = True
                    result.services_affected = list(connected_services)
                    result.metrics = {
                        svc: {"error_rate": round(rate * 100, 2)}
                        for svc, rate in elevated_error_services.items()
                        if svc in connected_services
                    }
                    result.details["dependency_chain"] = list(connected_services)
                    result.dashboard_link = self._build_dashboard_link(
                        "cascade", list(connected_services), start_time, end_time
                    )

        except Exception as e:
            logger.error(f"Error evaluating cascade failure rule {rule.id}: {e}")
            result.details["error"] = str(e)

        return result

    def run_all_apm_rules(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> List[APMDetectionResult]:
        """Run all loaded APM detection rules.

        Args:
            start_time: Start of evaluation window
            end_time: End of evaluation window

        Returns:
            List of detection results
        """
        results = []

        for rule_id, rule in self.rules.items():
            if not rule.enabled:
                continue

            try:
                # Determine rule type and evaluate
                if "latency" in rule.id.lower() or "slow" in rule.id.lower():
                    result = self.evaluate_latency_rule(rule, start_time, end_time)
                elif "error" in rule.id.lower():
                    result = self.evaluate_error_rate_rule(rule, start_time, end_time)
                elif "down" in rule.id.lower() or "availability" in rule.id.lower():
                    result = self.evaluate_availability_rule(rule, start_time, end_time)
                elif "cascade" in rule.id.lower():
                    result = self.evaluate_cascade_failure_rule(rule, start_time, end_time)
                else:
                    # Generic evaluation
                    result = self.evaluate_latency_rule(rule, start_time, end_time)

                results.append(result)

            except Exception as e:
                logger.error(f"Error running APM rule {rule_id}: {e}")
                results.append(APMDetectionResult(
                    rule_id=rule_id,
                    rule_name=rule.title,
                    triggered=False,
                    severity=rule.level,
                    details={"error": str(e)}
                ))

        return results

    def _build_latency_query(
        self,
        rule: APMRule,
        start_time: datetime,
        end_time: datetime,
    ) -> str:
        """Build SQL query for latency detection."""
        selection = rule.detection.get("selection", {})
        kind_filter = selection.get("kind", "server")

        return f"""
        SELECT
            service_name,
            operation_name,
            COUNT(*) as request_count,
            AVG(duration_ms) as avg_duration_ms,
            APPROX_PERCENTILE(duration_ms, 0.50) as p50_duration_ms,
            APPROX_PERCENTILE(duration_ms, 0.95) as p95_duration_ms,
            APPROX_PERCENTILE(duration_ms, 0.99) as p99_duration_ms
        FROM apm_traces
        WHERE timestamp >= '{start_time.isoformat()}'
          AND timestamp < '{end_time.isoformat()}'
          AND kind = '{kind_filter}'
        GROUP BY service_name, operation_name
        HAVING COUNT(*) >= 10
        """

    def _build_error_rate_query(
        self,
        rule: APMRule,
        start_time: datetime,
        end_time: datetime,
    ) -> str:
        """Build SQL query for error rate detection."""
        selection = rule.detection.get("selection", {})
        kind_filter = selection.get("kind", "server")

        return f"""
        SELECT
            service_name,
            COUNT(*) as total_count,
            SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as error_count
        FROM apm_traces
        WHERE timestamp >= '{start_time.isoformat()}'
          AND timestamp < '{end_time.isoformat()}'
          AND kind = '{kind_filter}'
        GROUP BY service_name
        HAVING COUNT(*) >= 10
        """

    def _build_availability_query(
        self,
        rule: APMRule,
        start_time: datetime,
        end_time: datetime,
    ) -> str:
        """Build SQL query for availability detection."""
        timeframe_minutes = self._parse_timeframe(rule.timeframe)

        return f"""
        SELECT
            service_name,
            COUNT(*) / {timeframe_minutes} as request_rate,
            MAX(timestamp) as last_seen
        FROM apm_traces
        WHERE timestamp >= '{start_time.isoformat()}'
          AND timestamp < '{end_time.isoformat()}'
          AND kind = 'server'
        GROUP BY service_name
        """

    def _get_service_dependencies(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> Dict[str, List[str]]:
        """Get service dependency map from trace data."""
        query = f"""
        SELECT DISTINCT
            parent.service_name as source_service,
            child.service_name as target_service
        FROM apm_traces parent
        JOIN apm_traces child ON parent.span_id = child.parent_span_id
            AND parent.trace_id = child.trace_id
        WHERE parent.timestamp >= '{start_time.isoformat()}'
          AND parent.timestamp < '{end_time.isoformat()}'
        """

        if self.query_executor:
            results = self.query_executor(query)
        else:
            results = []

        dependencies = {}
        for row in results:
            source = row.get("source_service", "")
            target = row.get("target_service", "")
            if source and target:
                if source not in dependencies:
                    dependencies[source] = []
                dependencies[source].append(target)

        return dependencies

    def _find_connected_error_services(
        self,
        error_services: List[str],
        dependencies: Dict[str, List[str]],
    ) -> set:
        """Find services in error that are connected via dependencies."""
        error_set = set(error_services)
        connected = set()

        # Build reverse dependency map
        reverse_deps = {}
        for source, targets in dependencies.items():
            for target in targets:
                if target not in reverse_deps:
                    reverse_deps[target] = []
                reverse_deps[target].append(source)

        # BFS to find connected services
        for service in error_services:
            # Check downstream
            if service in dependencies:
                for downstream in dependencies[service]:
                    if downstream in error_set:
                        connected.add(service)
                        connected.add(downstream)

            # Check upstream
            if service in reverse_deps:
                for upstream in reverse_deps[service]:
                    if upstream in error_set:
                        connected.add(service)
                        connected.add(upstream)

        return connected

    def _get_error_trace_ids(
        self,
        services: List[str],
        start_time: datetime,
        end_time: datetime,
        limit: int = 5,
    ) -> List[str]:
        """Get sample trace IDs for error investigation."""
        services_str = "', '".join(services)
        query = f"""
        SELECT DISTINCT trace_id
        FROM apm_traces
        WHERE timestamp >= '{start_time.isoformat()}'
          AND timestamp < '{end_time.isoformat()}'
          AND service_name IN ('{services_str}')
          AND status = 'error'
        LIMIT {limit}
        """

        if self.query_executor:
            results = self.query_executor(query)
            return [row.get("trace_id", "") for row in results if row.get("trace_id")]
        return []

    def _extract_threshold(
        self,
        detection: Dict[str, Any],
        metric_type: str,
        default: float,
    ) -> float:
        """Extract threshold value from detection condition."""
        condition = detection.get("condition", "")

        # Try to parse threshold from condition string
        # e.g., "p95(duration_ms) > 2000" -> 2000
        import re

        patterns = {
            "p95": r"p95\([^)]+\)\s*>\s*(\d+)",
            "p99": r"p99\([^)]+\)\s*>\s*(\d+)",
            "error_rate": r"error.*rate.*>\s*([\d.]+)",
        }

        pattern = patterns.get(metric_type)
        if pattern:
            match = re.search(pattern, condition, re.IGNORECASE)
            if match:
                return float(match.group(1))

        return default

    def _parse_timeframe(self, timeframe: str) -> int:
        """Parse timeframe string to minutes."""
        if timeframe.endswith("m"):
            return int(timeframe[:-1])
        elif timeframe.endswith("h"):
            return int(timeframe[:-1]) * 60
        elif timeframe.endswith("d"):
            return int(timeframe[:-1]) * 1440
        return 5  # Default 5 minutes

    def _build_dashboard_link(
        self,
        view_type: str,
        services: List[str],
        start_time: datetime,
        end_time: datetime,
    ) -> str:
        """Build link to APM dashboard with filters."""
        if not self.dashboard_base_url:
            return ""

        services_param = ",".join(services)
        return (
            f"{self.dashboard_base_url}/apm?"
            f"view={view_type}"
            f"&services={services_param}"
            f"&start={start_time.isoformat()}"
            f"&end={end_time.isoformat()}"
        )
