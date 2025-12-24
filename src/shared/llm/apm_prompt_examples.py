"""APM-specific prompt examples for natural language query generation.

This module provides example queries that help the LLM understand how to
translate natural language questions about application performance into
appropriate SQL queries against the APM tables.

Example patterns include:
- Latency analysis (slow service queries)
- Error investigation
- Service dependency queries
- Trace lookup and correlation
- Percentile calculations
"""

from typing import List, Dict, Any

# Example queries for few-shot learning
APM_QUERY_EXAMPLES: List[Dict[str, Any]] = [
    # Example 1: Slow service analysis
    {
        "user_query": "Why is the checkout service slow?",
        "intent": "latency_analysis",
        "tables_used": ["apm_traces", "apm_service_stats"],
        "sql_query": """
SELECT
    operation_name,
    COUNT(*) as request_count,
    AVG(duration_ms) as avg_latency_ms,
    APPROX_PERCENTILE(duration_ms, 0.50) as p50_ms,
    APPROX_PERCENTILE(duration_ms, 0.95) as p95_ms,
    APPROX_PERCENTILE(duration_ms, 0.99) as p99_ms,
    SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as error_count
FROM apm_traces
WHERE service_name = 'checkout-service'
    AND start_time >= date_add('hour', -1, current_timestamp)
    AND kind IN ('server', 'consumer')
GROUP BY operation_name
ORDER BY p95_ms DESC
LIMIT 20
""".strip(),
        "explanation": "Groups by operation to identify which specific endpoints are slow. Uses p95 for comparison as it excludes outliers while showing worst-case latency.",
    },
    # Example 2: Error traces in last hour
    {
        "user_query": "Show me error traces in the last hour",
        "intent": "error_investigation",
        "tables_used": ["apm_traces"],
        "sql_query": """
SELECT
    trace_id,
    span_id,
    service_name,
    operation_name,
    status_message as error_message,
    duration_ms,
    start_time,
    attributes
FROM apm_traces
WHERE status = 'error'
    AND start_time >= date_add('hour', -1, current_timestamp)
ORDER BY start_time DESC
LIMIT 100
""".strip(),
        "explanation": "Filters for error status spans in the last hour. Includes attributes which often contain error details and stack traces.",
    },
    # Example 3: Service dependency query
    {
        "user_query": "What services call the payment-api?",
        "intent": "dependency_analysis",
        "tables_used": ["apm_service_map"],
        "sql_query": """
SELECT
    source_service,
    call_count,
    error_count,
    error_rate,
    avg_latency_ms,
    p95_latency_ms
FROM apm_service_map
WHERE target_service = 'payment-api'
ORDER BY call_count DESC
""".strip(),
        "explanation": "Uses the service map view to find upstream services that call payment-api. Shows call volume and error rates for each caller.",
    },
    # Example 4: P99 latency over time
    {
        "user_query": "Show me p99 latency for the user-service over the last 24 hours",
        "intent": "latency_trending",
        "tables_used": ["apm_traces"],
        "sql_query": """
SELECT
    date_trunc('hour', from_iso8601_timestamp(start_time)) as hour,
    COUNT(*) as request_count,
    APPROX_PERCENTILE(duration_ms, 0.99) as p99_latency_ms,
    AVG(duration_ms) as avg_latency_ms
FROM apm_traces
WHERE service_name = 'user-service'
    AND kind IN ('server', 'consumer')
    AND start_time >= date_add('hour', -24, current_timestamp)
GROUP BY date_trunc('hour', from_iso8601_timestamp(start_time))
ORDER BY hour ASC
""".strip(),
        "explanation": "Groups by hour to show latency trend. Uses date_trunc for hourly buckets and filters for server/consumer spans to measure inbound request latency.",
    },
    # Example 5: Slowest endpoints
    {
        "user_query": "Find the slowest endpoints",
        "intent": "latency_analysis",
        "tables_used": ["apm_traces"],
        "sql_query": """
SELECT
    service_name,
    operation_name,
    COUNT(*) as request_count,
    AVG(duration_ms) as avg_latency_ms,
    APPROX_PERCENTILE(duration_ms, 0.95) as p95_latency_ms,
    MAX(duration_ms) as max_latency_ms
FROM apm_traces
WHERE kind IN ('server', 'consumer')
    AND start_time >= date_add('hour', -1, current_timestamp)
GROUP BY service_name, operation_name
HAVING COUNT(*) >= 10
ORDER BY p95_latency_ms DESC
LIMIT 20
""".strip(),
        "explanation": "Ranks all endpoints by p95 latency. HAVING clause ensures minimum sample size for statistical significance.",
    },
    # Example 6: Trace lookup
    {
        "user_query": "Show me all spans for trace abc123def456",
        "intent": "trace_lookup",
        "tables_used": ["apm_traces"],
        "sql_query": """
SELECT
    span_id,
    parent_span_id,
    service_name,
    operation_name,
    kind,
    status,
    duration_ms,
    start_time,
    end_time,
    attributes
FROM apm_traces
WHERE trace_id = 'abc123def456'
ORDER BY start_time ASC
""".strip(),
        "explanation": "Retrieves all spans for a specific trace, ordered by time to show the request flow.",
    },
    # Example 7: Error rate by service
    {
        "user_query": "Which services have the highest error rate?",
        "intent": "error_analysis",
        "tables_used": ["apm_traces"],
        "sql_query": """
SELECT
    service_name,
    COUNT(*) as total_requests,
    SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as error_count,
    CAST(SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS DOUBLE) / COUNT(*) as error_rate
FROM apm_traces
WHERE kind IN ('server', 'consumer')
    AND start_time >= date_add('hour', -1, current_timestamp)
GROUP BY service_name
HAVING COUNT(*) >= 100
ORDER BY error_rate DESC
LIMIT 20
""".strip(),
        "explanation": "Calculates error rate per service. Minimum request threshold ensures meaningful error rates.",
    },
    # Example 8: Downstream impact analysis
    {
        "user_query": "What services does order-service depend on?",
        "intent": "dependency_analysis",
        "tables_used": ["apm_service_map"],
        "sql_query": """
SELECT
    target_service,
    call_count,
    error_count,
    error_rate,
    avg_latency_ms,
    p95_latency_ms
FROM apm_service_map
WHERE source_service = 'order-service'
ORDER BY call_count DESC
""".strip(),
        "explanation": "Finds downstream dependencies of order-service by looking at outbound calls.",
    },
    # Example 9: Root cause analysis
    {
        "user_query": "Why are requests to /api/checkout failing?",
        "intent": "error_investigation",
        "tables_used": ["apm_traces"],
        "sql_query": """
WITH error_traces AS (
    SELECT DISTINCT trace_id
    FROM apm_traces
    WHERE operation_name LIKE '%/api/checkout%'
        AND status = 'error'
        AND start_time >= date_add('hour', -1, current_timestamp)
    LIMIT 100
)
SELECT
    t.service_name,
    t.operation_name,
    t.status,
    t.status_message,
    t.duration_ms,
    t.attributes
FROM apm_traces t
JOIN error_traces e ON t.trace_id = e.trace_id
WHERE t.status = 'error'
ORDER BY t.start_time ASC
""".strip(),
        "explanation": "First finds traces with errors at the checkout endpoint, then examines all error spans in those traces to identify root cause in downstream services.",
    },
    # Example 10: Metric analysis
    {
        "user_query": "Show CPU utilization for all services",
        "intent": "metric_analysis",
        "tables_used": ["apm_metrics"],
        "sql_query": """
SELECT
    service_name,
    AVG(value) as avg_cpu,
    MAX(value) as max_cpu,
    APPROX_PERCENTILE(value, 0.95) as p95_cpu
FROM apm_metrics
WHERE name = 'process.cpu.utilization'
    AND timestamp >= date_add('hour', -1, current_timestamp)
GROUP BY service_name
ORDER BY avg_cpu DESC
""".strip(),
        "explanation": "Aggregates CPU utilization metric across services. Uses standard OpenTelemetry metric name.",
    },
    # Example 11: Request throughput
    {
        "user_query": "What is the request throughput per service?",
        "intent": "throughput_analysis",
        "tables_used": ["apm_traces"],
        "sql_query": """
SELECT
    service_name,
    COUNT(*) as total_requests,
    COUNT(*) / 3600.0 as requests_per_second
FROM apm_traces
WHERE kind IN ('server', 'consumer')
    AND start_time >= date_add('hour', -1, current_timestamp)
GROUP BY service_name
ORDER BY total_requests DESC
""".strip(),
        "explanation": "Calculates requests per second by dividing total count by time window (1 hour = 3600 seconds).",
    },
    # Example 12: Critical path analysis
    {
        "user_query": "What is the critical path for slow checkout requests?",
        "intent": "trace_analysis",
        "tables_used": ["apm_traces"],
        "sql_query": """
WITH slow_checkouts AS (
    SELECT trace_id
    FROM apm_traces
    WHERE operation_name LIKE '%checkout%'
        AND kind = 'server'
        AND duration_ms > 1000
        AND start_time >= date_add('hour', -1, current_timestamp)
    LIMIT 10
)
SELECT
    t.service_name,
    t.operation_name,
    t.duration_ms,
    t.kind,
    t.parent_span_id IS NULL as is_root
FROM apm_traces t
JOIN slow_checkouts s ON t.trace_id = s.trace_id
ORDER BY t.trace_id, t.start_time ASC
""".strip(),
        "explanation": "Finds slow checkout traces then examines all spans to identify which services/operations contribute most to total latency.",
    },
]

# Query intent patterns for classification
APM_INTENT_PATTERNS = {
    "latency_analysis": {
        "keywords": ["slow", "latency", "response time", "duration", "performance", "p50", "p95", "p99", "percentile"],
        "primary_table": "apm_traces",
        "secondary_tables": ["apm_service_stats"],
    },
    "error_investigation": {
        "keywords": ["error", "failure", "failed", "exception", "500", "4xx", "5xx", "bug", "issue"],
        "primary_table": "apm_traces",
        "secondary_tables": [],
    },
    "dependency_analysis": {
        "keywords": ["calls", "depends", "upstream", "downstream", "service map", "dependency", "communication"],
        "primary_table": "apm_service_map",
        "secondary_tables": ["apm_traces"],
    },
    "trace_lookup": {
        "keywords": ["trace", "transaction", "request", "span", "trace_id"],
        "primary_table": "apm_traces",
        "secondary_tables": [],
    },
    "metric_analysis": {
        "keywords": ["cpu", "memory", "disk", "metric", "utilization", "gauge", "counter", "histogram"],
        "primary_table": "apm_metrics",
        "secondary_tables": [],
    },
    "throughput_analysis": {
        "keywords": ["throughput", "requests per second", "rps", "qps", "volume", "traffic"],
        "primary_table": "apm_traces",
        "secondary_tables": ["apm_service_stats"],
    },
}


def get_relevant_examples(user_query: str, max_examples: int = 3) -> List[Dict[str, Any]]:
    """Get relevant APM query examples based on user query.

    Args:
        user_query: The user's natural language query
        max_examples: Maximum number of examples to return

    Returns:
        List of relevant example dictionaries
    """
    query_lower = user_query.lower()
    scored_examples = []

    for example in APM_QUERY_EXAMPLES:
        score = 0

        # Score based on intent keywords
        intent = example.get("intent", "")
        if intent in APM_INTENT_PATTERNS:
            for keyword in APM_INTENT_PATTERNS[intent]["keywords"]:
                if keyword in query_lower:
                    score += 2

        # Score based on query similarity
        example_query_lower = example["user_query"].lower()
        common_words = set(query_lower.split()) & set(example_query_lower.split())
        score += len(common_words)

        if score > 0:
            scored_examples.append((score, example))

    # Sort by score descending and return top examples
    scored_examples.sort(key=lambda x: x[0], reverse=True)
    return [ex for _, ex in scored_examples[:max_examples]]


def classify_query_intent(user_query: str) -> str:
    """Classify the intent of an APM query.

    Args:
        user_query: The user's natural language query

    Returns:
        Intent string (e.g., 'latency_analysis', 'error_investigation')
    """
    query_lower = user_query.lower()
    best_intent = "general"
    best_score = 0

    for intent, config in APM_INTENT_PATTERNS.items():
        score = sum(1 for kw in config["keywords"] if kw in query_lower)
        if score > best_score:
            best_score = score
            best_intent = intent

    return best_intent


def format_examples_for_prompt(examples: List[Dict[str, Any]]) -> str:
    """Format examples for inclusion in LLM prompt.

    Args:
        examples: List of example dictionaries

    Returns:
        Formatted string for prompt
    """
    if not examples:
        return ""

    lines = ["", "Example APM Queries:", ""]

    for i, example in enumerate(examples, 1):
        lines.append(f"Example {i}:")
        lines.append(f"User: \"{example['user_query']}\"")
        lines.append(f"SQL:")
        lines.append("```sql")
        lines.append(example["sql_query"])
        lines.append("```")
        if example.get("explanation"):
            lines.append(f"Note: {example['explanation']}")
        lines.append("")

    return "\n".join(lines)
