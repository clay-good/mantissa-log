"""Prompt templates for LLM-based SQL generation."""

from typing import Dict, List, Optional


class PromptBuilder:
    """Builds prompts for SQL generation from natural language."""

    SYSTEM_PROMPT_TEMPLATE = """You are a security analyst assistant that converts natural language questions
into SQL queries for a security data lake. You are querying AWS Athena using
standard SQL syntax.

CRITICAL RULES:
1. ONLY output the SQL query, nothing else. No explanations, no markdown.
2. Always include appropriate time filters to limit data scanned.
3. Use partition columns (year, month, day) in WHERE clauses for efficiency.
4. Limit results to 1000 rows unless specifically asked for more.
5. Use the normalized views when possible for simpler queries.
6. For timestamp comparisons, use ISO 8601 format strings.

SECURITY CONTEXT:
- You are helping investigate security events
- Common tasks include: finding failed logins, tracking user activity,
  identifying suspicious network connections, auditing IAM changes
- Always consider time ranges to scope investigations appropriately

LOG SOURCE HEALTH MONITORING:
- The log_source_health table tracks the health state of every log source
  feeding into Mantissa Log.
- Each row represents one source_type (e.g., 'okta', 'cloudtrail') for a
  given tenant_id.
- Status values: HEALTHY, DELAYED, SILENT, VOLUME_ANOMALY, UNKNOWN.
- DELAYED means data is arriving slower than expected but within silence
  threshold. SILENT means no data has arrived within the silence threshold.
- VOLUME_ANOMALY means data is arriving but volume deviates significantly
  from the hourly baseline (z-score based).
- Use this table to answer questions about which sources are unhealthy,
  when data gaps occurred, volume trends, and source reliability.
- For volume trend queries over time, query the individual source tables
  (e.g., okta, cloudtrail) using the partition columns and COUNT(*)
  grouped by hour/day.
- The gap_windows column contains detected data gap periods as a JSON
  array of {{start, end}} pairs.

NETWORK DETECTION AND RESPONSE (NDR):
- The network_flows table contains normalised flow records from VPC flow
  logs (AWS/GCP/Azure), Zeek conn.log, and Suricata flow events.
- The dns_queries table contains DNS query logs from Route 53, GCP Cloud
  DNS, Azure DNS, Zeek dns.log, and Suricata DNS events.
- The firewall_events table contains firewall and IDS/IPS events from
  AWS Network Firewall, GCP Firewall, Azure Firewall, and Suricata alerts.
- All NDR tables are partitioned by year, month, day, hour.
- Use is_internal to filter RFC 1918 internal traffic vs external.
- Use subdomain_entropy (Shannon entropy) to detect DNS tunneling/DGA.
  Values above 3.5 are suspicious.
- Use conn_state for Zeek connection analysis: SF=normal, S0=SYN only,
  REJ=rejected, RSTO/RSTR=reset.
- Join network_flows with dns_queries on destination_ip to correlate
  connections with domain lookups.

SCHEMA INFORMATION:
{schema_context}

EXAMPLE QUERIES:
{examples}

USER QUESTION: {user_query}
SQL:"""

    def __init__(self):
        """Initialize prompt builder."""
        self.example_queries = self._get_example_queries()

    def build_query_prompt(
        self,
        user_query: str,
        schema_context: str,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        query_examples: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        """Build complete prompt for SQL generation.

        Args:
            user_query: User's natural language question
            schema_context: Schema context string
            conversation_history: Optional conversation history
            query_examples: Optional additional query examples

        Returns:
            Complete prompt string
        """
        examples = query_examples or self.example_queries
        examples_text = self._format_examples(examples)

        if conversation_history:
            history_text = self._format_conversation_history(conversation_history)
            examples_text = f"{examples_text}\n\nCONVERSATION HISTORY:\n{history_text}"

        return self.SYSTEM_PROMPT_TEMPLATE.format(
            schema_context=schema_context,
            examples=examples_text,
            user_query=user_query,
        )

    def build_explanation_prompt(
        self, sql_query: str, results: List[Dict]
    ) -> str:
        """Build prompt for explaining query results.

        Args:
            sql_query: SQL query that was executed
            results: Query results

        Returns:
            Explanation prompt
        """
        result_summary = self._format_results_summary(results)

        return f"""Given this SQL query and its results, provide a clear, concise explanation
for a security analyst.

SQL Query:
{sql_query}

Results ({len(results)} rows):
{result_summary}

Provide a 2-3 sentence summary of what these results show and any notable patterns
or security concerns."""

    def build_refinement_prompt(
        self, original_query: str, generated_sql: str, error: str
    ) -> str:
        """Build prompt for fixing SQL errors.

        Args:
            original_query: Original natural language query
            generated_sql: Generated SQL that failed
            error: Error message from execution

        Returns:
            Refinement prompt
        """
        return f"""The following SQL query failed with an error. Fix the query to address the error.

Original Question: {original_query}

Generated SQL:
{generated_sql}

Error:
{error}

Output ONLY the corrected SQL query, nothing else.
SQL:"""

    def build_query_refinement_prompt(
        self,
        original_question: str,
        original_sql: str,
        refinement_request: str,
        schema_context: str
    ) -> str:
        """Build prompt for refining a query based on user feedback.

        Args:
            original_question: Original natural language question
            original_sql: Previously generated SQL
            refinement_request: User's refinement request
            schema_context: Schema context information

        Returns:
            Refinement prompt
        """
        return f"""You are refining an existing SQL query based on user feedback.

Original Question: {original_question}

Current SQL Query:
{original_sql}

User's Refinement Request:
{refinement_request}

{schema_context}

Generate a refined SQL query that addresses the user's feedback while maintaining the original intent.

Output ONLY the SQL query, nothing else.
SQL:"""

    def _get_example_queries(self) -> List[Dict[str, str]]:
        """Get example query library.

        Returns:
            List of example query dictionaries
        """
        return [
            {
                "user": "Show me failed logins in the last 24 hours",
                "sql": """SELECT eventtime, useridentity.username, sourceipaddress, errorcode
FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
  AND errorcode IS NOT NULL
  AND eventtime >= cast(date_add('hour', -24, current_timestamp) as varchar)
  AND year = year(current_date)
  AND month = month(current_date)
  AND day >= day(date_add('day', -1, current_date))
ORDER BY eventtime DESC
LIMIT 1000""",
            },
            {
                "user": "What IPs has user john.doe connected from this week?",
                "sql": """SELECT DISTINCT sourceipaddress,
  MIN(eventtime) as first_seen,
  MAX(eventtime) as last_seen,
  COUNT(*) as event_count
FROM cloudtrail_logs
WHERE useridentity.username = 'john.doe'
  AND eventtime >= cast(date_add('day', -7, current_timestamp) as varchar)
  AND year = year(current_date)
  AND month = month(current_date)
  AND day >= day(date_add('day', -7, current_date))
GROUP BY sourceipaddress
ORDER BY event_count DESC""",
            },
            {
                "user": "Show me all S3 bucket deletions in the past week",
                "sql": """SELECT eventtime, useridentity.username, sourceipaddress,
  requestparameters, eventname
FROM cloudtrail_logs
WHERE eventname IN ('DeleteBucket', 'DeleteBucketPolicy')
  AND eventsource = 's3.amazonaws.com'
  AND eventtime >= cast(date_add('day', -7, current_timestamp) as varchar)
  AND year = year(current_date)
  AND month = month(current_date)
  AND day >= day(date_add('day', -7, current_date))
ORDER BY eventtime DESC
LIMIT 1000""",
            },
            {
                "user": "Find top 10 IPs by network traffic volume today",
                "sql": """SELECT srcaddr,
  SUM(bytes) as total_bytes,
  SUM(packets) as total_packets,
  COUNT(*) as flow_count
FROM vpc_flow_logs
WHERE year = year(current_date)
  AND month = month(current_date)
  AND day = day(current_date)
  AND action = 'ACCEPT'
GROUP BY srcaddr
ORDER BY total_bytes DESC
LIMIT 10""",
            },
            {
                "user": "Show me high severity GuardDuty findings from the last 3 days",
                "sql": """SELECT createdat, type, severity, title, description
FROM guardduty_findings
WHERE severity >= 7.0
  AND createdat >= cast(date_add('day', -3, current_timestamp) as varchar)
  AND year = year(current_date)
  AND month = month(current_date)
  AND day >= day(date_add('day', -3, current_date))
ORDER BY severity DESC, createdat DESC
LIMIT 1000""",
            },
            {
                "user": "List all IAM policy changes in the last 30 days",
                "sql": """SELECT eventtime, useridentity.username, eventname,
  requestparameters, sourceipaddress
FROM cloudtrail_logs
WHERE eventname IN ('PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy',
  'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy',
  'DeleteUserPolicy', 'DeleteRolePolicy', 'DeleteGroupPolicy')
  AND eventtime >= cast(date_add('day', -30, current_timestamp) as varchar)
  AND year = year(current_date)
  AND month = month(current_date)
  AND day >= day(date_add('day', -30, current_date))
ORDER BY eventtime DESC
LIMIT 1000""",
            },
            {
                "user": "Find failed network connections to port 22",
                "sql": """SELECT srcaddr, dstaddr, start, end, packets, bytes
FROM vpc_flow_logs
WHERE dstport = 22
  AND action = 'REJECT'
  AND year = year(current_date)
  AND month = month(current_date)
  AND day = day(current_date)
ORDER BY start DESC
LIMIT 1000""",
            },
            {
                "user": "Show API calls from IP 192.168.1.100 in the past 24 hours",
                "sql": """SELECT eventtime, eventname, eventsource,
  useridentity.username, errorcode
FROM cloudtrail_logs
WHERE sourceipaddress = '192.168.1.100'
  AND eventtime >= cast(date_add('hour', -24, current_timestamp) as varchar)
  AND year = year(current_date)
  AND month = month(current_date)
  AND day >= day(date_add('day', -1, current_date))
ORDER BY eventtime DESC
LIMIT 1000""",
            },
            {
                "user": "Count events by user for the last 7 days",
                "sql": """SELECT useridentity.username as user,
  COUNT(*) as event_count,
  COUNT(DISTINCT eventname) as unique_actions
FROM cloudtrail_logs
WHERE eventtime >= cast(date_add('day', -7, current_timestamp) as varchar)
  AND year = year(current_date)
  AND month = month(current_date)
  AND day >= day(date_add('day', -7, current_date))
  AND useridentity.username IS NOT NULL
GROUP BY useridentity.username
ORDER BY event_count DESC
LIMIT 100""",
            },
            {
                "user": "Find all root account usage this month",
                "sql": """SELECT eventtime, eventname, eventsource,
  sourceipaddress, useragent
FROM cloudtrail_logs
WHERE useridentity.type = 'Root'
  AND year = year(current_date)
  AND month = month(current_date)
ORDER BY eventtime DESC
LIMIT 1000""",
            },
            {
                "user": "Show application errors from the last hour",
                "sql": """SELECT timestamp, service, level, message, source_ip
FROM application_logs
WHERE level IN ('ERROR', 'FATAL', 'CRITICAL')
  AND timestamp >= cast(date_add('hour', -1, current_timestamp) as varchar)
  AND year = year(current_date)
  AND month = month(current_date)
  AND day = day(current_date)
ORDER BY timestamp DESC
LIMIT 1000""",
            },
            {
                "user": "List all CreateAccessKey events with the user who created them",
                "sql": """SELECT eventtime, useridentity.username,
  responseelements, sourceipaddress
FROM cloudtrail_logs
WHERE eventname = 'CreateAccessKey'
  AND eventtime >= cast(date_add('day', -30, current_timestamp) as varchar)
  AND year = year(current_date)
  AND month = month(current_date)
  AND day >= day(date_add('day', -30, current_date))
ORDER BY eventtime DESC
LIMIT 1000""",
            },
            {
                "user": "Find network connections to external IPs on port 443",
                "sql": """SELECT srcaddr, dstaddr,
  from_unixtime(start) as connection_time,
  packets, bytes
FROM vpc_flow_logs
WHERE dstport = 443
  AND action = 'ACCEPT'
  AND year = year(current_date)
  AND month = month(current_date)
  AND day = day(current_date)
  AND NOT regexp_like(dstaddr, '^10\\.|^172\\.(1[6-9]|2[0-9]|3[0-1])\\.|^192\\.168\\.')
ORDER BY start DESC
LIMIT 1000""",
            },
            {
                "user": "Show me permission denied errors grouped by user",
                "sql": """SELECT useridentity.username,
  COUNT(*) as denied_count,
  COUNT(DISTINCT eventname) as unique_actions,
  ARRAY_AGG(DISTINCT eventname) as attempted_actions
FROM cloudtrail_logs
WHERE errorcode = 'AccessDenied'
  AND eventtime >= cast(date_add('day', -7, current_timestamp) as varchar)
  AND year = year(current_date)
  AND month = month(current_date)
  AND day >= day(date_add('day', -7, current_date))
GROUP BY useridentity.username
ORDER BY denied_count DESC
LIMIT 100""",
            },
            {
                "user": "Find data transfer spikes over 1GB in VPC flows",
                "sql": """SELECT srcaddr, dstaddr,
  from_unixtime(start) as flow_start,
  from_unixtime(end) as flow_end,
  bytes,
  bytes / 1073741824.0 as gigabytes
FROM vpc_flow_logs
WHERE bytes > 1073741824
  AND year = year(current_date)
  AND month = month(current_date)
  AND day = day(current_date)
ORDER BY bytes DESC
LIMIT 100""",
            },
            {
                "user": "Which log sources are currently unhealthy?",
                "sql": """SELECT source_type, status, consecutive_failures,
  last_event_timestamp, last_check_timestamp,
  event_count_current_window, baseline_hourly_volume
FROM log_source_health
WHERE status != 'HEALTHY'
  AND status != 'UNKNOWN'
ORDER BY consecutive_failures DESC""",
            },
            {
                "user": "Show me the volume trend for Okta logs over the last 7 days",
                "sql": """SELECT year, month, day, hour,
  COUNT(*) as event_count
FROM okta
WHERE CONCAT(year, '-', month, '-', day) >= date_format(date_add('day', -7, current_date), '%Y-%m-%d')
GROUP BY year, month, day, hour
ORDER BY year, month, day, hour""",
            },
            {
                "user": "When was the last time CloudTrail had a data gap?",
                "sql": """SELECT source_type, gap_windows,
  last_event_timestamp, status, consecutive_failures
FROM log_source_health
WHERE source_type = 'cloudtrail'""",
            },
            {
                "user": "Are all identity provider log sources sending data?",
                "sql": """SELECT source_type, status, last_event_timestamp,
  event_count_current_window, consecutive_failures
FROM log_source_health
WHERE source_type IN ('okta', 'duo', 'microsoft365', 'google_workspace', 'onepassword')
ORDER BY status, source_type""",
            },
            {
                "user": "Which sources have been silent for more than 2 hours?",
                "sql": """SELECT source_type, status, last_event_timestamp,
  consecutive_failures, baseline_hourly_volume
FROM log_source_health
WHERE status = 'SILENT'
  AND last_event_timestamp < date_format(date_add('hour', -2, current_timestamp), '%Y-%m-%dT%H:%i:%s')
ORDER BY last_event_timestamp ASC""",
            },
            {
                "user": "Which internal hosts communicated with external IPs on non-standard ports in the last 24 hours?",
                "sql": """SELECT source_ip, destination_ip, destination_port,
  protocol, SUM(bytes_sent) as total_bytes, COUNT(*) as connection_count
FROM network_flows
WHERE is_internal = false
  AND source_ip LIKE '10.%' OR source_ip LIKE '172.1%' OR source_ip LIKE '192.168.%'
  AND destination_port NOT IN (80, 443, 53, 22, 25, 993, 587, 8080, 8443)
  AND timestamp >= cast(date_add('hour', -24, current_timestamp) as varchar)
  AND year = cast(year(current_date) as varchar)
  AND month = lpad(cast(month(current_date) as varchar), 2, '0')
  AND day >= lpad(cast(day(date_add('day', -1, current_date)) as varchar), 2, '0')
GROUP BY source_ip, destination_ip, destination_port, protocol
ORDER BY connection_count DESC
LIMIT 100""",
            },
            {
                "user": "Show me the top talkers by bytes transferred outbound",
                "sql": """SELECT source_ip,
  SUM(bytes_sent) as total_bytes_sent,
  SUM(bytes_received) as total_bytes_received,
  COUNT(*) as flow_count,
  COUNT(DISTINCT destination_ip) as unique_destinations
FROM network_flows
WHERE direction = 'outbound'
  AND year = cast(year(current_date) as varchar)
  AND month = lpad(cast(month(current_date) as varchar), 2, '0')
  AND day = lpad(cast(day(current_date) as varchar), 2, '0')
GROUP BY source_ip
ORDER BY total_bytes_sent DESC
LIMIT 20""",
            },
            {
                "user": "Find all DNS queries with high entropy subdomains",
                "sql": """SELECT source_ip, query_name, query_type,
  subdomain_entropy, subdomain_label_count,
  response_code, source_type
FROM dns_queries
WHERE subdomain_entropy > 3.5
  AND timestamp >= cast(date_add('hour', -24, current_timestamp) as varchar)
  AND year = cast(year(current_date) as varchar)
  AND month = lpad(cast(month(current_date) as varchar), 2, '0')
  AND day >= lpad(cast(day(date_add('day', -1, current_date)) as varchar), 2, '0')
ORDER BY subdomain_entropy DESC
LIMIT 1000""",
            },
            {
                "user": "What are the most queried domains by internal hosts today?",
                "sql": """SELECT query_name,
  COUNT(*) as query_count,
  COUNT(DISTINCT source_ip) as unique_clients,
  ARRAY_AGG(DISTINCT query_type) as query_types
FROM dns_queries
WHERE year = cast(year(current_date) as varchar)
  AND month = lpad(cast(month(current_date) as varchar), 2, '0')
  AND day = lpad(cast(day(current_date) as varchar), 2, '0')
GROUP BY query_name
ORDER BY query_count DESC
LIMIT 50""",
            },
            {
                "user": "Show me all denied firewall connections grouped by source IP",
                "sql": """SELECT source_ip,
  COUNT(*) as denied_count,
  COUNT(DISTINCT destination_ip) as unique_targets,
  COUNT(DISTINCT destination_port) as unique_ports,
  ARRAY_AGG(DISTINCT firewall_rule_name) as rules_triggered
FROM firewall_events
WHERE action IN ('deny', 'drop', 'blocked')
  AND timestamp >= cast(date_add('hour', -24, current_timestamp) as varchar)
  AND year = cast(year(current_date) as varchar)
  AND month = lpad(cast(month(current_date) as varchar), 2, '0')
  AND day >= lpad(cast(day(date_add('day', -1, current_date)) as varchar), 2, '0')
GROUP BY source_ip
ORDER BY denied_count DESC
LIMIT 50""",
            },
            {
                "user": "Find any regular interval connections to the same external IP (possible beaconing)",
                "sql": """SELECT source_ip, destination_ip, destination_port,
  COUNT(*) as connection_count,
  MIN(timestamp) as first_seen,
  MAX(timestamp) as last_seen
FROM network_flows
WHERE is_internal = false
  AND action = 'accept'
  AND timestamp >= cast(date_add('hour', -24, current_timestamp) as varchar)
  AND year = cast(year(current_date) as varchar)
  AND month = lpad(cast(month(current_date) as varchar), 2, '0')
  AND day >= lpad(cast(day(date_add('day', -1, current_date)) as varchar), 2, '0')
GROUP BY source_ip, destination_ip, destination_port
HAVING COUNT(*) >= 10
ORDER BY connection_count DESC
LIMIT 100""",
            },
            {
                "user": "Which hosts made connections on port 4444, 5555, or 8888?",
                "sql": """SELECT source_ip, destination_ip, destination_port,
  protocol, timestamp, cloud_provider, source_type
FROM network_flows
WHERE destination_port IN (4444, 5555, 8888)
  AND timestamp >= cast(date_add('day', -7, current_timestamp) as varchar)
  AND year = cast(year(current_date) as varchar)
  AND month = lpad(cast(month(current_date) as varchar), 2, '0')
  AND day >= lpad(cast(day(date_add('day', -7, current_date)) as varchar), 2, '0')
ORDER BY timestamp DESC
LIMIT 1000""",
            },
            {
                "user": "Show me all TXT record DNS queries in the last hour",
                "sql": """SELECT source_ip, query_name, response_code,
  subdomain_entropy, resolved_ips, source_type
FROM dns_queries
WHERE query_type = 'TXT'
  AND timestamp >= cast(date_add('hour', -1, current_timestamp) as varchar)
  AND year = cast(year(current_date) as varchar)
  AND month = lpad(cast(month(current_date) as varchar), 2, '0')
  AND day = lpad(cast(day(current_date) as varchar), 2, '0')
ORDER BY timestamp DESC
LIMIT 1000""",
            },
            {
                "user": "Find internal hosts that connected to more than 50 unique destination IPs in the last hour (possible scanning)",
                "sql": """SELECT source_ip,
  COUNT(DISTINCT destination_ip) as unique_destinations,
  COUNT(DISTINCT destination_port) as unique_ports,
  COUNT(*) as total_connections,
  SUM(bytes_sent) as total_bytes
FROM network_flows
WHERE source_ip LIKE '10.%' OR source_ip LIKE '172.1%' OR source_ip LIKE '192.168.%'
  AND timestamp >= cast(date_add('hour', -1, current_timestamp) as varchar)
  AND year = cast(year(current_date) as varchar)
  AND month = lpad(cast(month(current_date) as varchar), 2, '0')
  AND day = lpad(cast(day(current_date) as varchar), 2, '0')
GROUP BY source_ip
HAVING COUNT(DISTINCT destination_ip) > 50
ORDER BY unique_destinations DESC
LIMIT 50""",
            },
        ]

    def _format_examples(self, examples: List[Dict[str, str]]) -> str:
        """Format examples for prompt.

        Args:
            examples: List of example dictionaries

        Returns:
            Formatted examples string
        """
        formatted = []
        for example in examples:
            formatted.append(f"User: \"{example['user']}\"")
            formatted.append(f"SQL: {example['sql']}")
            formatted.append("")

        return "\n".join(formatted)

    def _format_conversation_history(
        self, history: List[Dict[str, str]]
    ) -> str:
        """Format conversation history.

        Args:
            history: List of conversation exchanges

        Returns:
            Formatted history string
        """
        formatted = []
        for exchange in history:
            if "user" in exchange:
                formatted.append(f"User: {exchange['user']}")
            if "sql" in exchange:
                formatted.append(f"SQL: {exchange['sql']}")
            if "result" in exchange:
                formatted.append(f"Result: {exchange['result']}")
            formatted.append("")

        return "\n".join(formatted)

    def _format_results_summary(self, results: List[Dict]) -> str:
        """Format results summary for explanation.

        Args:
            results: Query results

        Returns:
            Formatted summary
        """
        if not results:
            return "No results"

        if len(results) <= 5:
            return str(results)

        summary_lines = []
        for i, result in enumerate(results[:5], 1):
            summary_lines.append(f"{i}. {result}")

        if len(results) > 5:
            summary_lines.append(f"... and {len(results) - 5} more rows")

        return "\n".join(summary_lines)
