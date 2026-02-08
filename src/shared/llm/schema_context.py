"""Schema context builder for LLM prompts."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol
import logging

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


@dataclass
class ColumnInfo:
    """Column metadata information."""

    name: str
    type: str
    comment: Optional[str] = None


@dataclass
class TableInfo:
    """Table metadata information."""

    name: str
    description: Optional[str] = None
    columns: List[ColumnInfo] = field(default_factory=list)
    partitions: List[ColumnInfo] = field(default_factory=list)
    is_view: bool = False
    use_cases: List[str] = field(default_factory=list)


class SchemaSource(Protocol):
    """Protocol for schema information sources."""

    def get_tables(self) -> List[TableInfo]:
        """Get list of all tables.

        Returns:
            List of TableInfo objects
        """
        ...

    def get_columns(self, table_name: str) -> List[ColumnInfo]:
        """Get columns for a specific table.

        Args:
            table_name: Name of the table

        Returns:
            List of ColumnInfo objects
        """
        ...


class GlueSchemaSource:
    """AWS Glue Data Catalog schema source."""

    def __init__(self, database_name: str, region: str = "us-east-1"):
        """Initialize Glue schema source.

        Args:
            database_name: Glue database name
            region: AWS region
        """
        self.database_name = database_name
        self.region = region
        self.glue_client = boto3.client("glue", region_name=region)
        self._table_cache: Optional[List[TableInfo]] = None

    def get_tables(self) -> List[TableInfo]:
        """Get list of all tables from Glue catalog.

        Returns:
            List of TableInfo objects
        """
        if self._table_cache is not None:
            return self._table_cache

        tables = []

        try:
            paginator = self.glue_client.get_paginator("get_tables")
            for page in paginator.paginate(DatabaseName=self.database_name):
                for table in page["TableList"]:
                    table_info = self._parse_table_info(table)
                    tables.append(table_info)

            self._table_cache = tables
            return tables

        except ClientError as e:
            logger.error(f"Error fetching tables from Glue: {e}")
            return []

    def get_columns(self, table_name: str) -> List[ColumnInfo]:
        """Get columns for a specific table.

        Args:
            table_name: Name of the table

        Returns:
            List of ColumnInfo objects
        """
        try:
            response = self.glue_client.get_table(
                DatabaseName=self.database_name, Name=table_name
            )

            table = response["Table"]
            columns = []

            for col in table["StorageDescriptor"]["Columns"]:
                columns.append(
                    ColumnInfo(
                        name=col["Name"],
                        type=col["Type"],
                        comment=col.get("Comment"),
                    )
                )

            return columns

        except ClientError as e:
            logger.error(f"Error fetching columns for {table_name}: {e}")
            return []

    def _parse_table_info(self, table: Dict) -> TableInfo:
        """Parse Glue table metadata into TableInfo.

        Args:
            table: Glue table dictionary

        Returns:
            TableInfo object
        """
        columns = []
        for col in table["StorageDescriptor"]["Columns"]:
            columns.append(
                ColumnInfo(
                    name=col["Name"], type=col["Type"], comment=col.get("Comment")
                )
            )

        partitions = []
        for partition_key in table.get("PartitionKeys", []):
            partitions.append(
                ColumnInfo(
                    name=partition_key["Name"],
                    type=partition_key["Type"],
                    comment=partition_key.get("Comment"),
                )
            )

        is_view = table.get("TableType") == "VIRTUAL_VIEW"

        return TableInfo(
            name=table["Name"],
            description=table.get("Description"),
            columns=columns,
            partitions=partitions,
            is_view=is_view,
        )

    def clear_cache(self) -> None:
        """Clear cached table information."""
        self._table_cache = None


class StaticSchemaSource:
    """Static schema source with embedded schema definitions."""

    def __init__(self):
        """Initialize static schema source."""
        self._tables = self._get_static_schema()

    def get_tables(self) -> List[TableInfo]:
        """Get list of all tables.

        Returns:
            List of TableInfo objects
        """
        return self._tables

    def get_columns(self, table_name: str) -> List[ColumnInfo]:
        """Get columns for a specific table.

        Args:
            table_name: Name of the table

        Returns:
            List of ColumnInfo objects
        """
        for table in self._tables:
            if table.name == table_name:
                return table.columns
        return []

    def _get_static_schema(self) -> List[TableInfo]:
        """Get static schema definitions.

        Returns:
            List of TableInfo objects
        """
        return [
            TableInfo(
                name="cloudtrail_logs",
                description="AWS CloudTrail API activity logs",
                columns=[
                    ColumnInfo("eventtime", "string", "ISO 8601 timestamp"),
                    ColumnInfo("eventname", "string", "AWS API action name"),
                    ColumnInfo("eventsource", "string", "AWS service"),
                    ColumnInfo("sourceipaddress", "string", "Requester IP"),
                    ColumnInfo("useridentity", "struct", "Identity details"),
                    ColumnInfo("requestparameters", "string", "API parameters"),
                    ColumnInfo("responseelements", "string", "API response"),
                    ColumnInfo("errorcode", "string", "Error code if failed"),
                    ColumnInfo("errormessage", "string", "Error message"),
                ],
                partitions=[
                    ColumnInfo("year", "int", "Partition year"),
                    ColumnInfo("month", "int", "Partition month"),
                    ColumnInfo("day", "int", "Partition day"),
                ],
                use_cases=[
                    "API activity tracking",
                    "Access pattern analysis",
                    "Authentication events",
                ],
            ),
            TableInfo(
                name="vpc_flow_logs",
                description="AWS VPC network flow logs",
                columns=[
                    ColumnInfo("srcaddr", "string", "Source IP address"),
                    ColumnInfo("dstaddr", "string", "Destination IP address"),
                    ColumnInfo("srcport", "int", "Source port"),
                    ColumnInfo("dstport", "int", "Destination port"),
                    ColumnInfo("protocol", "int", "Protocol number"),
                    ColumnInfo("packets", "bigint", "Number of packets"),
                    ColumnInfo("bytes", "bigint", "Bytes transferred"),
                    ColumnInfo("start", "bigint", "Start timestamp"),
                    ColumnInfo("end", "bigint", "End timestamp"),
                    ColumnInfo("action", "string", "ACCEPT or REJECT"),
                ],
                partitions=[
                    ColumnInfo("year", "int", "Partition year"),
                    ColumnInfo("month", "int", "Partition month"),
                    ColumnInfo("day", "int", "Partition day"),
                ],
                use_cases=[
                    "Network traffic analysis",
                    "Firewall rule validation",
                    "Data exfiltration detection",
                ],
            ),
            TableInfo(
                name="guardduty_findings",
                description="AWS GuardDuty security findings",
                columns=[
                    ColumnInfo("id", "string", "Finding ID"),
                    ColumnInfo("type", "string", "Finding type"),
                    ColumnInfo("severity", "double", "Severity score 0-10"),
                    ColumnInfo("title", "string", "Finding title"),
                    ColumnInfo("description", "string", "Description"),
                    ColumnInfo("createdat", "string", "Creation timestamp"),
                    ColumnInfo("service", "struct", "Service information"),
                    ColumnInfo("resource", "struct", "Resource information"),
                ],
                partitions=[
                    ColumnInfo("year", "int", "Partition year"),
                    ColumnInfo("month", "int", "Partition month"),
                    ColumnInfo("day", "int", "Partition day"),
                ],
                use_cases=[
                    "Security threat detection",
                    "Anomaly identification",
                    "Incident response",
                ],
            ),
            TableInfo(
                name="application_logs",
                description="Generic application logs",
                columns=[
                    ColumnInfo("timestamp", "string", "Log timestamp"),
                    ColumnInfo("level", "string", "Log level"),
                    ColumnInfo("message", "string", "Log message"),
                    ColumnInfo("service", "string", "Service name"),
                    ColumnInfo("source_ip", "string", "Source IP"),
                    ColumnInfo("user_id", "string", "User identifier"),
                ],
                partitions=[
                    ColumnInfo("year", "int", "Partition year"),
                    ColumnInfo("month", "int", "Partition month"),
                    ColumnInfo("day", "int", "Partition day"),
                ],
                use_cases=[
                    "Application error tracking",
                    "Performance monitoring",
                    "User activity analysis",
                ],
            ),
            TableInfo(
                name="network_flows",
                description="Normalised network flow records from VPC flow "
                "logs (AWS/GCP/Azure), Zeek connection logs, and Suricata "
                "flow logs. Unified schema across all cloud providers and "
                "on-prem sensors.",
                columns=[
                    ColumnInfo("timestamp", "string", "ISO 8601 event timestamp"),
                    ColumnInfo("source_ip", "string", "Source IP address"),
                    ColumnInfo("destination_ip", "string", "Destination IP address"),
                    ColumnInfo("source_port", "int", "Source port number"),
                    ColumnInfo("destination_port", "int", "Destination port number"),
                    ColumnInfo("protocol", "string", "Protocol: tcp, udp, icmp"),
                    ColumnInfo("bytes_sent", "bigint", "Bytes sent from source"),
                    ColumnInfo("bytes_received", "bigint", "Bytes received at source"),
                    ColumnInfo("packets_sent", "int", "Packets sent"),
                    ColumnInfo("packets_received", "int", "Packets received"),
                    ColumnInfo("duration_seconds", "double", "Flow duration in seconds"),
                    ColumnInfo("action", "string", "accept, reject, allow, deny, drop"),
                    ColumnInfo("direction", "string", "inbound or outbound"),
                    ColumnInfo("tcp_flags", "array<string>", "TCP flags: SYN, ACK, FIN, RST, etc."),
                    ColumnInfo("conn_state", "string", "Zeek connection state: SF, S0, REJ, etc."),
                    ColumnInfo("cloud_provider", "string", "aws, gcp, azure, or on_prem"),
                    ColumnInfo("source_type", "string", "vpc_flow, nsg_flow, zeek_conn, suricata_flow"),
                    ColumnInfo("vpc_id", "string", "VPC/VNet/network identifier"),
                    ColumnInfo("subnet_id", "string", "Subnet identifier"),
                    ColumnInfo("instance_id", "string", "VM/instance identifier"),
                    ColumnInfo("is_internal", "boolean", "True if both IPs are RFC 1918"),
                    ColumnInfo("aws_service", "string", "AWS service name if applicable"),
                    ColumnInfo("flow_direction", "string", "Flow direction: ingress, egress"),
                    ColumnInfo("metadata", "string", "JSON blob with source-specific fields"),
                ],
                partitions=[
                    ColumnInfo("year", "string", "Partition year"),
                    ColumnInfo("month", "string", "Partition month"),
                    ColumnInfo("day", "string", "Partition day"),
                    ColumnInfo("hour", "string", "Partition hour"),
                ],
                use_cases=[
                    "Network traffic analysis",
                    "Lateral movement detection",
                    "Data exfiltration detection",
                    "Beaconing and C2 detection",
                    "Port scanning detection",
                ],
            ),
            TableInfo(
                name="dns_queries",
                description="DNS query logs from Route 53, GCP Cloud DNS, "
                "Azure DNS, Zeek DNS, and Suricata DNS. Includes entropy "
                "analysis for DNS tunneling and DGA detection.",
                columns=[
                    ColumnInfo("timestamp", "string", "ISO 8601 query timestamp"),
                    ColumnInfo("source_ip", "string", "Client IP making the query"),
                    ColumnInfo("query_name", "string", "Queried domain name"),
                    ColumnInfo("query_type", "string", "DNS record type: A, AAAA, CNAME, TXT, MX, SRV"),
                    ColumnInfo("response_code", "string", "DNS response: NOERROR, NXDOMAIN, SERVFAIL"),
                    ColumnInfo("resolved_ips", "array<string>", "IP addresses in the response"),
                    ColumnInfo("is_nxdomain", "boolean", "True if response was NXDOMAIN"),
                    ColumnInfo("subdomain_entropy", "double", "Shannon entropy of leftmost subdomain label"),
                    ColumnInfo("subdomain_label_count", "int", "Number of subdomain labels"),
                    ColumnInfo("transport", "string", "DNS transport: udp or tcp"),
                    ColumnInfo("cloud_provider", "string", "aws, gcp, azure, or on_prem"),
                    ColumnInfo("source_type", "string", "route53, gcp_cloud_dns, azure_dns, zeek_dns, suricata_dns"),
                    ColumnInfo("vpc_id", "string", "VPC/VNet identifier"),
                    ColumnInfo("ttl_values", "array<int>", "TTL values from DNS answers"),
                    ColumnInfo("answers_count", "int", "Number of answers in the response"),
                    ColumnInfo("metadata", "string", "JSON blob with source-specific fields"),
                ],
                partitions=[
                    ColumnInfo("year", "string", "Partition year"),
                    ColumnInfo("month", "string", "Partition month"),
                    ColumnInfo("day", "string", "Partition day"),
                    ColumnInfo("hour", "string", "Partition hour"),
                ],
                use_cases=[
                    "DNS tunneling detection",
                    "DGA domain detection",
                    "C2 domain identification",
                    "Domain reputation analysis",
                    "NXDOMAIN anomaly detection",
                ],
            ),
            TableInfo(
                name="firewall_events",
                description="Firewall and IDS/IPS events from AWS Network "
                "Firewall, GCP Firewall, Azure Firewall, and Suricata "
                "alerts. Includes threat intelligence and signature matches.",
                columns=[
                    ColumnInfo("timestamp", "string", "ISO 8601 event timestamp"),
                    ColumnInfo("source_ip", "string", "Source IP address"),
                    ColumnInfo("destination_ip", "string", "Destination IP address"),
                    ColumnInfo("source_port", "int", "Source port number"),
                    ColumnInfo("destination_port", "int", "Destination port number"),
                    ColumnInfo("protocol", "string", "Protocol: tcp, udp"),
                    ColumnInfo("action", "string", "allow, deny, drop, alert"),
                    ColumnInfo("firewall_rule_name", "string", "Rule or policy name"),
                    ColumnInfo("direction", "string", "inbound or outbound"),
                    ColumnInfo("threat_category", "string", "Threat category from IDS/threat intel"),
                    ColumnInfo("signature_id", "string", "IDS signature ID"),
                    ColumnInfo("signature_name", "string", "IDS signature description"),
                    ColumnInfo("cloud_provider", "string", "aws, gcp, azure, or on_prem"),
                    ColumnInfo("source_type", "string", "aws_network_firewall, gcp_firewall, azure_firewall, suricata_alert"),
                    ColumnInfo("metadata", "string", "JSON blob with source-specific fields"),
                ],
                partitions=[
                    ColumnInfo("year", "string", "Partition year"),
                    ColumnInfo("month", "string", "Partition month"),
                    ColumnInfo("day", "string", "Partition day"),
                    ColumnInfo("hour", "string", "Partition hour"),
                ],
                use_cases=[
                    "Firewall rule auditing",
                    "Intrusion detection",
                    "Threat intelligence matching",
                    "Blocked connection analysis",
                    "Attack surface monitoring",
                ],
            ),
            TableInfo(
                name="log_source_health",
                description="Health state of all monitored log sources. "
                "Tracks status, volume, baselines, and data gaps for "
                "each source_type per tenant.",
                columns=[
                    ColumnInfo(
                        "source_type", "string",
                        "Log source name (e.g., okta, cloudtrail, "
                        "vpc_flow_logs)"
                    ),
                    ColumnInfo(
                        "tenant_id", "string",
                        "Tenant identifier for multi-tenant deployments"
                    ),
                    ColumnInfo(
                        "status", "string",
                        "Current health status: HEALTHY, DELAYED, SILENT, "
                        "VOLUME_ANOMALY, or UNKNOWN"
                    ),
                    ColumnInfo(
                        "last_event_timestamp", "string",
                        "ISO 8601 timestamp of the most recent event "
                        "received"
                    ),
                    ColumnInfo(
                        "last_check_timestamp", "string",
                        "ISO 8601 timestamp of the last health check run"
                    ),
                    ColumnInfo(
                        "event_count_current_window", "int",
                        "Events received in the current monitoring window"
                    ),
                    ColumnInfo(
                        "event_count_previous_window", "int",
                        "Events received in the previous equivalent window"
                    ),
                    ColumnInfo(
                        "baseline_hourly_volume", "double",
                        "Rolling average hourly event volume"
                    ),
                    ColumnInfo(
                        "baseline_hourly_stddev", "double",
                        "Standard deviation of hourly event volume"
                    ),
                    ColumnInfo(
                        "consecutive_failures", "int",
                        "Consecutive check cycles in non-HEALTHY state"
                    ),
                    ColumnInfo(
                        "last_alert_timestamp", "string",
                        "ISO 8601 timestamp of last health alert sent"
                    ),
                    ColumnInfo(
                        "gap_windows", "string",
                        "JSON array of detected data gaps, each with "
                        "start and end ISO 8601 timestamps"
                    ),
                ],
                partitions=[],
                use_cases=[
                    "Log source health monitoring",
                    "Data gap detection",
                    "Volume anomaly detection",
                    "Source availability tracking",
                ],
            ),
        ]


class SchemaContext:
    """Builds schema context for LLM prompts."""

    def __init__(self, database_name: str, schema_source: SchemaSource):
        """Initialize schema context builder.

        Args:
            database_name: Database name
            schema_source: Source for schema information
        """
        self.database_name = database_name
        self.schema_source = schema_source

    def build_context(self) -> str:
        """Generate comprehensive schema description for LLM.

        Returns:
            Formatted schema context string
        """
        tables = self.schema_source.get_tables()

        context_lines = [
            f"Database: {self.database_name}",
            "",
            "Available Tables and Views:",
            "",
        ]

        for table in tables:
            context_lines.extend(self._format_table(table))
            context_lines.append("")

        context_lines.extend(self._get_query_patterns())

        return "\n".join(context_lines)

    def get_table_context(self, table_name: str) -> str:
        """Get detailed context for specific table.

        Args:
            table_name: Table name

        Returns:
            Formatted table context
        """
        tables = self.schema_source.get_tables()

        for table in tables:
            if table.name.lower() == table_name.lower():
                lines = self._format_table(table)
                return "\n".join(lines)

        return f"Table '{table_name}' not found"

    def get_relevant_tables(self, query_hint: str) -> List[str]:
        """Suggest relevant tables based on query hint.

        Args:
            query_hint: User's query hint

        Returns:
            List of relevant table names
        """
        hint_lower = query_hint.lower()
        tables = self.schema_source.get_tables()
        relevant = []

        keywords = {
            "authentication": ["cloudtrail_logs"],
            "auth": ["cloudtrail_logs"],
            "login": ["cloudtrail_logs"],
            "network": ["vpc_flow_logs", "network_flows"],
            "traffic": ["vpc_flow_logs", "network_flows"],
            "flow": ["vpc_flow_logs", "network_flows"],
            "connection": ["network_flows"],
            "lateral movement": ["network_flows"],
            "beaconing": ["network_flows"],
            "beacon": ["network_flows"],
            "scanning": ["network_flows"],
            "port scan": ["network_flows"],
            "exfiltration": ["network_flows"],
            "bytes transferred": ["network_flows"],
            "top talker": ["network_flows"],
            "internal host": ["network_flows"],
            "external ip": ["network_flows"],
            "security": ["guardduty_findings"],
            "threat": ["guardduty_findings", "firewall_events"],
            "guardduty": ["guardduty_findings"],
            "application": ["application_logs"],
            "error": ["application_logs"],
            "api": ["cloudtrail_logs"],
            "dns": ["dns_queries"],
            "domain": ["dns_queries"],
            "query_name": ["dns_queries"],
            "nxdomain": ["dns_queries"],
            "entropy": ["dns_queries"],
            "tunneling": ["dns_queries"],
            "dga": ["dns_queries"],
            "subdomain": ["dns_queries"],
            "txt record": ["dns_queries"],
            "resolved ip": ["dns_queries"],
            "firewall": ["firewall_events"],
            "denied": ["firewall_events"],
            "blocked": ["firewall_events"],
            "ids": ["firewall_events"],
            "ips": ["firewall_events"],
            "signature": ["firewall_events"],
            "intrusion": ["firewall_events"],
            "suricata": ["firewall_events", "network_flows"],
            "zeek": ["network_flows", "dns_queries"],
            "health": ["log_source_health"],
            "healthy": ["log_source_health"],
            "unhealthy": ["log_source_health"],
            "silent": ["log_source_health"],
            "delayed": ["log_source_health"],
            "gap": ["log_source_health"],
            "volume": ["log_source_health"],
            "baseline": ["log_source_health"],
            "source status": ["log_source_health"],
            "log source": ["log_source_health"],
            "sending data": ["log_source_health"],
        }

        for keyword, table_names in keywords.items():
            if keyword in hint_lower:
                relevant.extend(table_names)

        if not relevant:
            return [table.name for table in tables]

        return list(set(relevant))

    def _format_table(self, table: TableInfo) -> List[str]:
        """Format table information.

        Args:
            table: TableInfo object

        Returns:
            List of formatted lines
        """
        lines = []

        table_type = "VIEW" if table.is_view else "TABLE"
        lines.append(f"{table_type}: {table.name}")

        if table.description:
            lines.append(f"Description: {table.description}")

        if table.partitions:
            partition_desc = ", ".join(
                f"{p.name} ({p.type})" for p in table.partitions
            )
            lines.append(f"Partitions: {partition_desc}")

        if table.use_cases:
            lines.append(f"Use for: {', '.join(table.use_cases)}")

        lines.append("Columns:")
        for col in table.columns:
            comment = f": {col.comment}" if col.comment else ""
            lines.append(f"  - {col.name} ({col.type}){comment}")

        return lines

    def _get_query_patterns(self) -> List[str]:
        """Get common query patterns.

        Returns:
            List of formatted pattern lines
        """
        return [
            "",
            "Common Query Patterns:",
            "- Time filtering: WHERE eventtime >= '2024-01-01' AND eventtime < '2024-01-02'",
            "- Use partition pruning: WHERE year = 2024 AND month = 1 AND day = 1",
            "- IP address matching: WHERE sourceipaddress = '192.168.1.1'",
            "- String matching: WHERE eventname LIKE '%Delete%'",
            "- Aggregations: COUNT(*), SUM(bytes), AVG(packets)",
            "- Grouping: GROUP BY sourceipaddress, eventname",
            "- Ordering: ORDER BY eventtime DESC LIMIT 100",
            "",
            "Health Monitoring Patterns:",
            "- Find unhealthy sources: SELECT * FROM log_source_health WHERE status != 'HEALTHY'",
            "- Check specific source: SELECT * FROM log_source_health WHERE source_type = 'okta'",
            "- Sources with gaps: SELECT source_type, gap_windows FROM log_source_health WHERE gap_windows != '[]'",
            "- Volume trends: Query source tables directly with COUNT(*) GROUP BY year, month, day, hour",
            "- Identity sources: WHERE source_type IN ('okta', 'duo', 'microsoft365', 'google_workspace', 'onepassword')",
            "",
            "Network Detection Patterns:",
            "- Flow analysis: SELECT source_ip, destination_ip, SUM(bytes_sent) FROM network_flows WHERE ...",
            "- Internal-to-external: WHERE is_internal = false AND source_ip LIKE '10.%'",
            "- Beaconing: GROUP BY source_ip, destination_ip and analyze inter-arrival times",
            "- Port scanning: COUNT(DISTINCT destination_port) > 50 grouped by source_ip",
            "- Non-standard ports: WHERE destination_port NOT IN (80, 443, 53, 22, 25)",
            "- Zeek flows: WHERE source_type = 'zeek_conn' for on-prem sensor data",
            "",
            "DNS Analysis Patterns:",
            "- High entropy: WHERE subdomain_entropy > 3.5 (potential tunneling/DGA)",
            "- NXDOMAIN: WHERE is_nxdomain = true for failed lookups (DGA indicator)",
            "- TXT records: WHERE query_type = 'TXT' (tunneling/exfiltration vector)",
            "- Top queried: GROUP BY query_name ORDER BY COUNT(*) DESC",
            "- Resolve joins: Join dns_queries.resolved_ips with network_flows.destination_ip",
            "",
            "Firewall/IDS Patterns:",
            "- Denied connections: WHERE action IN ('deny', 'drop', 'blocked')",
            "- Threat matches: WHERE threat_category IS NOT NULL",
            "- IDS alerts: WHERE signature_id IS NOT NULL (Suricata/Snort detections)",
            "- Rule analysis: GROUP BY firewall_rule_name, action",
            "",
            "Important Notes:",
            "- Always use partition columns (year, month, day) for better performance",
            "- String comparisons are case-sensitive",
            "- Use date_parse() or from_iso8601_timestamp() for timestamp conversions",
            "- Limit result sets with LIMIT clause to avoid large scans",
            "- The log_source_health table has no partitions; query it directly without year/month/day filters",
        ]
