"""Schema context builder for LLM prompts."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol

import boto3
from botocore.exceptions import ClientError


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
            print(f"Error fetching tables from Glue: {e}")
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
            print(f"Error fetching columns for {table_name}: {e}")
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
            "network": ["vpc_flow_logs"],
            "traffic": ["vpc_flow_logs"],
            "flow": ["vpc_flow_logs"],
            "security": ["guardduty_findings"],
            "threat": ["guardduty_findings"],
            "guardduty": ["guardduty_findings"],
            "application": ["application_logs"],
            "error": ["application_logs"],
            "api": ["cloudtrail_logs"],
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
            "Important Notes:",
            "- Always use partition columns (year, month, day) for better performance",
            "- String comparisons are case-sensitive",
            "- Use date_parse() or from_iso8601_timestamp() for timestamp conversions",
            "- Limit result sets with LIMIT clause to avoid large scans",
        ]
