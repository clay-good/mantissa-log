"""
Formatters for Scheduled Intelligence Summaries

Formats query results and summaries for Slack output.
"""

from datetime import datetime
from typing import Dict, List, Any, Optional

from .config import ScheduledQueryConfig
from .manager import ScheduledQuery


class SlackSummaryFormatter:
    """Formats scheduled query summaries for Slack."""

    def __init__(self, config: Optional[ScheduledQueryConfig] = None):
        """
        Initialize formatter.

        Args:
            config: Scheduled query configuration
        """
        self.config = config or ScheduledQueryConfig()

    def format(
        self,
        query: ScheduledQuery,
        summary: str,
        results: List[Dict[str, Any]],
        generated_sql: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Format query results as Slack message.

        Args:
            query: The scheduled query
            summary: Generated summary text
            results: Query results
            generated_sql: Optional SQL that was executed

        Returns:
            Slack message payload
        """
        blocks = []

        # Header
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"Scheduled Report: {query.name}"
            }
        })

        # Timestamp and stats
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        stats_text = f"*Executed:* {now} | *Results:* {len(results)} records"

        if self.config.include_execution_stats:
            stats_text += f" | *Run #{query.run_count + 1}*"

        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": stats_text
                }
            ]
        })

        blocks.append({"type": "divider"})

        # Summary section
        if summary:
            # Split long summaries into multiple blocks
            summary_chunks = self._chunk_text(summary, 2900)

            for i, chunk in enumerate(summary_chunks):
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": chunk
                    }
                })

        # Query details (collapsible via context)
        if self.config.include_query_details:
            blocks.append({"type": "divider"})

            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Original Query:* {query.query_text[:500]}"
                    }
                ]
            })

            if generated_sql:
                # Truncate SQL for display
                sql_display = generated_sql[:300]
                if len(generated_sql) > 300:
                    sql_display += "..."

                blocks.append({
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"```{sql_display}```"
                        }
                    ]
                })

        # Results table (for small result sets)
        if results and len(results) <= 10:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Sample Results:*"
                }
            })

            table_text = self._format_results_table(results[:5])
            if table_text:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"```{table_text}```"
                    }
                })

        # Footer
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Mantissa Log | Schedule: {query.schedule_expression}"
                }
            ]
        })

        # Build payload
        payload = {
            "username": "Mantissa Log",
            "icon_emoji": ":bar_chart:",
            "blocks": blocks
        }

        # Add channel if specified
        if query.output_channel and not query.output_channel.startswith('https://'):
            payload["channel"] = query.output_channel

        return payload

    def format_error(
        self,
        query: ScheduledQuery,
        error_message: str
    ) -> Dict[str, Any]:
        """
        Format error message for Slack.

        Args:
            query: The scheduled query
            error_message: Error description

        Returns:
            Slack message payload
        """
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"Scheduled Query Failed: {query.name}"
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Time:* {now}"
                    }
                ]
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Error:*\n```{error_message[:1000]}```"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Query:* {query.query_text[:500]}"
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Query ID: {query.query_id} | Error count: {query.error_count + 1}"
                    }
                ]
            }
        ]

        payload = {
            "username": "Mantissa Log",
            "icon_emoji": ":warning:",
            "attachments": [
                {
                    "color": "#DC2626",  # Red
                    "blocks": blocks
                }
            ]
        }

        if query.output_channel and not query.output_channel.startswith('https://'):
            payload["channel"] = query.output_channel

        return payload

    def format_weekly_digest(
        self,
        queries: List[ScheduledQuery],
        execution_stats: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Format weekly digest of all scheduled queries.

        Args:
            queries: List of scheduled queries
            execution_stats: Aggregated execution statistics

        Returns:
            Slack message payload
        """
        now = datetime.utcnow().strftime("%Y-%m-%d")
        total_runs = execution_stats.get('total_runs', 0)
        successful_runs = execution_stats.get('successful_runs', 0)
        failed_runs = execution_stats.get('failed_runs', 0)
        success_rate = (successful_runs / total_runs * 100) if total_runs > 0 else 0

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"Weekly Scheduled Query Digest - {now}"
                }
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Queries:*\n{len(queries)}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Enabled:*\n{sum(1 for q in queries if q.enabled)}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Executions:*\n{total_runs}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Success Rate:*\n{success_rate:.1f}%"
                    }
                ]
            }
        ]

        # Top queries by run count
        if queries:
            top_queries = sorted(queries, key=lambda q: q.run_count, reverse=True)[:5]

            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Most Active Queries:*"
                }
            })

            for q in top_queries:
                status_emoji = ":white_check_mark:" if q.last_run_status == 'success' else ":x:"
                blocks.append({
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"{status_emoji} *{q.name}* - {q.run_count} runs | {q.output_channel}"
                        }
                    ]
                })

        # Failed queries
        failed_queries = [q for q in queries if q.error_count > 0]
        if failed_queries:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Queries with Errors:*"
                }
            })

            for q in failed_queries[:5]:
                blocks.append({
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f":warning: *{q.name}* - {q.error_count} errors"
                        }
                    ]
                })

        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "Mantissa Log - Scheduled Intelligence Summaries"
                }
            ]
        })

        return {
            "username": "Mantissa Log",
            "icon_emoji": ":clipboard:",
            "blocks": blocks
        }

    def _chunk_text(self, text: str, max_length: int) -> List[str]:
        """Split text into chunks for Slack block limits."""
        if len(text) <= max_length:
            return [text]

        chunks = []
        current_chunk = ""

        for line in text.split("\n"):
            if len(current_chunk) + len(line) + 1 <= max_length:
                current_chunk += line + "\n"
            else:
                if current_chunk:
                    chunks.append(current_chunk.strip())
                current_chunk = line + "\n"

        if current_chunk:
            chunks.append(current_chunk.strip())

        return chunks

    def _format_results_table(
        self,
        results: List[Dict[str, Any]],
        max_cols: int = 4
    ) -> str:
        """Format results as a text table."""
        if not results:
            return ""

        # Get column headers (first N columns)
        headers = list(results[0].keys())[:max_cols]

        # Calculate column widths
        widths = {h: len(h) for h in headers}
        for row in results:
            for h in headers:
                val = str(row.get(h, ''))[:30]  # Truncate long values
                widths[h] = max(widths[h], len(val))

        # Build table
        lines = []

        # Header row
        header_line = " | ".join(h.ljust(widths[h]) for h in headers)
        lines.append(header_line)
        lines.append("-" * len(header_line))

        # Data rows
        for row in results:
            row_values = []
            for h in headers:
                val = str(row.get(h, ''))[:30]
                row_values.append(val.ljust(widths[h]))
            lines.append(" | ".join(row_values))

        return "\n".join(lines)


class DailyDigestFormatter(SlackSummaryFormatter):
    """Specialized formatter for daily alert digests."""

    def format_daily_digest(
        self,
        alerts: List[Dict[str, Any]],
        date: str
    ) -> Dict[str, Any]:
        """
        Format daily alert digest.

        Args:
            alerts: List of alerts from the day
            date: Date string for the digest

        Returns:
            Slack message payload
        """
        # Group by severity
        by_severity = {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []}
        for alert in alerts:
            severity = alert.get('severity', 'info').lower()
            if severity in by_severity:
                by_severity[severity].append(alert)

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"Daily Alert Digest - {date}"
                }
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Critical:* {len(by_severity['critical'])}"},
                    {"type": "mrkdwn", "text": f"*High:* {len(by_severity['high'])}"},
                    {"type": "mrkdwn", "text": f"*Medium:* {len(by_severity['medium'])}"},
                    {"type": "mrkdwn", "text": f"*Low/Info:* {len(by_severity['low']) + len(by_severity['info'])}"}
                ]
            }
        ]

        # Critical and high alerts get individual sections
        for severity in ['critical', 'high']:
            if by_severity[severity]:
                blocks.append({"type": "divider"})
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*{severity.upper()} Alerts:*"
                    }
                })

                for alert in by_severity[severity][:10]:
                    title = alert.get('title', 'Unknown Alert')[:100]
                    rule = alert.get('rule_name', 'Unknown Rule')
                    timestamp = alert.get('timestamp', '')

                    blocks.append({
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"*{title}*\nRule: {rule} | Time: {timestamp}"
                            }
                        ]
                    })

        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Mantissa Log | Total alerts: {len(alerts)}"
                }
            ]
        })

        return {
            "username": "Mantissa Log",
            "icon_emoji": ":bell:",
            "attachments": [
                {
                    "color": "#F59E0B" if by_severity['critical'] or by_severity['high'] else "#10B981",
                    "blocks": blocks
                }
            ]
        }


class SecurityPostureFormatter(SlackSummaryFormatter):
    """Specialized formatter for security posture summaries."""

    def format_posture_summary(
        self,
        metrics: Dict[str, Any],
        period: str = "week"
    ) -> Dict[str, Any]:
        """
        Format security posture summary.

        Args:
            metrics: Security metrics dictionary
            period: Time period (week, month)

        Returns:
            Slack message payload
        """
        total_events = metrics.get('total_events', 0)
        alerts_fired = metrics.get('alerts_fired', 0)
        rules_triggered = metrics.get('unique_rules_triggered', 0)
        top_rules = metrics.get('top_rules', [])
        unusual_patterns = metrics.get('unusual_patterns', [])

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"Security Posture Summary - Past {period.title()}"
                }
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Total Events:*\n{total_events:,}"},
                    {"type": "mrkdwn", "text": f"*Alerts Generated:*\n{alerts_fired:,}"},
                    {"type": "mrkdwn", "text": f"*Rules Triggered:*\n{rules_triggered}"},
                    {"type": "mrkdwn", "text": f"*Alert Rate:*\n{(alerts_fired/total_events*100):.2f}%" if total_events > 0 else "N/A"}
                ]
            }
        ]

        if top_rules:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Top Triggered Rules:*"
                }
            })

            for i, rule in enumerate(top_rules[:5], 1):
                blocks.append({
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"{i}. *{rule['name']}* - {rule['count']} alerts"
                        }
                    ]
                })

        if unusual_patterns:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Unusual Patterns Detected:*"
                }
            })

            for pattern in unusual_patterns[:5]:
                blocks.append({
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f":warning: {pattern}"
                        }
                    ]
                })

        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "Mantissa Log - Security Intelligence"
                }
            ]
        })

        return {
            "username": "Mantissa Log",
            "icon_emoji": ":shield:",
            "blocks": blocks
        }
