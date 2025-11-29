"""
Behavioral Analysis for Alert Enrichment

Queries historical data to provide behavioral context for alerts.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import ipaddress

logger = logging.getLogger(__name__)


class BehavioralAnalyzer:
    """
    Analyzes historical behavior patterns for alert enrichment.

    Queries Athena/BigQuery/Synapse to gather:
    - User activity history
    - IP address history
    - Session context
    - Baseline statistics
    """

    # RFC 1918 private IP ranges
    PRIVATE_IP_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
    ]

    def __init__(self, query_executor, config: Optional[Dict[str, Any]] = None):
        """
        Initialize behavioral analyzer.

        Args:
            query_executor: Query executor for Athena/BigQuery/Synapse
            config: Configuration options
        """
        self.executor = query_executor
        self.config = config or {}
        self.baseline_window_days = self.config.get('baseline_window_days', 30)
        self.max_events = self.config.get('max_historical_events_per_query', 1000)
        self._cache = {}

    def get_behavioral_context(
        self,
        alert_data: Dict[str, Any],
        event_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Get comprehensive behavioral context for an alert.

        Args:
            alert_data: Alert metadata
            event_data: First event from the alert

        Returns:
            Behavioral context dictionary
        """
        context = {}

        # Extract key identifiers from event
        user = self._extract_user(event_data)
        source_ip = self._extract_ip(event_data)
        event_name = event_data.get('eventName', event_data.get('event_name'))
        session_id = self._extract_session_id(event_data)

        # Get user history if we have a user
        if user:
            context['user_history'] = self.get_user_history(
                user=user,
                event_name=event_name,
                current_ip=source_ip
            )

        # Get IP history if we have a source IP
        if source_ip:
            context['ip_history'] = self.get_ip_history(
                ip_address=source_ip,
                user=user
            )

        # Get session context if we have a session ID
        if session_id:
            context['session_context'] = self.get_session_context(
                session_id=session_id,
                user=user
            )

        return context

    def get_user_history(
        self,
        user: str,
        event_name: Optional[str] = None,
        current_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get historical activity for a user.

        Args:
            user: Username or user ID
            event_name: Specific event to check history for
            current_ip: Current source IP for comparison

        Returns:
            User history dictionary
        """
        history = {
            'user': user,
            'has_done_before': False,
            'previous_count': 0,
            'typical_ips': [],
            'typical_times': 'Unknown',
            'first_seen': None,
            'last_seen': None
        }

        try:
            # Query for user's previous instances of this event type
            if event_name:
                event_history_query = f"""
                SELECT
                    COUNT(*) as event_count,
                    MIN(eventTime) as first_occurrence,
                    MAX(eventTime) as last_occurrence
                FROM cloudtrail_logs
                WHERE (userIdentity.userName = '{user}'
                       OR userIdentity.principalId = '{user}'
                       OR userIdentity.arn LIKE '%{user}%')
                  AND eventName = '{event_name}'
                  AND eventTime >= CURRENT_TIMESTAMP - INTERVAL '{self.baseline_window_days}' DAY
                  AND eventTime < CURRENT_TIMESTAMP
                LIMIT 1
                """

                result = self._execute_query_safe(event_history_query)
                if result and len(result) > 0:
                    history['previous_count'] = result[0].get('event_count', 0)
                    history['has_done_before'] = history['previous_count'] > 0
                    history['first_seen'] = result[0].get('first_occurrence')
                    history['last_seen'] = result[0].get('last_occurrence')

            # Query for typical IPs used by this user
            ip_query = f"""
            SELECT
                sourceIPAddress,
                COUNT(*) as usage_count
            FROM cloudtrail_logs
            WHERE (userIdentity.userName = '{user}'
                   OR userIdentity.principalId = '{user}'
                   OR userIdentity.arn LIKE '%{user}%')
              AND sourceIPAddress IS NOT NULL
              AND eventTime >= CURRENT_TIMESTAMP - INTERVAL '{self.baseline_window_days}' DAY
            GROUP BY sourceIPAddress
            ORDER BY usage_count DESC
            LIMIT 10
            """

            ip_result = self._execute_query_safe(ip_query)
            if ip_result:
                history['typical_ips'] = [r.get('sourceIPAddress') for r in ip_result if r.get('sourceIPAddress')]

                # Check if current IP is in typical IPs
                if current_ip and current_ip not in history['typical_ips']:
                    history['current_ip_is_new'] = True
                else:
                    history['current_ip_is_new'] = False

            # Query for typical activity times
            time_query = f"""
            SELECT
                HOUR(eventTime) as hour_of_day,
                COUNT(*) as event_count
            FROM cloudtrail_logs
            WHERE (userIdentity.userName = '{user}'
                   OR userIdentity.principalId = '{user}'
                   OR userIdentity.arn LIKE '%{user}%')
              AND eventTime >= CURRENT_TIMESTAMP - INTERVAL '{self.baseline_window_days}' DAY
            GROUP BY HOUR(eventTime)
            ORDER BY event_count DESC
            LIMIT 5
            """

            time_result = self._execute_query_safe(time_query)
            if time_result:
                peak_hours = [r.get('hour_of_day') for r in time_result if r.get('hour_of_day') is not None]
                if peak_hours:
                    if all(8 <= h <= 18 for h in peak_hours[:3]):
                        history['typical_times'] = 'Business hours (8 AM - 6 PM UTC)'
                    elif all(h < 8 or h > 18 for h in peak_hours[:3]):
                        history['typical_times'] = 'Off-hours'
                    else:
                        history['typical_times'] = f"Peak hours: {', '.join(str(h) + ':00' for h in peak_hours[:3])} UTC"

        except Exception as e:
            logger.warning(f"Error getting user history: {e}")

        return history

    def get_ip_history(
        self,
        ip_address: str,
        user: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get historical activity for an IP address.

        Args:
            ip_address: Source IP address
            user: Optional user to filter by

        Returns:
            IP history dictionary
        """
        history = {
            'ip': ip_address,
            'is_internal': self._is_internal_ip(ip_address),
            'first_seen': None,
            'total_events': 0,
            'unique_users': 0,
            'geolocation': 'Unknown'
        }

        try:
            # Query for IP usage history
            ip_query = f"""
            SELECT
                COUNT(*) as total_events,
                COUNT(DISTINCT COALESCE(userIdentity.userName, userIdentity.principalId)) as unique_users,
                MIN(eventTime) as first_seen,
                MAX(eventTime) as last_seen
            FROM cloudtrail_logs
            WHERE sourceIPAddress = '{ip_address}'
              AND eventTime >= CURRENT_TIMESTAMP - INTERVAL '{self.baseline_window_days}' DAY
            LIMIT 1
            """

            result = self._execute_query_safe(ip_query)
            if result and len(result) > 0:
                history['total_events'] = result[0].get('total_events', 0)
                history['unique_users'] = result[0].get('unique_users', 0)
                history['first_seen'] = result[0].get('first_seen')
                history['last_seen'] = result[0].get('last_seen')

            # Check if this IP is new (first seen in last 24 hours)
            if history['first_seen']:
                # Parse the timestamp and check if it's recent
                history['is_new_ip'] = history['total_events'] < 5

        except Exception as e:
            logger.warning(f"Error getting IP history: {e}")

        return history

    def get_session_context(
        self,
        session_id: str,
        user: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get context about other actions in the same session.

        Args:
            session_id: Session identifier
            user: Optional user to filter by

        Returns:
            Session context dictionary
        """
        context = {
            'session_id': session_id,
            'action_count': 0,
            'actions': [],
            'session_start': None,
            'session_duration_minutes': 0
        }

        try:
            # Query for session activity
            session_query = f"""
            SELECT
                eventName,
                eventTime,
                eventSource,
                errorCode
            FROM cloudtrail_logs
            WHERE userIdentity.accessKeyId = '{session_id}'
               OR userIdentity.sessionContext.attributes.sessionId = '{session_id}'
            ORDER BY eventTime ASC
            LIMIT {self.max_events}
            """

            result = self._execute_query_safe(session_query)
            if result:
                context['action_count'] = len(result)
                context['actions'] = list(set(r.get('eventName') for r in result if r.get('eventName')))[:20]

                # Get session timing
                if len(result) > 0:
                    context['session_start'] = result[0].get('eventTime')
                    if len(result) > 1:
                        # Calculate approximate session duration
                        first_time = result[0].get('eventTime')
                        last_time = result[-1].get('eventTime')
                        if first_time and last_time:
                            # Simplified duration calculation
                            context['session_duration_minutes'] = 'Active session'

        except Exception as e:
            logger.warning(f"Error getting session context: {e}")

        return context

    def get_baseline_stats(
        self,
        event_name: str,
        user: Optional[str] = None,
        entity_type: str = 'event'
    ) -> Dict[str, Any]:
        """
        Get baseline statistics for comparison.

        Args:
            event_name: Event name to analyze
            user: Optional user to filter by
            entity_type: Type of entity (event, user, ip)

        Returns:
            Baseline statistics dictionary
        """
        stats = {
            'event_name': event_name,
            'avg_daily': 0,
            'std_dev': 0,
            'today_count': 0,
            'deviation_percent': 0,
            'is_anomalous': False
        }

        try:
            # Build user filter if provided
            user_filter = ""
            if user:
                user_filter = f"""
                AND (userIdentity.userName = '{user}'
                     OR userIdentity.principalId = '{user}'
                     OR userIdentity.arn LIKE '%{user}%')
                """

            # Query for daily averages over baseline period
            baseline_query = f"""
            SELECT
                DATE(eventTime) as event_date,
                COUNT(*) as daily_count
            FROM cloudtrail_logs
            WHERE eventName = '{event_name}'
              AND eventTime >= CURRENT_TIMESTAMP - INTERVAL '{self.baseline_window_days}' DAY
              AND eventTime < CURRENT_DATE
              {user_filter}
            GROUP BY DATE(eventTime)
            """

            result = self._execute_query_safe(baseline_query)
            if result:
                daily_counts = [r.get('daily_count', 0) for r in result]
                if daily_counts:
                    stats['avg_daily'] = sum(daily_counts) / len(daily_counts)

                    # Calculate standard deviation
                    if len(daily_counts) > 1:
                        mean = stats['avg_daily']
                        variance = sum((x - mean) ** 2 for x in daily_counts) / len(daily_counts)
                        stats['std_dev'] = variance ** 0.5

            # Query for today's count
            today_query = f"""
            SELECT COUNT(*) as today_count
            FROM cloudtrail_logs
            WHERE eventName = '{event_name}'
              AND DATE(eventTime) = CURRENT_DATE
              {user_filter}
            """

            today_result = self._execute_query_safe(today_query)
            if today_result and len(today_result) > 0:
                stats['today_count'] = today_result[0].get('today_count', 0)

            # Calculate deviation
            if stats['avg_daily'] > 0:
                stats['deviation_percent'] = round(
                    ((stats['today_count'] - stats['avg_daily']) / stats['avg_daily']) * 100,
                    1
                )

                # Mark as anomalous if more than 2 standard deviations above mean
                if stats['std_dev'] > 0:
                    z_score = (stats['today_count'] - stats['avg_daily']) / stats['std_dev']
                    stats['is_anomalous'] = z_score > 2
                else:
                    stats['is_anomalous'] = stats['today_count'] > stats['avg_daily'] * 3

        except Exception as e:
            logger.warning(f"Error getting baseline stats: {e}")

        return stats

    def _execute_query_safe(self, query: str) -> Optional[List[Dict[str, Any]]]:
        """
        Execute a query with error handling.

        Args:
            query: SQL query string

        Returns:
            Query results or None on error
        """
        try:
            if self.executor:
                return self.executor.execute_query(query)
            else:
                logger.debug(f"No query executor available, skipping query")
                return None
        except Exception as e:
            logger.warning(f"Query execution failed: {e}")
            return None

    def _extract_user(self, event_data: Dict[str, Any]) -> Optional[str]:
        """Extract user identifier from event data."""
        # Try various user fields
        if 'userIdentity' in event_data:
            ui = event_data['userIdentity']
            return (
                ui.get('userName') or
                ui.get('principalId') or
                ui.get('arn', '').split('/')[-1] if ui.get('arn') else None
            )
        return event_data.get('user') or event_data.get('userName')

    def _extract_ip(self, event_data: Dict[str, Any]) -> Optional[str]:
        """Extract source IP from event data."""
        return (
            event_data.get('sourceIPAddress') or
            event_data.get('source_ip') or
            event_data.get('srcaddr')
        )

    def _extract_session_id(self, event_data: Dict[str, Any]) -> Optional[str]:
        """Extract session identifier from event data."""
        if 'userIdentity' in event_data:
            ui = event_data['userIdentity']
            # Try access key first
            if ui.get('accessKeyId'):
                return ui['accessKeyId']
            # Try session context
            if ui.get('sessionContext', {}).get('attributes', {}).get('sessionId'):
                return ui['sessionContext']['attributes']['sessionId']
        return None

    def _is_internal_ip(self, ip_address: str) -> bool:
        """Check if an IP address is internal/private."""
        try:
            ip = ipaddress.ip_address(ip_address)
            return any(ip in network for network in self.PRIVATE_IP_RANGES)
        except ValueError:
            return False
