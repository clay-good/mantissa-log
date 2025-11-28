"""
Conversational Query Parser

Parses natural language queries with conversation context to understand follow-up
questions and commands.
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum


class IntentType(Enum):
    """Types of user intents."""
    QUERY = "query"  # Execute a query
    REFINE_QUERY = "refine_query"  # Modify existing query
    CREATE_DETECTION = "create_detection"  # Save as detection rule
    CONFIGURE_ALERT = "configure_alert"  # Add alert routing
    SHOW_RESULTS = "show_results"  # Display previous results
    EXPLAIN = "explain"  # Explain query or results
    HELP = "help"  # Ask for help
    UNKNOWN = "unknown"  # Cannot determine intent


class ConversationalQueryParser:
    """Parses natural language with conversation context."""

    # Patterns for detecting follow-up references
    FOLLOWUP_PATTERNS = [
        r'\b(and|also|additionally)\b',
        r'\b(then|after that)\b',
        r'\b(that|those|it|them)\b',
        r'^(show|display|get|find)',
    ]

    # Patterns for detection creation
    DETECTION_PATTERNS = [
        r'\b(save|create|make).*(detection|rule|alert)\b',
        r'\b(detection|rule|alert).*(this|that)\b',
        r'\b(run|execute).*(automatically|scheduled|every|daily|hourly)\b',
        r'\b(schedule|automate).*(query|detection)\b',
    ]

    # Patterns for alert configuration
    ALERT_PATTERNS = [
        r'\b(send|notify|alert|page).*(slack|jira|pagerduty|email)\b',
        r'\b(slack|jira|pagerduty|email).*(channel|project|service)\b',
        r'\b(create|open|file).*(ticket|issue)\b',
        r'\b(add|configure|setup).*(integration|destination)\b',
    ]

    # Patterns for query refinement
    REFINE_PATTERNS = [
        r'\b(filter|limit|exclude|include|add|remove)\b',
        r'\b(only|just|except)\b',
        r'\b(more|less|other|different)\b',
        r'\b(change|modify|update|adjust)\b',
    ]

    # Schedule expressions
    SCHEDULE_PATTERNS = {
        r'every (\d+) minute': lambda m: f"rate({m.group(1)} minutes)",
        r'every (\d+) hour': lambda m: f"rate({m.group(1)} hours)",
        r'every (\d+) day': lambda m: f"rate({m.group(1)} days)",
        r'daily': lambda m: "rate(1 day)",
        r'hourly': lambda m: "rate(1 hour)",
        r'every 5 (minutes|mins)': lambda m: "rate(5 minutes)",
        r'every 15 (minutes|mins)': lambda m: "rate(15 minutes)",
        r'every 30 (minutes|mins)': lambda m: "rate(30 minutes)",
    }

    # Severity keywords
    SEVERITY_MAP = {
        'critical': ['critical', 'crit', 'urgent', 'emergency', 'sev1'],
        'high': ['high', 'important', 'major', 'sev2'],
        'medium': ['medium', 'moderate', 'med', 'sev3'],
        'low': ['low', 'minor', 'sev4'],
        'info': ['info', 'informational', 'fyi', 'sev5']
    }

    # Integration keywords
    INTEGRATION_MAP = {
        'slack': ['slack'],
        'jira': ['jira', 'ticket', 'issue'],
        'pagerduty': ['pagerduty', 'page', 'oncall', 'on-call'],
        'email': ['email', 'mail'],
        'webhook': ['webhook', 'http', 'custom']
    }

    def __init__(self):
        pass

    def parse(
        self,
        user_message: str,
        conversation_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Parse user message with conversation context.

        Args:
            user_message: User's natural language input
            conversation_context: Previous conversation context

        Returns:
            Parsed intent and entities
        """
        context = conversation_context or {}
        message_lower = user_message.lower()

        # Detect intent
        intent = self._detect_intent(message_lower, context)

        # Extract entities
        entities = self._extract_entities(user_message, message_lower, context)

        # Check if this is a follow-up
        is_followup = self._is_followup(message_lower, context)

        # Build enhanced context
        enhanced_context = self._build_enhanced_context(
            user_message,
            intent,
            entities,
            is_followup,
            context
        )

        return {
            'intent': intent.value,
            'is_followup': is_followup,
            'entities': entities,
            'needs_context': is_followup and context.get('current_sql') is not None,
            'context': enhanced_context,
            'original_message': user_message
        }

    def _detect_intent(
        self,
        message_lower: str,
        context: Dict[str, Any]
    ) -> IntentType:
        """Detect user intent from message."""
        # Check for detection creation
        for pattern in self.DETECTION_PATTERNS:
            if re.search(pattern, message_lower, re.IGNORECASE):
                return IntentType.CREATE_DETECTION

        # Check for alert configuration
        for pattern in self.ALERT_PATTERNS:
            if re.search(pattern, message_lower, re.IGNORECASE):
                return IntentType.CONFIGURE_ALERT

        # Check for query refinement (if context has a query)
        if context.get('current_sql'):
            for pattern in self.REFINE_PATTERNS:
                if re.search(pattern, message_lower, re.IGNORECASE):
                    return IntentType.REFINE_QUERY

        # Check for explain request
        if any(word in message_lower for word in ['explain', 'why', 'how', 'what does']):
            if context.get('last_results') or context.get('current_sql'):
                return IntentType.EXPLAIN

        # Check for show previous results
        if any(phrase in message_lower for phrase in ['show', 'display', 'see']) and \
           any(phrase in message_lower for phrase in ['that', 'those', 'it', 'results']):
            if context.get('last_results'):
                return IntentType.SHOW_RESULTS

        # Default to query
        return IntentType.QUERY

    def _is_followup(self, message_lower: str, context: Dict[str, Any]) -> bool:
        """Check if message is a follow-up to previous conversation."""
        if not context.get('current_query'):
            return False

        # Check for follow-up patterns
        for pattern in self.FOLLOWUP_PATTERNS:
            if re.search(pattern, message_lower):
                return True

        # Check for pronouns referring to previous context
        pronouns = ['that', 'those', 'it', 'them', 'this', 'these']
        if any(pronoun in message_lower.split() for pronoun in pronouns):
            return True

        return False

    def _extract_entities(
        self,
        user_message: str,
        message_lower: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract entities from user message."""
        entities = {}

        # Extract schedule
        schedule = self._extract_schedule(message_lower)
        if schedule:
            entities['schedule'] = schedule

        # Extract severity
        severity = self._extract_severity(message_lower)
        if severity:
            entities['severity'] = severity

        # Extract integration
        integration = self._extract_integration(message_lower)
        if integration:
            entities['integration'] = integration

        # Extract threshold
        threshold = self._extract_threshold(message_lower)
        if threshold is not None:
            entities['threshold'] = threshold

        # Extract time range
        time_range = self._extract_time_range(message_lower)
        if time_range:
            entities['time_range'] = time_range

        # Extract table names (common AWS log tables)
        tables = self._extract_tables(message_lower)
        if tables:
            entities['tables'] = tables

        # Extract field names
        fields = self._extract_fields(user_message)
        if fields:
            entities['fields'] = fields

        return entities

    def _extract_schedule(self, message_lower: str) -> Optional[str]:
        """Extract schedule expression from message."""
        for pattern, converter in self.SCHEDULE_PATTERNS.items():
            match = re.search(pattern, message_lower)
            if match:
                return converter(match)

        return None

    def _extract_severity(self, message_lower: str) -> Optional[str]:
        """Extract severity level from message."""
        for severity, keywords in self.SEVERITY_MAP.items():
            if any(keyword in message_lower for keyword in keywords):
                return severity

        return None

    def _extract_integration(self, message_lower: str) -> Optional[str]:
        """Extract integration type from message."""
        for integration, keywords in self.INTEGRATION_MAP.items():
            if any(keyword in message_lower for keyword in keywords):
                return integration

        return None

    def _extract_threshold(self, message_lower: str) -> Optional[int]:
        """Extract threshold value from message."""
        # Look for patterns like "more than 10", "greater than 5", "at least 3"
        patterns = [
            r'more than (\d+)',
            r'greater than (\d+)',
            r'at least (\d+)',
            r'over (\d+)',
            r'above (\d+)',
            r'exceeds? (\d+)',
            r'threshold of (\d+)',
            r'(\d+) or more'
        ]

        for pattern in patterns:
            match = re.search(pattern, message_lower)
            if match:
                return int(match.group(1))

        return None

    def _extract_time_range(self, message_lower: str) -> Optional[Dict[str, Any]]:
        """Extract time range from message."""
        # Look for patterns like "last 24 hours", "past 7 days", "yesterday"
        patterns = {
            r'last (\d+) (hour|hr)s?': ('hours', lambda m: int(m.group(1))),
            r'last (\d+) (day|d)s?': ('days', lambda m: int(m.group(1))),
            r'last (\d+) (week|wk)s?': ('weeks', lambda m: int(m.group(1))),
            r'past (\d+) (hour|hr)s?': ('hours', lambda m: int(m.group(1))),
            r'past (\d+) (day|d)s?': ('days', lambda m: int(m.group(1))),
            r'yesterday': ('days', lambda m: 1),
            r'today': ('hours', lambda m: 24),
            r'this week': ('days', lambda m: 7)
        }

        for pattern, (unit, extractor) in patterns.items():
            match = re.search(pattern, message_lower)
            if match:
                return {
                    'unit': unit,
                    'value': extractor(match)
                }

        return None

    def _extract_tables(self, message_lower: str) -> List[str]:
        """Extract table names from message."""
        tables = []

        table_keywords = {
            'cloudtrail': ['cloudtrail', 'cloud trail', 'api call', 'api activity'],
            'vpc_flow': ['vpc flow', 'network', 'traffic', 'connection'],
            's3_access': ['s3 access', 's3 log', 'bucket access'],
            'lambda_logs': ['lambda', 'function', 'invocation']
        }

        for table, keywords in table_keywords.items():
            if any(keyword in message_lower for keyword in keywords):
                tables.append(table)

        return tables

    def _extract_fields(self, user_message: str) -> List[str]:
        """Extract field names from message (case-sensitive for SQL fields)."""
        # Common AWS log fields
        common_fields = [
            'eventName', 'eventSource', 'eventTime', 'userIdentity',
            'sourceIPAddress', 'errorCode', 'errorMessage',
            'requestParameters', 'responseElements',
            'userName', 'accountId', 'region'
        ]

        found_fields = []
        for field in common_fields:
            if field in user_message:
                found_fields.append(field)

        return found_fields

    def _build_enhanced_context(
        self,
        user_message: str,
        intent: IntentType,
        entities: Dict[str, Any],
        is_followup: bool,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build enhanced context for LLM prompt."""
        enhanced = {}

        # Add previous query context if follow-up
        if is_followup and context.get('current_sql'):
            enhanced['previous_query'] = context['current_query']
            enhanced['previous_sql'] = context['current_sql']

        # Add last results summary if available
        if context.get('last_results'):
            enhanced['last_results_summary'] = context['last_results']

        # Add pending action if any
        if context.get('pending_action'):
            enhanced['pending_action'] = context['pending_action']

        # Add detection config if building a detection
        if intent == IntentType.CREATE_DETECTION:
            enhanced['detection_config'] = context.get('detection_config', {})

        # Add mentioned integrations
        if context.get('mentioned_integrations'):
            enhanced['mentioned_integrations'] = context['mentioned_integrations']

        return enhanced
