# Conversational Context - Phase 3 Implementation

Complete multi-turn conversation system with context preservation, follow-up recognition, and intelligent intent parsing.

## Overview

Phase 3 implements a complete conversational interface that enables natural, multi-turn dialogues for querying logs, creating detections, and configuring alerts. The system maintains context across turns, understands follow-up questions, and provides intelligent suggestions.

## Architecture

### Backend Components

1. **Session Manager** ([src/shared/conversation/session_manager.py](../../src/shared/conversation/session_manager.py))
   - Manages conversation sessions with 30-minute timeout
   - Stores messages and context in DynamoDB
   - Provides LLM-formatted context
   - Auto-cleanup with 7-day TTL

2. **Conversation API** ([src/aws/api/conversation_api.py](../../src/aws/api/conversation_api.py))
   - REST endpoints for session management
   - Message storage and retrieval
   - Context updates
   - Session lifecycle management

3. **Query Parser** ([src/shared/conversation/query_parser.py](../../src/shared/conversation/query_parser.py))
   - Intent detection (query, refine, create_detection, configure_alert)
   - Entity extraction (schedule, severity, integration, threshold)
   - Follow-up recognition
   - Context enhancement

### Frontend Components

1. **ConversationalInterface** ([web/src/components/ConversationalInterface.jsx](../../web/src/components/ConversationalInterface.jsx))
   - Full conversational UI with session management
   - Message input and display
   - Example prompts
   - Reset session functionality

2. **ConversationHistory** ([web/src/components/ConversationHistory.jsx](../../web/src/components/ConversationHistory.jsx))
   - Message display with avatars
   - Metadata rendering (SQL, warnings)
   - Timestamp formatting
   - Monochrome design

## Intent Types

### 1. QUERY
Execute a search query on log data.

**Examples**:
- "Show me failed login attempts"
- "Find all API calls from IP 192.168.1.1"
- "What events happened in the last hour?"

**Entities Extracted**:
- tables: cloudtrail, vpc_flow, s3_access
- fields: eventName, sourceIPAddress, etc.
- time_range: last X hours/days

### 2. REFINE_QUERY
Modify the previous query (follow-up).

**Examples**:
- "Filter those to only show critical events"
- "Limit to 10 results"
- "Exclude successful logins"
- "And add the timestamp field"

**Context Required**: current_sql must exist

**Follow-up Indicators**:
- Pronouns: that, those, it, them
- Modifiers: filter, limit, exclude, add, remove
- Conjunctions: and, also, additionally

### 3. CREATE_DETECTION
Save query as a scheduled detection rule.

**Examples**:
- "Create a detection to run every hour"
- "Save this as a detection rule"
- "Make a rule that runs daily"
- "Alert me if this happens more than 10 times"

**Entities Extracted**:
- schedule: rate(X minutes/hours/days) or cron expression
- threshold: numeric value
- severity: critical, high, medium, low, info

### 4. CONFIGURE_ALERT
Add alert routing to a detection.

**Examples**:
- "Send alerts to Slack"
- "Create a Jira ticket when this triggers"
- "Page the on-call team via PagerDuty"
- "Email security@company.com"

**Entities Extracted**:
- integration: slack, jira, pagerduty, email, webhook

### 5. SHOW_RESULTS
Display results from previous query.

**Examples**:
- "Show those results again"
- "Display the previous query output"

### 6. EXPLAIN
Explain the query or results.

**Examples**:
- "Explain what this query does"
- "Why did I get these results?"
- "What does this SQL mean?"

## Entity Extraction

### Schedule Expressions

**Patterns**:
```python
"every 5 minutes" → "rate(5 minutes)"
"every hour" → "rate(1 hour)"
"daily" → "rate(1 day)"
"hourly" → "rate(1 hour)"
"every 15 mins" → "rate(15 minutes)"
```

### Severity Levels

**Keywords**:
```python
critical: ['critical', 'crit', 'urgent', 'emergency', 'sev1']
high: ['high', 'important', 'major', 'sev2']
medium: ['medium', 'moderate', 'med', 'sev3']
low: ['low', 'minor', 'sev4']
info: ['info', 'informational', 'fyi', 'sev5']
```

### Integrations

**Keywords**:
```python
slack: ['slack']
jira: ['jira', 'ticket', 'issue']
pagerduty: ['pagerduty', 'page', 'oncall', 'on-call']
email: ['email', 'mail']
webhook: ['webhook', 'http', 'custom']
```

### Thresholds

**Patterns**:
```python
"more than 10" → threshold: 10
"greater than 5" → threshold: 5
"at least 3" → threshold: 3
"over 20" → threshold: 20
"exceeds 15" → threshold: 15
```

### Time Ranges

**Patterns**:
```python
"last 24 hours" → {unit: 'hours', value: 24}
"past 7 days" → {unit: 'days', value: 7}
"yesterday" → {unit: 'days', value: 1}
"this week" → {unit: 'days', value: 7}
```

## Conversation Flow Examples

### Example 1: Simple Query

**Turn 1**:
```
User: Show me failed login attempts in the last 24 hours
Intent: QUERY
Entities: {time_range: {unit: 'hours', value: 24}, tables: ['cloudtrail']}