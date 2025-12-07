# Conversational Context Feature

Multi-turn conversation support with context preservation for natural language query generation.

## Overview

The Conversational Context feature enables users to have multi-turn conversations with the query interface. The system remembers previous questions and answers, allowing users to ask follow-up questions without repeating context.

## Key Features

- Session-based conversation memory
- Context-aware query generation
- Follow-up command recognition
- Conversation history display
- 24-hour session persistence
- Automatic context cleanup

## Implementation

### Backend Components

#### 1. Session Manager ([src/shared/conversation/session_manager.py](../../src/shared/conversation/session_manager.py))

Core conversation management with classes:

**Message:**
```python
@dataclass
class Message:
    role: str  # 'user' or 'assistant'
    content: str
    timestamp: str
    metadata: Dict[str, Any]
```

**ConversationSession:**
```python
@dataclass
class ConversationSession:
    session_id: str
    user_id: str
    messages: List[Message]
    context: Dict[str, Any]
    created_at: str
    updated_at: str
    expires_at: str  # 24 hours from creation
```

**SessionManager:**
- Creates and manages sessions
- Stores sessions in DynamoDB
- Handles session expiration
- Provides LLM-formatted context

**Example Usage:**
```python
from conversation import SessionManager, DynamoDBSessionStorage

# Initialize
storage = DynamoDBSessionStorage(table_name='sessions')
manager = SessionManager(storage_backend=storage)

# Create session
session = manager.create_session(user_id='user-123')

# Add messages
manager.add_user_message(session.session_id, "Show me failed logins")
manager.add_assistant_message(
    session.session_id,
    "Here's a query for failed logins",
    metadata={'sql': 'SELECT ...'}
)

# Get context for LLM
context = manager.get_context_for_llm(session.session_id)
```

#### 2. Conversational Query API ([src/aws/api/conversational_query.py](../../src/aws/api/conversational_query.py))

Lambda function for context-aware query generation.

**Endpoint:** `POST /api/conversational-query`

**Request:**
```json
{
  "question": "Show me failed logins",
  "sessionId": "abc-123",
  "userId": "user-456"
}
```

**Response:**
```json
{
  "sql": "SELECT ...",
  "explanation": "This query shows...",
  "sessionId": "abc-123",
  "conversationHistory": [
    {"role": "user", "content": "Show me failed logins"},
    {"role": "assistant", "content": "This query shows..."}
  ],
  "warnings": []
}
```

**Features:**
- Auto-creates session if not provided
- Preserves conversation history
- Builds context-aware prompts
- Supports follow-up questions
- Recognizes command types (query modification, alert routing, etc.)

### Frontend Components (Monochrome Design)

#### 1. ConversationHistory ([web/src/components/ConversationHistory.jsx](../../web/src/components/ConversationHistory.jsx))

Displays conversation messages with monochrome avatars and timestamps.

**Features:**
- User/Assistant message distinction
- Relative timestamps
- SQL query preview
- Warning display
- Monochrome design
- Dark mode support

**Design:**
- User messages: Light gray background
- Assistant messages: White/dark background with border
- Avatars: Monochrome icons (User/Bot)
- No color-coding, only grayscale
- Smooth slide-up animations

#### 2. ConversationalQueryInterface ([web/src/components/ConversationalQueryInterface.jsx](../../web/src/components/ConversationalQueryInterface.jsx))

Full conversational query interface with context.

**Features:**
- Session management
- Message history
- Context indicators
- Follow-up suggestions
- SQL display
- New conversation/clear history actions
- Example questions
- Monochrome UI throughout

**Layout:**
- 2/3 conversation area
- 1/3 sidebar with examples
- Sticky input at bottom
- Auto-scroll to latest message

## User Workflows

### Starting a Conversation

**Step 1: Initial Question**
```
User: "Show me all failed login attempts"

System generates:
- Creates new session
- Generates SQL query
- Stores conversation
- Returns query + explanation
```

**Step 2: Follow-up Question**
```
User: "And filter by user admin"

System:
- Retrieves session context
- Sees previous query was about failed logins
- Modifies the query to add WHERE clause
- Updates conversation history
```

**Step 3: Another Follow-up**
```
User: "Show only the top 10"

System:
- Uses full conversation context
- Adds LIMIT 10 to the query
- Maintains all previous filters
```

### Context Recognition Examples

**Pronoun References:**
```
User: "Show me failed logins"
System: [Generates Query A]

User: "And group it by user"
System: Recognizes "it" refers to Query A, modifies accordingly
```

**Implicit Context:**
```
User: "What are the most common API calls?"
System: [Generates Query B from cloudtrail]

User: "Filter by last hour"
System: Knows to filter the cloudtrail query, not a new table
```

**Command Type Detection:**
```
User: "Show me high severity GuardDuty findings"
System: [Generates Query C]

User: "Create a detection rule for this"
System: Recognizes this is about rule creation, not query modification
Returns: { followup_type: "rule_creation" }
```

## Session Management

### Session Lifecycle

```
Create → Active → Expired → Cleanup
  ↓        ↓         ↓         ↓
 0min    <24h      24h      >24h
```

**Creation:**
- Auto-created on first message
- 24-hour expiration time
- Stored in DynamoDB

**Active:**
- All messages preserved
- Context available for LLM
- Updated on each interaction

**Expired:**
- After 24 hours
- Cleaned up by TTL
- New session required

### Session Storage Schema

**DynamoDB Table:** `mantissa-log-conversation-sessions`

```json
{
  "session_id": "abc-123",
  "user_id": "user-456",
  "messages": [
    {
      "role": "user",
      "content": "Show me failed logins",
      "timestamp": "2024-11-27T10:00:00Z",
      "metadata": {}
    },
    {
      "role": "assistant",
      "content": "This query shows failed login attempts",
      "timestamp": "2024-11-27T10:00:01Z",
      "metadata": {
        "sql": "SELECT ...",
        "table_schema": "cloudtrail"
      }
    }
  ],
  "context": {
    "last_query": "SELECT ...",
    "last_table": "cloudtrail",
    "user_preferences": {}
  },
  "created_at": "2024-11-27T10:00:00Z",
  "updated_at": "2024-11-27T10:05:00Z",
  "expires_at": "2024-11-28T10:00:00Z",
  "ttl": 1732791600
}
```

**Indexes:**
- Primary: `session_id`
- GSI: `user_id` + `expires_at` (for listing user sessions)

**TTL:**
- Enabled on `ttl` attribute
- Auto-deletes expired sessions
- Reduces storage costs

## LLM Context Building

### Prompt Structure

```
System Instructions
↓
Available Tables & Schemas
↓
Conversation History (last 10 messages)
↓
Session Context (last query, table, etc.)
↓
Current Question
↓
Response Format Instructions
```

### Example Prompt

```
You are a SQL query generator for AWS security log analysis.

Available tables:
- cloudtrail: AWS CloudTrail API events
- vpc_flow_logs: VPC network traffic logs
- guardduty_findings: AWS GuardDuty findings

Conversation History:
User: Show me failed login attempts
Assistant: This query shows failed CloudTrail login attempts with errorcode
User: Filter by last hour

Last generated query:
SELECT * FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
  AND errorcode IS NOT NULL

Current question: Filter by last hour

Generate a SQL query to answer the question.

Important:
- This is a follow-up question
- Modify the last query shown above
- Add time-based WHERE clause
- Use partitions for performance

Return JSON format:
{
  "sql": "SELECT ...",
  "explanation": "This query...",
  "is_followup": true,
  "followup_type": "query_modification"
}
```

## Follow-up Command Types

The system recognizes different types of follow-up commands:

### 1. Query Modification
```
User: "Show me failed logins"
User: "Add a limit of 10"
Type: query_modification
Action: Modify last SQL query
```

### 2. Alert Routing
```
User: "Show me failed logins"
User: "Send to Slack if this happens"
Type: alert_routing
Action: Open alert configuration modal
```

### 3. Rule Creation
```
User: "Show me failed logins"
User: "Create a detection rule"
Type: rule_creation
Action: Open detection rule wizard
```

### 4. Filtering/Refinement
```
User: "Show me API calls"
User: "Only from IP 203.0.113.42"
Type: query_modification
Action: Add WHERE clause
```

## UI Design (Monochrome)

### Conversation Display

**Light Mode:**
- User messages: `bg-mono-100` (light gray)
- Assistant messages: `bg-white` with border
- Avatars: Grayscale circles with icons
- Timestamps: `text-mono-500`

**Dark Mode:**
- User messages: `bg-mono-850` (dark gray)
- Assistant messages: `bg-mono-900` with border
- Avatars: Inverted grayscale
- Timestamps: `text-mono-500`

**Animations:**
- Messages slide up on appear
- Smooth fade-in transitions
- No color-based status indicators

### Session Indicators

**Active Session:**
```
┌─────────────────────┐
│ ● Session active    │  ← Pulsing dot (monochrome)
└─────────────────────┘
```

**No Session:**
```
Empty state with bot icon
"No conversation history yet"
```

## Performance Considerations

### Context Window Management

**Max Messages in Context:**
- Default: 10 most recent messages
- Prevents token limit issues
- Maintains relevant context

**Message Pruning:**
```python
def get_context_for_llm(session_id, max_messages=10):
    # Only include last N messages
    # Older messages still in DB for history
    # But not sent to LLM
    return session.get_recent_messages(max_messages)
```

### Cost Optimization

**Session Storage:**
- DynamoDB on-demand pricing
- TTL auto-cleanup (no scan costs)
- Compressed message storage

**LLM Costs:**
- Limited context window (max 10 messages)
- Truncate long SQL queries in context
- System prompt reuse

## Testing

### Unit Tests

```python
def test_session_creation():
    manager = SessionManager()
    session = manager.create_session('user-123')
    assert session.session_id is not None
    assert session.user_id == 'user-123'
    assert len(session.messages) == 0

def test_message_addition():
    manager = SessionManager()
    session = manager.create_session('user-123')

    manager.add_user_message(session.session_id, "Test question")
    assert len(session.messages) == 1
    assert session.messages[0].role == 'user'
```

### Integration Tests

```python
def test_conversational_flow():
    # First message
    response1 = client.post('/api/conversational-query', json={
        'question': 'Show me failed logins',
        'userId': 'test-user'
    })
    session_id = response1.json()['sessionId']

    # Follow-up message
    response2 = client.post('/api/conversational-query', json={
        'question': 'Filter by last hour',
        'sessionId': session_id,
        'userId': 'test-user'
    })

    # Should reference previous context
    assert 'WHERE' in response2.json()['sql']
    assert 'hour' in response2.json()['sql'].lower()
```

## Future Enhancements

### 1. Multi-Modal Context
- Image/chart references
- Query result previews in context
- Table schema awareness

### 2. Context Summarization
- Summarize long conversations
- Extract key facts
- Reduce token usage

### 3. Conversation Branching
- "Go back to query 3"
- Multiple conversation threads
- Bookmark important queries

### 4. Collaborative Sessions
- Share sessions with team
- Multi-user conversations
- Collaborative refinement

## Documentation

- [Session Manager Source](../../src/shared/conversation/session_manager.py)
- [Conversational Query API](../../src/aws/api/conversational_query.py)
- [ConversationHistory Component](../../web/src/components/ConversationHistory.jsx)
- [ConversationalQueryInterface](../../web/src/components/ConversationalQueryInterface.jsx)
- [DynamoDB Schema](../../infrastructure/aws/terraform/modules/state/conversation_sessions.tf)
