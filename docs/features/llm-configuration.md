# LLM Model Configuration Feature

Bring Your Own Keys (BYOK) for LLM providers with comprehensive usage tracking and cost analytics.

## Overview

The LLM Configuration feature allows users to configure their preferred LLM provider and bring their own API keys. This provides flexibility, cost control, and transparency in LLM usage.

## Key Features

- Multi-provider support (Anthropic, OpenAI, Google, AWS Bedrock)
- Secure API key storage in AWS Secrets Manager
- Model selection for different operations
- Connection testing for each provider
- Real-time usage tracking and cost analytics
- Daily usage trends and breakdowns
- Monochrome UI design

## Supported Providers

### 1. Anthropic (Claude)
- **Models:**
  - Claude 3.5 Sonnet: $3/$15 per 1M tokens (input/output)
  - Claude 3.5 Haiku: $0.80/$4 per 1M tokens
  - Claude 3 Opus: $15/$75 per 1M tokens
- **Requires:** API key from console.anthropic.com

### 2. OpenAI (GPT)
- **Models:**
  - GPT-4 Turbo: $10/$30 per 1M tokens
  - GPT-4: $30/$60 per 1M tokens
  - GPT-3.5 Turbo: $0.50/$1.50 per 1M tokens
- **Requires:** API key from platform.openai.com

### 3. Google (Gemini)
- **Models:**
  - Gemini 1.5 Pro: $3.50/$10.50 per 1M tokens
  - Gemini Pro: $0.50/$1.50 per 1M tokens
- **Requires:** API key from ai.google.dev

### 4. AWS Bedrock (Claude via AWS)
- **Models:**
  - Claude 3.5 Sonnet: $3/$15 per 1M tokens
  - Claude 3.5 Haiku: $0.80/$4 per 1M tokens
  - Claude 3 Opus: $15/$75 per 1M tokens
- **Requires:** AWS credentials (no separate API key)

## Implementation

### Backend Components

#### 1. LLM Settings API ([src/aws/api/llm_settings.py](../../src/aws/api/llm_settings.py))

Manages user LLM preferences and API keys.

**Endpoints:**
- `GET /api/llm-settings/{userId}` - Get user settings
- `PUT /api/llm-settings/{userId}` - Update settings
- `POST /api/llm-settings/{userId}/test` - Test provider connection

**Get Settings Response:**
```json
{
  "preferences": {
    "defaultProvider": "anthropic",
    "queryModel": "claude-3-5-sonnet-20241022",
    "detectionModel": "claude-3-5-sonnet-20241022",
    "maxTokens": 2000,
    "temperature": 0.0,
    "enableCaching": true,
    "trackUsage": true
  },
  "hasApiKeys": {
    "anthropic": true,
    "openai": false,
    "google": false,
    "bedrock": true
  }
}
```

**Update Settings Request:**
```json
{
  "preferences": {
    "defaultProvider": "anthropic",
    "queryModel": "claude-3-5-sonnet-20241022",
    "detectionModel": "claude-3-5-sonnet-20241022",
    "maxTokens": 2000,
    "temperature": 0.0
  },
  "apiKeys": {
    "anthropic": "sk-ant-api03-..."
  }
}
```

**Test Connection Response:**
```json
{
  "success": true,
  "provider": "anthropic",
  "message": "Connection successful",
  "model": "claude-3-5-sonnet-20241022",
  "latency_ms": 342.51
}
```

#### 2. LLM Provider Adapters ([src/shared/llm/providers.py](../../src/shared/llm/providers.py))

Unified interface for all LLM providers.

**Classes:**
- `LLMProvider` - Base abstract class
- `AnthropicProvider` - Anthropic Claude implementation
- `OpenAIProvider` - OpenAI GPT implementation
- `GoogleProvider` - Google Gemini implementation
- `BedrockProvider` - AWS Bedrock implementation
- `LLMProviderFactory` - Factory for creating providers

**Usage Example:**
```python
from llm.providers import LLMProviderFactory

# Create provider
provider = LLMProviderFactory.create('anthropic', api_key='sk-ant-...')

# Generate completion
response = provider.generate(
    prompt="Show me failed login attempts",
    max_tokens=2000,
    temperature=0.0
)

print(f"Content: {response.content}")
print(f"Cost: ${response.usage.cost_usd}")
print(f"Tokens: {response.usage.total_tokens}")
print(f"Latency: {response.usage.latency_ms}ms")
```

**LLMResponse Object:**
```python
@dataclass
class LLMResponse:
    content: str              # Generated text
    usage: LLMUsage           # Usage metrics
    model: str                # Model used
    provider: str             # Provider name
    raw_response: Dict        # Raw API response
```

**LLMUsage Object:**
```python
@dataclass
class LLMUsage:
    input_tokens: int         # Input tokens
    output_tokens: int        # Output tokens
    total_tokens: int         # Total tokens
    cost_usd: float           # Cost in USD
    latency_ms: float         # Latency in ms
    model: str                # Model name
    provider: str             # Provider name
```

#### 3. Usage Tracker ([src/shared/llm/usage_tracker.py](../../src/shared/llm/usage_tracker.py))

Tracks and stores LLM usage metrics.

**Classes:**
- `UsageEntry` - Single usage entry dataclass
- `UsageTracker` - Main tracker class
- `UsageTrackerMiddleware` - Automatic tracking middleware

**Usage Example:**
```python
from llm.usage_tracker import UsageTracker

tracker = UsageTracker()

# Track usage
tracker.track_usage(
    user_id='user-123',
    provider='anthropic',
    model='claude-3-5-sonnet-20241022',
    operation_type='query_generation',
    input_tokens=1500,
    output_tokens=500,
    cost_usd=0.0105,
    latency_ms=342.51,
    request_id='req-abc-123',
    metadata={'query': 'failed logins'}
)

# Get summary
summary = tracker.get_usage_summary(
    user_id='user-123',
    start_date='2024-11-01T00:00:00Z',
    end_date='2024-11-30T23:59:59Z'
)

print(f"Total cost: ${summary['total_cost_usd']}")
print(f"Total requests: {summary['total_requests']}")
print(f"Total tokens: {summary['total_tokens']}")
```

#### 4. Usage Analytics API ([src/aws/api/llm_usage.py](../../src/aws/api/llm_usage.py))

Provides usage statistics and cost analytics.

**Endpoints:**
- `GET /api/llm-usage/{userId}` - Get usage entries
- `GET /api/llm-usage/{userId}/summary` - Get usage summary
- `GET /api/llm-usage/{userId}/daily?days=30` - Get daily usage

**Summary Response:**
```json
{
  "total_requests": 1247,
  "total_tokens": 2456789,
  "total_cost_usd": 12.3456,
  "by_provider": {
    "anthropic": {
      "requests": 847,
      "tokens": 1656789,
      "cost_usd": 8.2345
    },
    "openai": {
      "requests": 400,
      "tokens": 800000,
      "cost_usd": 4.1111
    }
  },
  "by_operation": {
    "query_generation": {
      "requests": 900,
      "tokens": 1800000,
      "cost_usd": 9.0000
    },
    "detection_rule": {
      "requests": 347,
      "tokens": 656789,
      "cost_usd": 3.3456
    }
  },
  "by_model": {
    "claude-3-5-sonnet-20241022": {
      "requests": 847,
      "tokens": 1656789,
      "cost_usd": 8.2345
    }
  }
}
```

### Frontend Components

#### 1. LLMConfiguration ([web/src/components/LLMConfiguration.jsx](../../web/src/components/LLMConfiguration.jsx))

Main configuration interface for LLM settings.

**Features:**
- Provider selection (4 provider cards)
- API key input with masked display
- Connection testing for each provider
- Model selection dropdowns
- Cost preview per 1M tokens
- Advanced settings (max tokens, temperature, caching)
- Monochrome design with dark mode

**Sections:**
1. Default Provider Selection
2. API Keys Configuration
3. Model Selection (Query & Detection)
4. Advanced Settings
5. Save Button

**Provider Card States:**
- Selected: Dark border, light background
- Has API Key: Shows key icon + "Configured" badge
- Test Result: Success (checkmark) or Error (X) with latency

**Cost Preview:**
Displays estimated cost for 1M input + 1M output tokens:
- Query Model Cost
- Detection Model Cost
- Real-time calculation based on selected models

#### 2. LLMUsageAnalytics ([web/src/components/LLMUsageAnalytics.jsx](../../web/src/components/LLMUsageAnalytics.jsx))

Usage analytics and cost tracking dashboard.

**Features:**
- Overview cards (Total Cost, Requests, Tokens, Avg Cost)
- Usage by Provider breakdown
- Usage by Operation breakdown
- Daily usage trend chart
- Usage by Model table
- Time period selector (7/30/90 days)
- Monochrome design with dark mode

**Overview Cards:**
- Total Cost: Dollar icon, total spend in USD
- Total Requests: Lightning icon, request count
- Total Tokens: Activity icon, token count
- Avg Cost/Request: Trending icon, cost efficiency

**Breakdown Sections:**
- Provider: Anthropic, OpenAI, Google, Bedrock
- Operation: Query Generation, Detection Rule, Conversation
- Model: Individual model costs

**Daily Trend Chart:**
- Horizontal bar chart
- Each day shows date, cost bar, request count
- Bars scaled relative to max daily cost
- Monochrome gradient bars

## Security

### API Key Storage

API keys are stored in AWS Secrets Manager, NOT in DynamoDB.

**Secret Naming Convention:**
```
mantissa-log/users/{user_id}/llm/{provider}
```

**Example:**
```
mantissa-log/users/user-123/llm/anthropic
```

**Security Features:**
- Encrypted at rest with KMS
- Never logged or displayed after initial save
- Retrieved only when making LLM calls
- User cannot retrieve their own keys via API

### DynamoDB Storage

User preferences (not API keys) stored in DynamoDB.

**Table:** `mantissa-log-user-settings`

**Item:**
```json
{
  "user_id": "user-123",
  "setting_type": "llm_preferences",
  "preferences": {
    "defaultProvider": "anthropic",
    "queryModel": "claude-3-5-sonnet-20241022",
    "detectionModel": "claude-3-5-sonnet-20241022",
    "maxTokens": 2000,
    "temperature": 0.0,
    "enableCaching": true,
    "trackUsage": true
  },
  "updated_at": "2024-11-27T10:30:00Z"
}
```

## Usage Tracking

### DynamoDB Table

**Table:** `mantissa-log-llm-usage`

**Schema:**
- Hash Key: `user_id` (S)
- Range Key: `timestamp` (S)
- Attributes: provider, model, operation_type, input_tokens, output_tokens, cost_usd, latency_ms, request_id, metadata
- GSI: ProviderIndex (provider + timestamp)
- GSI: OperationTypeIndex (operation_type + timestamp)
- TTL: 90 days (automatic cleanup)

**Item Example:**
```json
{
  "user_id": "user-123",
  "timestamp": "2024-11-27T10:30:00.123Z",
  "provider": "anthropic",
  "model": "claude-3-5-sonnet-20241022",
  "operation_type": "query_generation",
  "input_tokens": 1500,
  "output_tokens": 500,
  "total_tokens": 2000,
  "cost_usd": 0.0105,
  "latency_ms": 342.51,
  "request_id": "req-abc-123",
  "metadata": {
    "query": "Show me failed login attempts",
    "table": "cloudtrail"
  },
  "ttl": 1732791600
}
```

### Operation Types

- `query_generation` - Natural language to SQL queries
- `detection_rule` - Detection rule creation
- `conversation` - Multi-turn conversations
- `rule_enrichment` - Rule metadata enrichment

### Automatic Tracking

Usage is tracked automatically via `UsageTrackerMiddleware`:

```python
from llm.usage_tracker import UsageTracker, UsageTrackerMiddleware
from llm.providers import LLMProviderFactory

tracker = UsageTracker()
middleware = UsageTrackerMiddleware(tracker)

# Generate and track
provider = LLMProviderFactory.create('anthropic', api_key='...')
response = provider.generate(prompt="Show me failed logins")

# Automatically track
middleware.track_llm_call(
    user_id='user-123',
    operation_type='query_generation',
    llm_response=response,
    request_id='req-abc-123',
    metadata={'query': 'failed logins'}
)
```

## Cost Calculation

### Formula

```
Cost = (input_tokens / 1,000,000) * input_price +
       (output_tokens / 1,000,000) * output_price
```

### Example

Claude 3.5 Sonnet:
- Input: 1500 tokens
- Output: 500 tokens
- Input price: $3.00 per 1M tokens
- Output price: $15.00 per 1M tokens

```
Cost = (1500 / 1,000,000) * $3.00 + (500 / 1,000,000) * $15.00
     = $0.0045 + $0.0075
     = $0.0120
```

## User Workflows

### Setting Up a Provider

**Step 1: Navigate to Settings**
```
User → Settings → LLM Configuration
```

**Step 2: Select Provider**
```
Click on provider card (Anthropic, OpenAI, Google, Bedrock)
Card highlights with dark border
```

**Step 3: Enter API Key**
```
Type API key in password field
Key is masked (••••••••)
```

**Step 4: Test Connection**
```
Click "Test" button
System makes test API call
Shows success with latency or error message
```

**Step 5: Configure Models**
```
Select Query Generation Model from dropdown
Select Detection Rule Model from dropdown
See cost preview update automatically
```

**Step 6: Save Settings**
```
Click "Save Settings" button
API key stored in Secrets Manager
Preferences stored in DynamoDB
Success message displayed
```

### Viewing Usage Analytics

**Step 1: Navigate to Analytics**
```
User → Settings → Usage Analytics
```

**Step 2: Select Time Period**
```
Choose from dropdown: 7, 30, or 90 days
Dashboard updates automatically
```

**Step 3: Review Overview**
```
See 4 overview cards:
- Total Cost
- Total Requests
- Total Tokens
- Avg Cost/Request
```

**Step 4: Analyze Breakdowns**
```
Review usage by:
- Provider (which API is most used)
- Operation (queries vs rules vs conversations)
- Model (which models cost most)
```

**Step 5: Check Daily Trends**
```
View bar chart of daily costs
Identify usage spikes
Plan capacity accordingly
```

## UI Design (Monochrome)

### Provider Selection Cards

**Default State:**
```
Border: mono-200/mono-800 (light/dark)
Background: transparent
Hover: border-mono-400/mono-600
```

**Selected State:**
```
Border: mono-950/mono-50 (2px)
Background: mono-100/mono-850
```

**With API Key:**
```
Small badge: "Configured" with key icon
Badge colors: mono-900/mono-100 background
```

### Test Results

**Success:**
```
Background: mono-100/mono-850
Border: mono-300/mono-700
Icon: Checkmark (mono-900/mono-100)
Text: "Connection successful (342ms)"
```

**Error:**
```
Background: mono-150/mono-850
Border: mono-300/mono-700
Icon: X (mono-700/mono-300)
Text: Error message
```

### Usage Analytics

**Overview Cards:**
```
Icon in circle: mono-100/mono-850 background
Icon color: mono-900/mono-100
Value: Large, bold, mono-950/mono-50
Label: Small, mono-600/mono-400
```

**Progress Bars:**
```
Background: mono-100/mono-850
Fill: mono-900/mono-100
Height: 8px, rounded
```

**Daily Chart:**
```
Bar background: mono-100/mono-850
Bar fill: mono-900/mono-100
Width: % of max daily cost
Text overlay: cost amount
```

## Performance Considerations

### Usage Table Size

**TTL Strategy:**
- Keep 90 days of usage data
- Automatic cleanup via DynamoDB TTL
- Reduces storage costs

**Query Optimization:**
- Use GSI for provider/operation filtering
- Limit date ranges to reduce scan costs
- Cache summary calculations

### Cost Optimization

**Secrets Manager:**
- $0.40/secret/month
- 4 providers max per user = $1.60/month
- Only create secrets when keys are provided

**DynamoDB:**
- On-demand pricing for usage table
- ~$0.000125 per write
- ~$0.00025 per read
- TTL deletes are free

**LLM Costs:**
- User brings own keys (BYOK)
- No costs to Mantissa Log platform
- Users control their own spending

## Testing

### Backend Tests

```python
def test_provider_factory():
    provider = LLMProviderFactory.create('anthropic', 'key')
    assert isinstance(provider, AnthropicProvider)

def test_usage_tracking():
    tracker = UsageTracker()
    tracker.track_usage(
        user_id='test',
        provider='anthropic',
        model='claude',
        operation_type='query',
        input_tokens=100,
        output_tokens=50,
        cost_usd=0.001,
        latency_ms=100,
        request_id='test-123'
    )

    summary = tracker.get_usage_summary('test')
    assert summary['total_requests'] == 1
    assert summary['total_cost_usd'] == 0.001

def test_api_key_storage():
    # API key stored in Secrets Manager
    store_api_key('user-123', 'anthropic', 'sk-ant-...')

    # Can retrieve
    key = get_api_key('user-123', 'anthropic')
    assert key == 'sk-ant-...'

    # Can check existence
    exists = check_api_key_exists('user-123', 'anthropic')
    assert exists == True
```

### Frontend Tests

```javascript
test('renders provider selection', () => {
  render(<LLMConfiguration userId="test" />);
  expect(screen.getByText('Anthropic')).toBeInTheDocument();
  expect(screen.getByText('OpenAI')).toBeInTheDocument();
});

test('saves API key and preferences', async () => {
  const { user } = render(<LLMConfiguration userId="test" />);

  // Select provider
  await user.click(screen.getByText('Anthropic'));

  // Enter API key
  await user.type(screen.getByPlaceholderText(/Enter Anthropic/), 'sk-ant-123');

  // Save
  await user.click(screen.getByText('Save Settings'));

  // Verify API called
  expect(fetch).toHaveBeenCalledWith(
    '/api/llm-settings/test',
    expect.objectContaining({ method: 'PUT' })
  );
});
```

## Future Enhancements

### 1. Cost Alerts
- Set monthly budget limits
- Email/Slack notifications at 50%, 80%, 100%
- Automatic provider switching at limits

### 2. Model Recommendations
- Suggest cheaper models for simple queries
- Auto-detect query complexity
- Recommend Haiku vs Sonnet based on query

### 3. Caching Layer
- Cache common query patterns
- Reduce LLM calls by 30-50%
- Implement prompt caching (Anthropic feature)

### 4. Provider Fallbacks
- Primary provider fails → fallback to secondary
- Cost-based routing (use cheapest available)
- Latency-based routing (use fastest)

### 5. Advanced Analytics
- Cost forecasting based on trends
- Anomaly detection (unusual spending)
- Query optimization suggestions

## Documentation

- [LLM Settings API](../../src/aws/api/llm_settings.py)
- [LLM Provider Adapters](../../src/shared/llm/providers.py)
- [Usage Tracker](../../src/shared/llm/usage_tracker.py)
- [Usage Analytics API](../../src/aws/api/llm_usage.py)
- [LLMConfiguration Component](../../web/src/components/LLMConfiguration.jsx)
- [LLMUsageAnalytics Component](../../web/src/components/LLMUsageAnalytics.jsx)
- [LLM Usage Table](../../infrastructure/aws/terraform/modules/state/llm_usage.tf)
