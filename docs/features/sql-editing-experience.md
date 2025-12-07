# SQL Editing Experience

Professional SQL editor with syntax highlighting, inline validation, live cost estimation, and AI-generated SQL recovery.

## Overview

The SQL Editing Experience provides a powerful, user-friendly interface for writing and editing SQL queries with real-time feedback on syntax, performance, and cost implications. Users can seamlessly switch between natural language and SQL modes while maintaining full query context.

## Key Features

1. **Syntax Validation** - Real-time SQL validation with inline warnings
2. **Cost Estimation** - Live cost updates as SQL is edited
3. **Revert to AI-Generated** - Restore original AI-generated SQL
4. **SQL Reference** - Built-in documentation and examples
5. **Query Statistics** - Execution metrics and results display
6. **Save as Detection** - One-click conversion to detection rules

## Components

### 1. SQLEditor ([web/src/components/SQLEditor.jsx](../../web/src/components/SQLEditor.jsx))

Full-featured SQL editor component with validation and cost estimation.

**Props**:
```typescript
{
  initialSql: string;              // Initial SQL content
  aiGeneratedSql: string;          // Original AI-generated SQL (for revert)
  onSqlChange: (sql: string) => void;  // Callback when SQL changes
  onExecute: (sql: string) => void;    // Callback to execute query
  showCostEstimate: boolean;       // Show live cost estimation
  readOnly: boolean;               // Disable editing
}
```

**Features**:
- Debounced validation (500ms)
- Real-time cost estimation
- Revert to original functionality
- Collapsible SQL reference
- Execute button with validation check

### 2. EnhancedQueryInterface ([web/src/components/EnhancedQueryInterface.jsx](../../web/src/components/EnhancedQueryInterface.jsx))

Unified interface combining natural language and SQL modes.

**Features**:
- Mode toggle (Natural Language / SQL Editor)
- Seamless mode switching with context preservation
- Query results display
- Save as Detection integration
- DetectionRuleWizardV3 integration

## SQL Validation

### Validation Rules

**Error Level** (blocks execution):
```javascript
// Missing SELECT statement
if (!sqlUpper.includes('SELECT')) {
  error: 'Query must contain a SELECT statement'
}

// Missing FROM clause
if (!sqlUpper.includes('FROM')) {
  error: 'Query must contain a FROM clause'
}
```

**Warning Level** (shows warning, allows execution):
```javascript
// SELECT * detected
if (sqlUpper.includes('SELECT *')) {
  warning: 'Using SELECT * scans all columns and increases cost. Consider selecting only needed columns.'
}

// No WHERE clause
if (!sqlUpper.includes('WHERE')) {
  warning: 'No WHERE clause detected. Query will scan entire table and may be expensive.'
}

// Missing partition filters
if (!hasDateFilter) {
  warning: 'Consider adding partition filters (e.g., WHERE dt >= DATE_SUB(CURRENT_DATE, 7)) to reduce costs.'
}
```

**Info Level** (suggestions):
```javascript
// No LIMIT clause
if (!sqlUpper.includes('LIMIT')) {
  info: 'Consider adding a LIMIT clause to restrict result size.'
}
```

### Validation Display

Each warning is displayed with:
- Icon indicating severity (error/warning/info)
- Clear message describing the issue
- Actionable recommendation
- Monochrome design with appropriate contrast

Example:
```
⚠ Using SELECT * scans all columns and increases cost.
  Consider selecting only needed columns.
```

## Cost Estimation

### Estimation Algorithm

The system estimates data scanned based on query characteristics:

**Base Estimate**: 1.0 GB

**Multipliers**:
- `SELECT *`: 2.0x (scans all columns)
- No `WHERE` clause: 10.0x (full table scan)
- Has date filter:
  - ≤ 1 day: 0.01x
  - ≤ 7 days: 0.1x
  - ≤ 30 days: 0.3x
  - General date filter: 0.5x
- Has `LIMIT`: 0.8x

**Cost Calculation**:
```javascript
const costPerTB = 5.00;  // AWS Athena pricing
const costPerGB = costPerTB / 1024;
const estimatedCost = estimatedGB * costPerGB;
```

**Confidence Levels**:
- `high`: Query has WHERE clause with partition filters
- `medium`: Query has WHERE clause
- `low`: No WHERE clause (full table scan)

### Cost Display

```
💲 Estimated Cost
$0.00488 per execution
~1.000 GB scanned (medium confidence)
```

Updates live as user edits SQL (debounced 500ms).

## Revert to AI-Generated SQL

**Behavior**:
- "Revert to AI-generated" button appears when SQL is modified
- Clicking restores original AI-generated SQL
- Clears "Modified" indicator
- Triggers re-validation and cost estimation

**Use Cases**:
- User made breaking changes and wants to start over
- User wants to compare their edits to original
- User accidentally modified query

**Implementation**:
```javascript
const handleRevert = () => {
  setSql(originalSql);
  setHasChanges(false);
  if (onSqlChange) {
    onSqlChange(originalSql);
  }
};
```

## SQL Reference

Collapsible reference section with:

**Common Tables**:
- `cloudtrail_logs` - AWS API calls
- `vpc_flow_logs` - Network traffic
- `s3_access_logs` - S3 bucket access
- `lambda_logs` - Lambda function logs

**Partition Filters** (reduce cost):
```sql
WHERE dt >= DATE_SUB(CURRENT_DATE, 7)
WHERE year = '2024' AND month = '11'
```

**Example Query**:
```sql
SELECT eventName, userIdentity.userName, sourceIPAddress
FROM cloudtrail_logs
WHERE dt >= DATE_SUB(CURRENT_DATE, 1)
  AND eventName = 'ConsoleLogin'
LIMIT 100
```

## Query Results Display

After execution, displays:

**Summary Statistics**:
- Results count
- Data scanned (MB)
- Execution time (seconds)

**Results Table**:
- Scrollable table with all columns
- First 50 rows displayed
- Indicator if more results exist
- Monochrome design with hover states

**Example**:
```
Results: 15
Data Scanned: 125.43 MB
Execution Time: 1.25s

┌─────────────┬──────────────┬─────────────────┐
│ eventName   │ userName     │ sourceIPAddress │
├─────────────┼──────────────┼─────────────────┤
│ ConsoleLogin│ alice@ex.com │ 203.0.113.42    │
│ ...         │ ...          │ ...             │
└─────────────┴──────────────┴─────────────────┘
```

## Mode Switching

### Natural Language Mode

- Full conversational interface
- Context-aware follow-ups
- Auto-generates SQL
- Executes immediately

### SQL Editor Mode

- Direct SQL editing
- Real-time validation
- Cost estimation
- Manual execution control

**Switching Behavior**:
- SQL preserved when switching modes
- Query results retained
- Context maintained
- Smooth transition (no page reload)

## Integration with Detection Creation

**Save as Detection** button appears when:
- Query has been executed
- Results are available

**Clicking triggers**:
1. Opens DetectionRuleWizardV3
2. Pre-fills query with current SQL
3. Includes query statistics for cost projection
4. Guides through detection configuration

**Wizard Pre-fills**:
```javascript
{
  query: currentSql,
  queryStats: {
    data_scanned_bytes: 131072000,  // From execution
    execution_time_ms: 1250,
    result_count: 15
  }
}
```

## User Workflows

### Workflow 1: Natural Language → SQL Edit → Detection

**Step 1: Natural language query**
```
User: "Show me failed login attempts in the last 24 hours"
System: Generates and executes SQL
```

**Step 2: Switch to SQL mode**
```
User: Clicks "SQL Editor" tab
System: Shows generated SQL with cost estimate
```

**Step 3: Edit SQL**
```
User: Adds partition filter for cost optimization
      Changes: WHERE dt >= DATE_SUB(CURRENT_DATE, 1)
System: Updates cost estimate in real-time
        Shows: $0.00024 per execution (was $0.02400)
```

**Step 4: Execute and verify**
```
User: Clicks "Execute Query"
System: Shows results with actual statistics
```

**Step 5: Save as detection**
```
User: Clicks "Save as Detection"
System: Opens wizard with pre-filled query and stats
```

### Workflow 2: Direct SQL → Validate → Fix → Execute

**Step 1: Write SQL directly**
```
User: Types query in SQL Editor
System: Real-time validation shows warnings
```

**Step 2: Review warnings**
```
Warning: No WHERE clause detected. Query will scan
         entire table and may be expensive.

Cost Estimate: $5.24 per execution
               ~1024.00 GB scanned (low confidence)
```

**Step 3: Add optimizations**
```
User: Adds WHERE dt >= DATE_SUB(CURRENT_DATE, 7)
System: Warning clears
        New cost: $0.36 per execution
                  ~70.00 GB scanned (medium confidence)
```

**Step 4: Execute**
```
User: Clicks "Execute Query"
System: Returns results with actual metrics
```

### Workflow 3: AI-Generated → Edit → Revert → Retry

**Step 1: Generate from NL**
```
User: "Find all S3 deletions"
System: Generates SQL
```

**Step 2: Edit SQL**
```
User: Modifies query, adds complex JOIN
System: Shows "Modified" indicator
        Validation error: "Invalid JOIN syntax"
```

**Step 3: Revert to original**
```
User: Clicks "Revert to AI-generated"
System: Restores original working SQL
        Clears "Modified" indicator
        Validation passes
```

**Step 4: Try different approach**
```
User: Switches to Natural Language mode
      Asks: "And filter to last 7 days"
System: Refines original query (better than manual edit)
```

## Validation Examples

### Example 1: Optimal Query

**SQL**:
```sql
SELECT eventName, sourceIPAddress, COUNT(*) as count
FROM cloudtrail_logs
WHERE dt >= DATE_SUB(CURRENT_DATE, 7)
  AND eventName = 'DeleteBucket'
GROUP BY eventName, sourceIPAddress
LIMIT 100
```

**Validation Result**:
```
✓ No warnings
Cost Estimate: $0.18 per execution
               ~35.00 GB scanned (high confidence)
```

### Example 2: Needs Optimization

**SQL**:
```sql
SELECT *
FROM cloudtrail_logs
WHERE eventName = 'DeleteBucket'
```

**Validation Result**:
```
⚠ Using SELECT * scans all columns and increases cost.
  Consider selecting only needed columns.

⚠ Consider adding partition filters (e.g.,
  WHERE dt >= DATE_SUB(CURRENT_DATE, 7)) to reduce costs.

ℹ Consider adding a LIMIT clause to restrict result size.

Cost Estimate: $2.50 per execution
               ~512.00 GB scanned (medium confidence)
```

### Example 3: Error State

**SQL**:
```sql
eventName, sourceIPAddress
FROM cloudtrail_logs
WHERE dt >= CURRENT_DATE
```

**Validation Result**:
```
✗ Query must contain a SELECT statement

[Execute Query button is disabled]
```

## Technical Implementation

### Debouncing

Validation and cost estimation use 500ms debounce:
```javascript
useEffect(() => {
  if (debounceTimerRef.current) {
    clearTimeout(debounceTimerRef.current);
  }

  debounceTimerRef.current = setTimeout(() => {
    validateSQL(sql);
    if (showCostEstimate && sql.trim()) {
      estimateCost(sql);
    }
  }, 500);
}, [sql]);
```

**Benefits**:
- Doesn't validate on every keystroke
- Reduces API calls
- Improves performance
- Better UX (no flickering warnings)

### State Management

```javascript
const [sql, setSql] = useState('');              // Current SQL
const [originalSql, setOriginalSql] = useState('');  // AI-generated
const [warnings, setWarnings] = useState([]);    // Validation warnings
const [costEstimate, setCostEstimate] = useState(null);  // Cost data
const [hasChanges, setHasChanges] = useState(false);  // Modification flag
```

### Props Flow

```
EnhancedQueryInterface
  ├─ naturalLanguage mode
  │  └─ ConversationalInterface
  │     └─ Generates SQL via API
  │        └─ Sets currentSql and aiGeneratedSql
  │
  └─ sql mode
     └─ SQLEditor
        ├─ initialSql={currentSql}
        ├─ aiGeneratedSql={aiGeneratedSql}
        ├─ onSqlChange={handleSqlChange}
        └─ onExecute={handleSqlExecute}
```

## Styling

**Monochrome Design**:
- Light mode: White/light gray backgrounds, black text
- Dark mode: Dark gray/black backgrounds, white text
- No color-coding for warnings (uses icons and intensity)
- High contrast for readability
- Consistent 4px/8px spacing grid

**Warning Styles**:
```css
error:   bg-mono-100 dark:bg-mono-850 border-mono-400
warning: bg-mono-50 dark:bg-mono-900 border-mono-300
info:    bg-mono-50 dark:bg-mono-900 border-mono-200
```

**Textarea**:
```css
font-mono text-sm min-h-32 resize-y
```

**Buttons**:
```css
btn-primary: Solid black (light) / white (dark)
btn-secondary: Outlined with hover states
```

## Future Enhancements

### 1. Advanced Syntax Highlighting

Full SQL syntax highlighting with:
- Keywords (SELECT, FROM, WHERE)
- Strings ('value')
- Numbers (123)
- Comments (-- comment)
- Functions (COUNT, SUM)

Implementation would use a library like `react-syntax-highlighter` or custom regex-based highlighting.

### 2. Autocomplete

SQL autocomplete with:
- Table names
- Column names
- SQL keywords
- Functions
- Previous queries

Triggered by:
- Table name after FROM
- Column name after SELECT
- Keyword suggestion

### 3. Query History

Save and recall previous queries:
- Last 10 queries per user
- Search through history
- One-click restore
- Share queries with team

### 4. Query Templates

Pre-built query templates:
- Failed logins
- S3 access patterns
- Network anomalies
- API rate analysis

User can:
- Select template
- Fill in parameters
- Customize and save

### 5. Explain Plan

Show Athena execution plan:
- Data scanned breakdown
- Partition pruning details
- Join strategy
- Optimization suggestions

### 6. Formatting

Auto-format SQL:
- Consistent indentation
- Keyword capitalization
- Line breaks at clauses
- Comment preservation

## Related Documentation

- [Conversational Context](./conversational-context-phase3.md)
- [Cost Projection](./cost-projection-phase2.md)
- [Detection Rule Wizard](./query-to-rule-conversion.md)
- [System Integration](../architecture/system-integration.md)

## Component References

- [SQLEditor.jsx](../../web/src/components/SQLEditor.jsx)
- [EnhancedQueryInterface.jsx](../../web/src/components/EnhancedQueryInterface.jsx)
- [ConversationalInterface.jsx](../../web/src/components/ConversationalInterface.jsx)
- [DetectionRuleWizardV3.jsx](../../web/src/components/DetectionRuleWizardV3.jsx)
