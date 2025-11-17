# GuardRail Examples

Example implementations showing how to use GuardRail for LangChain security monitoring.

## Simple Agent Example

`simple_agent_example.py` - Basic demonstration of GuardRail callback integration

Shows:
- Adding GuardRail to a LangChain agent
- Blocking malicious inputs
- Viewing security event summaries

### Usage

```python
from guardrail import GuardRailCallback

# Create callback with threat blocking
guardrail = GuardRailCallback(
    block_threats=True,
    severity_threshold="HIGH"
)

# Add to any LangChain agent
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    callbacks=[guardrail]  # Add GuardRail protection
)

# Use agent normally - GuardRail monitors in background
result = agent.invoke({"input": "user query"})

# Check for security events
summary = guardrail.get_threat_summary()
print(f"Threats detected: {summary['total_threats']}")
```

### Key Features

1. **Real-time Monitoring**: GuardRail scans all prompts and tool inputs
2. **Threat Blocking**: Optionally prevent malicious inputs from executing
3. **Event Logging**: Track all security events for audit trails
4. **Severity Filtering**: Set thresholds for what threats to block

### Running Examples

```bash
# Set OpenAI API key (required for examples)
export OPENAI_API_KEY="your-key-here"

# Run simple example
python examples/simple_agent_example.py
```

## Pattern Detection

GuardRail detects 50+ attack patterns across categories:

- **Prompt Injection**: Instruction override, role manipulation
- **System Extraction**: Attempts to reveal system prompts
- **Jailbreaking**: Safety bypass attempts
- **Tool Misuse**: SQL injection, command injection
- **Data Exfiltration**: Unauthorized data transmission
- **File Manipulation**: Path traversal, unauthorized access

## Integration Patterns

### Monitor Only (No Blocking)

```python
guardrail = GuardRailCallback(block_threats=False)
# Logs threats but allows execution
```

### Block Critical Threats Only

```python
guardrail = GuardRailCallback(
    block_threats=True,
    severity_threshold="CRITICAL"
)
# Only blocks CRITICAL severity threats
```

### Get Detailed Security Reports

```python
summary = guardrail.get_threat_summary()
events = guardrail.get_events()

for event in events:
    print(f"Stage: {event['stage']}")
    print(f"Threats: {event['threats']}")
```
