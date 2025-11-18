# GuardRail

Real-time security monitoring for LangChain AI agents

## Overview

GuardRail provides pattern-based threat detection and risk scoring for AI agents. It monitors prompts, tool calls and agent behavior in real-time to help you build secure AI applications.

**Key Features**
- 56+ attack patterns covering prompt injection, SQL injection, jailbreaks and more
- Risk-based scoring (0-100) instead of binary blocking
- Drop-in LangChain callback for real-time protection
- Human-in-the-loop review queue for ambiguous cases
- Zero performance overhead

## Installation
```bash
pip install -e .
```

## Quick Start

### 1. Detect Threats in Text

**CLI**
```bash
guardrail detect "Ignore all previous instructions"
guardrail detect "DROP TABLE users"
```

**Python API**
```python
from guardrail import ThreatDetector

detector = ThreatDetector()
threats = detector.scan("Ignore all instructions")

for threat in threats:
    print(f"[{threat['severity']}] {threat['description']}")
```

### 2. Protect LangChain Agents
```python
from langchain.agents import AgentExecutor
from guardrail import GuardRailCallback

# Create callback with risk scoring
guardrail = GuardRailCallback(
    auto_block_threshold=81,  # Block CRITICAL threats (81-100)
    review_threshold=31       # Flag MEDIUM+ for review (31-60)
)

# Add to any agent (one line)
agent = AgentExecutor(
    agent=my_agent,
    tools=tools,
    callbacks=[guardrail]
)

# Run agent with real-time protection
result = agent.invoke({"input": "user query"})

# Review security events
summary = guardrail.get_score_summary()
print(f"Average risk: {summary['avg_score']}/100")
print(f"Events flagged: {summary['flagged_for_review']}")
```

### 3. Analyze Agent Security
```python
from guardrail.core.agent_inspector import AgentInspector

inspector = AgentInspector()
summary = inspector.get_security_summary(my_agent)

print(f"Risk level: {summary['risk_level']}")
for risk in summary['risks']:
    print(f"  [{risk['severity']}] {risk['description']}")
```

## Risk Scoring System

GuardRail uses 0-100 risk scores for nuanced threat detection.

| Score | Level | Action |
|-------|-------|--------|
| 0-30 | LOW | Auto-allow |
| 31-60 | MEDIUM | Flag for review |
| 61-80 | HIGH | Recommend blocking |
| 81-100 | CRITICAL | Auto-block |

**How scores are calculated**
- Pattern severity - CRITICAL (+60), HIGH (+40), MEDIUM (+20), LOW (+10)
- Malicious keywords - +11 per keyword (email, secret, password, drop, etc.)
- Legitimate keywords - -15 per keyword (reset, start fresh, etc.)

**Example configurations**
```python
# Production - Only block CRITICAL
callback = GuardRailCallback(auto_block_threshold=81)

# Strict mode - Block HIGH and CRITICAL
callback = GuardRailCallback(auto_block_threshold=61)

# Audit only - Never block, just log
callback = GuardRailCallback(auto_block_threshold=101)
```

## Attack Coverage

56+ patterns across 8 categories:

- **Prompt Injection** (36 patterns) - Instruction override, role manipulation, context manipulation
- **Tool Misuse** (20 patterns) - SQL injection, command injection, file traversal
- **System Extraction** - System prompt revelation attempts
- **Jailbreaking** - Safety guideline bypasses
- **Data Exfiltration** - Unauthorized data transmission
- **Network Exploitation** - Port scanning, reverse shells
- **Context Manipulation** - Session hijacking, delimiter injection
- **Attack Chains** - Multi-stage attack detection

## Architecture
```
guardrail/
├── core/
│   ├── detector.py         # Pattern-based detection engine
│   ├── risk_scorer.py      # Risk scoring (0-100)
│   ├── agent_inspector.py  # Agent security analysis
│   └── scanner.py          # Attack simulation
├── attacks/
│   ├── prompt_injection.py # 36 prompt injection patterns
│   └── tool_misuse.py      # 20 tool misuse patterns
├── integrations/
│   └── langchain_callback.py # Real-time monitoring
└── cli/
    └── commands/
        ├── detect.py       # Threat detection CLI
        └── scan.py         # Security scan CLI
```

## API Reference

### ThreatDetector
```python
from guardrail import ThreatDetector

detector = ThreatDetector()
threats = detector.scan(text: str) -> List[Dict]
```

Returns list of threats:
```python
{
    'id': 'PI-001',
    'category': 'prompt_injection',
    'severity': 'HIGH',  # CRITICAL, HIGH, MEDIUM or LOW
    'description': 'Direct instruction override attempt'
}
```

### GuardRailCallback
```python
from guardrail import GuardRailCallback

callback = GuardRailCallback(
    auto_block_threshold: int = 81,    # Score to auto-block (81 = CRITICAL only)
    review_threshold: int = 31,        # Score to flag for review (31 = MEDIUM+)
    enable_review_queue: bool = True   # Maintain human review queue
)
```

**Methods**
- `get_events()` - All security events
- `get_score_summary()` - Score statistics
- `get_threat_summary()` - Threat breakdown by category/severity
- `get_review_queue()` - Items pending human review
- `clear_events()` - Clear event history

**Event structure**
```python
{
    'stage': 'llm_start',
    'text': 'user input...',
    'score': 62,
    'level': 'HIGH',
    'threats': [...]
}
```

### AgentInspector
```python
from guardrail.core.agent_inspector import AgentInspector

inspector = AgentInspector()

# Detailed inspection
info = inspector.inspect(agent) -> Dict

# Security summary
summary = inspector.get_security_summary(agent) -> Dict
```

Returns:
```python
{
    'risk_level': 'MEDIUM',  # LOW, MEDIUM or HIGH
    'risks': [
        {
            'category': 'dangerous_tool',
            'severity': 'HIGH',
            'description': 'Agent has shell access',
            'recommendation': 'Restrict shell commands'
        }
    ]
}
```

## Testing

49 tests covering all functionality.
```bash
# Run all tests
pytest

# Specific test suites
pytest tests/test_detector.py -v
pytest tests/test_callback.py -v
pytest tests/test_agent_inspector.py -v

# With coverage
pytest --cov=guardrail tests/
```

## Use Cases

**Enterprise AI Applications**
- Chatbot input validation
- API security monitoring
- Multi-agent systems
- Production LLM deployments

**Security Operations**
- Real-time threat detection
- Security audit trails
- Compliance logging
- Risk assessment

**Development**
- Pre-deployment security testing
- Agent configuration analysis
- Attack pattern testing
- Security-first AI development

## Human-in-the-Loop Review

GuardRail includes a review queue for handling ambiguous inputs.
```python
callback = GuardRailCallback(
    auto_block_threshold=81,
    review_threshold=31,
    enable_review_queue=True
)

# Run agent...
agent.invoke({"input": "some query"})

# Check review queue
queue = callback.get_review_queue()
for item in queue.get_pending():
    print(f"Score: {item['score']}/100")
    print(f"Text: {item['text']}")
    print(f"Threats: {item['threats']}")

    # Human decision
    if user_approves(item):
        queue.approve(item['id'])
    else:
        queue.reject(item['id'])
```

## CLI Commands
```bash
# Detect threats in text
guardrail detect "your input text"

# Full security scan (simulates attacks)
guardrail scan "your system prompt"
```

## Performance

- Pattern matching - <1ms overhead per request
- No external API calls
- Stateless detection (scales horizontally)
- Minimal memory footprint

## Contributing

Contributions welcome! Areas of interest include additional attack patterns, framework integrations (beyond LangChain), performance optimizations and documentation improvements.

## License

MIT License

## Support

- **Documentation** - See this README
- **Issues** - GitHub Issues
- **Security** - Report security issues via GitHub Security Advisories

Built for secure AI development