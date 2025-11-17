# GuardRail

Real-time security monitoring for LangChain AI agents

## Installation

```bash
pip install -e .
```

## Quick Start

### 1. Pattern-Based Threat Detection

Scan any text for security threats:

```bash
# CLI usage
guardrail detect "Ignore all previous instructions"
```

```python
# Python API
from guardrail import ThreatDetector

detector = ThreatDetector()
threats = detector.scan("Ignore all instructions")

if threats:
    for threat in threats:
        print(f"{threat['severity']}: {threat['description']}")
```

### 2. Runtime Protection for LangChain Agents

Add real-time security monitoring to any LangChain agent:

```python
from langchain.agents import AgentExecutor
from guardrail import GuardRailCallback

# Create GuardRail callback
guardrail = GuardRailCallback(
    block_threats=True,        # Block malicious inputs
    severity_threshold="HIGH"  # Block HIGH and CRITICAL threats
)

# Add to any LangChain agent
agent_executor = AgentExecutor(
    agent=my_agent,
    tools=tools,
    callbacks=[guardrail]  # One line to add security
)

# Agent now has real-time protection
result = agent_executor.invoke({"input": "user query"})

# Check security events
summary = guardrail.get_threat_summary()
print(f"Threats detected: {summary['total_threats']}")
```

### 3. Agent Security Analysis

Inspect agents for security risks:

```python
from guardrail.core.agent_inspector import AgentInspector

inspector = AgentInspector()
summary = inspector.get_security_summary(my_agent)

print(f"Risk Level: {summary['risk_level']}")
for risk in summary['risks']:
    print(f"  - {risk['category']}: {risk['description']}")
```

## Features

### Core Security Engine

- **56+ Attack Patterns** across multiple categories
- **Real-time Detection** using pattern matching
- **Low Latency** - minimal overhead on agent execution
- **Configurable Severity** - set custom blocking thresholds

### Attack Categories

- **Prompt Injection**: Instruction override, role manipulation
- **System Extraction**: System prompt revelation attempts
- **Jailbreaking**: Safety guideline bypasses
- **Tool Misuse**: SQL injection, command injection
- **Data Exfiltration**: Unauthorized data transmission
- **File Manipulation**: Path traversal, unauthorized access
- **Network Exploitation**: Port scanning, reverse shells
- **Context Manipulation**: Session hijacking, delimiter injection

### LangChain Integration

- **Callback Handler**: Drop-in security for any LangChain agent
- **Event Logging**: Complete audit trail of security events
- **Blocking Mode**: Prevent malicious inputs from executing
- **Agent Introspection**: Analyze agents for security risks

## Architecture

```
guardrail/
├── core/
│   ├── detector.py        # Pattern-based threat detection
│   ├── scanner.py         # Attack simulation engine
│   └── agent_inspector.py # Agent security analysis
├── attacks/
│   ├── prompt_injection.py # 36 prompt injection patterns
│   └── tool_misuse.py      # 20 tool misuse patterns
├── integrations/
│   └── langchain_callback.py # Real-time LangChain monitoring
├── cli/
│   └── commands/
│       ├── detect.py      # Pattern detection CLI
│       └── scan.py        # Full security scan CLI
└── utils/                 # Utilities
```

## Testing

50 comprehensive tests covering all functionality:

```bash
# Run all tests
pytest

# Run specific test suite
pytest tests/test_detector.py -v
pytest tests/test_callback.py -v
pytest tests/test_agent_inspector.py -v

# With coverage
pytest --cov=guardrail tests/
```

## Examples

See [`examples/`](examples/) directory for complete examples:

- `simple_agent_example.py` - Basic GuardRail integration
- `README.md` - Integration patterns and usage guide

## Use Cases

### M&A Agentic Platforms

GuardRail provides critical security for AI agents handling sensitive deal data:

- ✓ Prevents prompt injection attacks that could leak confidential deal terms
- ✓ Blocks unauthorized access to sensitive financial information
- ✓ Monitors tool usage to prevent data exfiltration
- ✓ Provides audit trails for compliance requirements
- ✓ Real-time protection without performance degradation

### Enterprise AI Applications

- API security monitoring
- Chatbot input validation
- Agent behavior analysis
- Security event tracking

## Current Status

Production-ready MVP with core security features and LangChain integration.

## API Reference

### ThreatDetector

```python
detector = ThreatDetector()
threats = detector.scan(text: str) -> List[Dict]
```

Returns list of detected threats with:
- `id`: Pattern ID
- `category`: Threat category
- `severity`: CRITICAL, HIGH, MEDIUM, or LOW
- `description`: Human-readable description

### GuardRailCallback

```python
callback = GuardRailCallback(
    block_threats: bool = False,
    severity_threshold: str = "HIGH"
)
```

Methods:
- `get_events()` - Get all security events
- `get_threat_summary()` - Get summary by category/severity
- `clear_events()` - Clear recorded events

### AgentInspector

```python
inspector = AgentInspector()
info = inspector.inspect(agent) -> Dict
summary = inspector.get_security_summary(agent) -> Dict
```

## Contributing

GuardRail is in active development. See development guide for contribution guidelines.

## License

MIT License - See LICENSE file for details

## Support

- Documentation: See `docs/` directory
- Examples: See `examples/` directory
- Issues: GitHub Issues
- Security: Report via security@example.com

---

**Built for security-conscious AI development**
