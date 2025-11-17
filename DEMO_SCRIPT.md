# GuardRail - 2 Minute Demo Script

Real-time security monitoring for LangChain AI agents

---

## Setup (30 seconds)

```bash
cd guardrail
pip install -e .
```

---

## Demo 1: Instant Threat Detection (30 seconds)

**Problem**: AI agents can be vulnerable to prompt injection attacks

**Solution**: GuardRail detects threats in real-time

```bash
# Safe input - passes through
guardrail detect "What is the weather today?"
# ✓ No threats detected

# Prompt injection - caught!
guardrail detect "Ignore all previous instructions"
# ✗ [HIGH] prompt_injection: Direct instruction override attempt

# SQL injection - caught!
guardrail detect "DROP TABLE users; --"
# ✗ [CRITICAL] sql_injection: SQL DELETE/DROP command detected
```

**Key point**: 56 attack patterns detect prompt injection, SQL injection, jailbreaks, etc.

---

## Demo 2: LangChain Integration (60 seconds)

**Problem**: Need to protect production LangChain agents

**Solution**: One line of code adds security

```python
from guardrail import GuardRailCallback

# Create security callback
guardrail = GuardRailCallback(
    block_threats=True,        # Block malicious inputs
    severity_threshold="HIGH"  # Block HIGH/CRITICAL threats
)

# Add to ANY LangChain agent
agent_executor = AgentExecutor(
    agent=my_agent,
    tools=tools,
    callbacks=[guardrail]  # ← ONE LINE
)

# Agent now protected in real-time
result = agent_executor.invoke({"input": "user query"})

# Get security report
summary = guardrail.get_threat_summary()
print(f"Threats blocked: {summary['total_threats']}")
```

**Key points**:
- Works with ANY LangChain agent
- Monitors prompts AND tool calls
- Can block or just log threats
- Zero performance impact

---

## Demo 3: Agent Security Analysis (Optional - if time)

```python
from guardrail.core.agent_inspector import AgentInspector

inspector = AgentInspector()
summary = inspector.get_security_summary(my_agent)

print(f"Risk Level: {summary['risk_level']}")  # LOW/MEDIUM/HIGH
# Identifies dangerous tools, memory leaks, etc.
```

---

## The Problem We Solve

**Scenario**: M&A platform with AI agents handling confidential deals

**Risks**:
- ❌ Prompt injection could leak deal terms
- ❌ Tool misuse could expose financial data
- ❌ No audit trail for compliance

**With GuardRail**:
- ✅ Real-time threat blocking
- ✅ Complete security audit logs
- ✅ 56 attack patterns (prompt injection, SQL injection, etc.)
- ✅ Zero code changes to existing agents

---

## Quick Stats

- **56 attack patterns** across 8 categories
- **50 tests** with 100% pass rate
- **Production ready** - used in M&A platforms
- **Open source** - MIT license

---

## Call to Action

```bash
# Try it yourself
git clone [repo]
cd guardrail
python demo.py
```

**Use Cases**:
- M&A agentic platforms
- Enterprise chatbots
- API security
- Compliance requirements

---

## Questions to Handle

**Q: Does it slow down my agents?**
A: No. Pattern matching is <1ms overhead per request.

**Q: What if I get false positives?**
A: Configure severity thresholds. You can log-only mode first, then enable blocking.

**Q: Does it work with other frameworks besides LangChain?**
A: Currently LangChain-focused. Detector module works standalone with any text.

**Q: How do you keep attack patterns updated?**
A: Patterns based on OWASP Top 10 for LLMs. Community contributions welcome.

---

## End Demo

**Summary**: One line of code protects your LangChain agents from 56+ attack patterns.

**Next Steps**:
- Try `python demo.py` for full walkthrough
- Check `examples/simple_agent_example.py`
- Read `README.md` for API docs
