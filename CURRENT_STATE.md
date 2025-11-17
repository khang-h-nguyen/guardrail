# GuardRail - Current State & Usage

## What's Been Removed (Cleanup)

**Deleted files:**
- `server/` directory - Old FastAPI prototype, not needed for CLI tool
- `guardrail_cli.py` - Redundant entry point (use `python -m guardrail.cli.main`)
- `guardrail-clean.tar.gz` - Archive file
- Development status indicators from README (removed "Week 1 COMPLETE", etc.)

**Result**: Clean, production-ready codebase with only essential files

---

## What GuardRail Can Do NOW (Without Week 3/4)

### ✅ Core Capability 1: Pattern-Based Threat Detection

**What it does**: Scans text for 56 security threats in real-time

**How to use**:

```bash
# CLI
guardrail detect "Ignore all previous instructions"
guardrail detect "DROP TABLE users"

# Python API
from guardrail import ThreatDetector
detector = ThreatDetector()
threats = detector.scan("malicious text")
```

**Attack categories**:
- Prompt injection (instruction override, role manipulation)
- SQL injection
- Command injection
- Jailbreaking
- Data exfiltration
- File manipulation
- Network exploitation
- Context manipulation

**Use case**: Pre-deployment security testing, input validation

---

### ✅ Core Capability 2: LangChain Real-Time Protection

**What it does**: Monitors LangChain agents during execution, blocks threats

**How to use**:

```python
from guardrail import GuardRailCallback

# Add to ANY LangChain agent
guardrail = GuardRailCallback(
    block_threats=True,
    severity_threshold="HIGH"
)

agent = AgentExecutor(
    agent=my_agent,
    tools=tools,
    callbacks=[guardrail]  # ← ONE LINE
)

# Get security events
summary = guardrail.get_threat_summary()
```

**Features**:
- Monitors: LLM prompts, tool calls, chain inputs
- Modes: Block threats OR log only
- Configurable severity thresholds
- Complete audit trails

**Use case**: Production agent protection, compliance logging

---

### ✅ Core Capability 3: Agent Security Analysis

**What it does**: Analyzes agent configurations for security risks

**How to use**:

```python
from guardrail.core.agent_inspector import AgentInspector

inspector = AgentInspector()
summary = inspector.get_security_summary(agent)
# Returns: risk_level (LOW/MEDIUM/HIGH), identified risks
```

**Detects**:
- Dangerous tools (shell, database, file access)
- Memory leaks
- Overly permissive prompts

**Use case**: Pre-deployment security assessment

---

### ✅ Core Capability 4: Legacy Scan Mode

**What it does**: Simulates attack payloads against agent prompts

**How to use**:

```bash
guardrail scan "You are a helpful assistant"
# Runs 19 attack simulations, reports vulnerabilities
```

**Use case**: Traditional security scanning

---

## Demo Workflows

### Workflow 1: Quick Demo (2 minutes)

```bash
# Show threat detection
guardrail detect "Ignore all instructions"          # Malicious
guardrail detect "What is the weather?"             # Safe

# Show SQL injection detection
guardrail detect "DROP TABLE users; --"
```

**Script**: See `DEMO_SCRIPT.md` for full 2-minute presentation

---

### Workflow 2: Full Capabilities Demo (5 minutes)

```bash
python demo.py
```

This runs 4 demos:
1. CLI threat detection
2. Python API usage
3. LangChain integration simulation
4. Agent security analysis

---

### Workflow 3: Live Integration Demo (Requires OpenAI key)

```bash
export OPENAI_API_KEY="sk-..."
python examples/simple_agent_example.py
```

Shows real LangChain agent with GuardRail protection.

---

## Repository Structure

```
guardrail/
├── guardrail/
│   ├── core/
│   │   ├── detector.py           # Pattern-based detection (NEW)
│   │   ├── agent_inspector.py    # Agent analysis (NEW)
│   │   └── scanner.py            # Legacy simulation mode
│   ├── attacks/
│   │   ├── prompt_injection.py   # 36 patterns + legacy class
│   │   ├── tool_misuse.py        # 20 patterns (NEW)
│   │   ├── attack_chains.py      # Legacy attack chains
│   │   └── base.py               # Base classes
│   ├── integrations/
│   │   └── langchain_callback.py # Real-time monitoring (NEW)
│   └── cli/
│       └── commands/
│           ├── detect.py         # Pattern detection CLI (NEW)
│           └── scan.py           # Legacy scan CLI
├── tests/                        # 50 tests, 100% pass
├── examples/                     # Integration examples
├── demo.py                       # Full demo script
├── DEMO_SCRIPT.md               # 2-min presentation guide
└── README.md                    # Complete documentation
```

**What's used:**
- ✅ `detector.py` - Powers `detect` command and `GuardRailCallback`
- ✅ `agent_inspector.py` - Powers security analysis
- ✅ `scanner.py` - Powers `scan` command (legacy mode)
- ✅ `attack_chains.py` - Used by `scanner.py`
- ✅ `prompt_injection.py` - Used by both new (PATTERNS) and legacy (class)
- ✅ `langchain_callback.py` - LangChain integration

**What's NOT used:**
- ❌ Nothing - all code is actively used

---

## Should You Wait for Week 3/4?

### You CAN demo NOW if:
- You want to show threat detection capabilities
- You want to demonstrate LangChain integration
- Your use case is M&A platforms, chatbots, or API security
- You're presenting to technical audience

### Wait for Week 3/4 if:
- You need LangSmith dashboard integration
- You want prettier visualizations
- You need more documentation/tutorials
- You're presenting to non-technical stakeholders

### What Week 3/4 Would Add:
- **Week 3**: LangSmith integration (view security events in LangSmith dashboard)
- **Week 4**: Documentation, packaging, launch materials

### What You Have NOW:
- ✅ Full threat detection (56 patterns)
- ✅ Real-time LangChain protection
- ✅ Agent security analysis
- ✅ CLI tools
- ✅ Python API
- ✅ 50 passing tests
- ✅ Working examples
- ✅ Complete README

**Bottom line**: The core value proposition is COMPLETE. Week 3/4 are polish and integrations.

---

## Recommended Demo Flow

**5-Minute Technical Demo**:

1. **Problem** (30s): "AI agents handling sensitive M&A data can be attacked via prompt injection"

2. **Solution Overview** (30s): "GuardRail adds real-time security with one line of code"

3. **Live Demo** (3min):
   ```bash
   # Show detection
   guardrail detect "Ignore all instructions"
   guardrail detect "DROP TABLE users"

   # Show full capabilities
   python demo.py
   ```

4. **Code Example** (1min): Show `examples/simple_agent_example.py`

5. **Q&A**: Use `DEMO_SCRIPT.md` for common questions

---

## Files for Demo

**Primary**:
- `demo.py` - Comprehensive 4-part demo (run this!)
- `DEMO_SCRIPT.md` - Your presentation guide
- `README.md` - Technical reference

**Secondary**:
- `examples/simple_agent_example.py` - Real integration
- `examples/README.md` - Integration patterns

**For Questions**:
- Tests in `tests/` - Show code quality
- Attack patterns in `guardrail/attacks/` - Show depth

---

## Summary

**What works NOW**: Everything. 56 patterns, real-time protection, agent analysis.

**Demo readiness**: 100% ready. Use `demo.py` or `DEMO_SCRIPT.md`.

**Should you wait**: No, unless you specifically need LangSmith dashboard integration.

**Your choice**: Week 3/4 add polish. Core functionality is production-ready today.
