# GuardRail

Security testing framework for AI agents and LLM applications.

## Installation

```bash
pip install -r server/requirements.txt
```

## Usage

```bash
# Run security scan with default prompt
python guardrail_cli.py scan

# Run with custom prompt
python guardrail_cli.py scan "You are a helpful customer service assistant."

# Minimal output
python guardrail_cli.py scan "Your prompt" --quiet
```

## Architecture

```
guardrail/
├── attacks/          # Attack modules (prompt injection, attack chains)
├── core/             # Scanner orchestration
├── cli/              # Command-line interface
├── integrations/     # External integrations
└── utils/            # Utilities
```

## Features

**Security Tests**
- 15 prompt injection payloads
- 4 multi-step attack chain scenarios
- Automated vulnerability detection

**Output**
- Color-coded severity levels
- Security scoring (A-F grades)
- Detailed vulnerability reports

## Development Status

Phase 1.1: Complete
- CLI framework (Typer + Rich)
- Modular attack architecture
- 19 automated security tests
