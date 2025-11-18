# Security Framework Alignment

GuardRail's attack patterns are based on established security frameworks and industry standards for AI/LLM security.

## Framework Mappings

### OWASP Top 10 for LLMs (2023)

GuardRail provides detection coverage for the following OWASP LLM vulnerabilities:

| OWASP LLM ID | Vulnerability | GuardRail Coverage | Pattern Count |
|--------------|---------------|-------------------|---------------|
| **LLM01** | Prompt Injection | ✓ Full Coverage | 36 patterns |
| **LLM02** | Insecure Output Handling | ✓ Partial (SQL/Command injection) | 8 patterns |
| **LLM03** | Training Data Poisoning | ✗ Out of scope | - |
| **LLM04** | Model Denial of Service | ✗ Out of scope | - |
| **LLM05** | Supply Chain Vulnerabilities | ✗ Out of scope | - |
| **LLM06** | Sensitive Information Disclosure | ✓ Full Coverage | 6 patterns |
| **LLM07** | Insecure Plugin Design | ✓ Full Coverage | 20 patterns |
| **LLM08** | Excessive Agency | ✓ Detection via AgentInspector | - |
| **LLM09** | Overreliance | ✗ Out of scope | - |
| **LLM10** | Model Theft | ✗ Out of scope | - |

**Coverage:** 5/10 OWASP LLM vulnerabilities (runtime detection focused)

### MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

GuardRail patterns align with the following MITRE ATLAS tactics:

| ATLAS Tactic | ATLAS Technique | GuardRail Patterns |
|--------------|-----------------|-------------------|
| **ML Attack Staging** | AML.T0043 - Craft Adversarial Data | PI-001 to PI-036 (Prompt Injection) |
| **ML Model Access** | AML.T0051 - LLM Prompt Injection | PI-001 to PI-036 (Prompt Injection) |
| **ML Model Access** | AML.T0054 - LLM Jailbreak | PI-020 to PI-024 (Jailbreaking) |
| **Exfiltration** | AML.T0024 - Exfiltration via ML Inference API | PI-033 to PI-036 (Data Exfiltration) |

### OWASP Web Top 10 (Classic Vulnerabilities)

GuardRail also detects traditional web vulnerabilities in AI agent tool usage:

| OWASP Web ID | Vulnerability | GuardRail Patterns |
|--------------|--------------|-------------------|
| **A03:2021** | Injection | TM-001 to TM-010 (SQL/Command Injection) |
| **A01:2021** | Broken Access Control | TM-011 to TM-015 (Path Traversal) |
| **A05:2021** | Security Misconfiguration | Detected via AgentInspector |

### CWE (Common Weakness Enumeration)

Pattern mappings to specific CWEs:

- **CWE-89** (SQL Injection): TM-001 to TM-005
- **CWE-77** (Command Injection): TM-006 to TM-008
- **CWE-22** (Path Traversal): TM-011 to TM-014
- **CWE-918** (SSRF): TM-016 to TM-017
- **CWE-94** (Code Injection): TM-009

## Pattern ID Reference

### Prompt Injection Patterns (LLM01)

**Direct Instruction Override:**
- PI-001: Ignore instructions - `OWASP LLM01, MITRE AML.T0051`
- PI-002: Disregard instructions - `OWASP LLM01, MITRE AML.T0051`
- PI-003: Forget instructions - `OWASP LLM01, MITRE AML.T0051`
- PI-004: Override system - `OWASP LLM01, MITRE AML.T0051`
- PI-005: New instructions - `OWASP LLM01, MITRE AML.T0051`

**Role Manipulation:**
- PI-006 to PI-010: Role changes - `OWASP LLM01, MITRE AML.T0051`

**System Prompt Extraction:**
- PI-011 to PI-015: System prompt revelation - `OWASP LLM06, MITRE AML.T0024`

**Jailbreaking:**
- PI-020 to PI-024: Safety bypass - `OWASP LLM01, MITRE AML.T0054`

**Context Manipulation:**
- PI-025 to PI-032: Delimiter/context attacks - `OWASP LLM01, MITRE AML.T0051`

**Data Exfiltration:**
- PI-033 to PI-036: Data leakage attempts - `OWASP LLM06, MITRE AML.T0024`

### Tool Misuse Patterns

**SQL Injection (LLM02, LLM07):**
- TM-001 to TM-005: SQL injection - `OWASP LLM02, OWASP A03, CWE-89`

**Command Injection (LLM07):**
- TM-006 to TM-008: Command execution - `OWASP A03, CWE-77, OWASP LLM07`

**Code Injection (LLM07):**
- TM-009 to TM-010: Code execution - `CWE-94, OWASP LLM07`

**Path Traversal (LLM07):**
- TM-011 to TM-014: File system access - `OWASP A01, CWE-22, OWASP LLM07`

**Network Exploitation (LLM07):**
- TM-015 to TM-018: SSRF and port scanning - `CWE-918, OWASP LLM07`

**Privilege Escalation (LLM08):**
- TM-019 to TM-020: Unauthorized elevation - `OWASP LLM08`

## Framework Alignment Benefits

**For Security Teams:**
- Map GuardRail detections to OWASP LLM Top 10 for compliance reporting
- Align with MITRE ATLAS for threat modeling
- Reference CWE IDs for vulnerability management systems

**For Compliance:**
- Demonstrate coverage of industry-standard vulnerability frameworks
- Use in security assessment reports
- Track remediation against known vulnerability classifications

**For Development:**
- Understand which attack vectors are covered
- Prioritize pattern updates based on emerging OWASP/MITRE guidance
- Communicate security posture using industry terminology

## Out of Scope

GuardRail focuses on **runtime detection** and does not cover:
- Training data poisoning (LLM03)
- Model denial of service (LLM04)
- Supply chain vulnerabilities (LLM05)
- Model theft (LLM10)
- Overreliance issues (LLM09)

These are important but require different mitigation strategies (secure training pipelines, rate limiting, dependency scanning, model protection).

## References

- [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [OWASP Web Security Top 10](https://owasp.org/www-project-top-ten/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)

## Version

- **Document Version:** 1.0
- **Last Updated:** 2025-11-18
- **OWASP LLM Version:** 1.1 (2023)
- **MITRE ATLAS Version:** 4.5.0
