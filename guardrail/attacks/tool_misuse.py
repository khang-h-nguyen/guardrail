"""
Tool Misuse Attack Patterns

Detection patterns for malicious tool usage including:
- SQL injection
- Command injection
- File system manipulation
- Network exploitation
- Privilege escalation

Framework Alignment:
- OWASP LLM02: Insecure Output Handling
- OWASP LLM07: Insecure Plugin Design
- OWASP Web A03:2021: Injection
- CWE-89 (SQL Injection), CWE-77 (Command Injection), CWE-22 (Path Traversal)
"""

PATTERNS = [
    # SQL Injection
    {
        'id': 'TM-001',
        'category': 'sql_injection',
        'pattern': r'(delete|drop)\s+(from|table)\s+\w+',
        'severity': 'CRITICAL',
        'description': 'SQL DELETE/DROP command detected',
        'framework': 'OWASP-LLM02, OWASP-A03, CWE-89'
    },
    {
        'id': 'TM-002',
        'category': 'sql_injection',
        'pattern': r';\s*(drop|delete|truncate)\s+(table|database)',
        'severity': 'CRITICAL',
        'description': 'SQL injection with destructive command',
        'framework': 'OWASP-LLM02, OWASP-A03, CWE-89'
    },
    {
        'id': 'TM-003',
        'category': 'sql_injection',
        'pattern': r'(union|or)\s+\d+\s*=\s*\d+',
        'severity': 'HIGH',
        'description': 'SQL injection union/boolean attack',
        'framework': 'OWASP-LLM02, OWASP-A03, CWE-89'
    },
    {
        'id': 'TM-004',
        'category': 'sql_injection',
        'pattern': r'--\s*$',
        'severity': 'MEDIUM',
        'description': 'SQL comment injection',
        'framework': 'OWASP-LLM02, OWASP-A03, CWE-89'
    },
    {
        'id': 'TM-005',
        'category': 'sql_injection',
        'pattern': r';\s*exec\s*\(',
        'severity': 'CRITICAL',
        'description': 'SQL stored procedure execution attempt',
        'framework': 'OWASP-LLM02, OWASP-A03, CWE-89'
    },

    # Command Injection
    {
        'id': 'TM-006',
        'category': 'command_injection',
        'pattern': r';\s*(rm|del|format|mkfs)\s',
        'severity': 'CRITICAL',
        'description': 'Destructive shell command injection',
        'framework': 'OWASP-LLM07, OWASP-A03, CWE-77'
    },
    {
        'id': 'TM-007',
        'category': 'command_injection',
        'pattern': r'\|\s*(curl|wget|nc|netcat)',
        'severity': 'CRITICAL',
        'description': 'Network tool injection for exfiltration',
        'framework': 'OWASP-LLM07, OWASP-A03, CWE-77'
    },
    {
        'id': 'TM-008',
        'category': 'command_injection',
        'pattern': r'`[^`]+`',
        'severity': 'HIGH',
        'description': 'Backtick command substitution',
        'framework': 'OWASP-LLM07, OWASP-A03, CWE-77'
    },
    {
        'id': 'TM-009',
        'category': 'command_injection',
        'pattern': r'\$\([^\)]+\)',
        'severity': 'HIGH',
        'description': 'Command substitution syntax',
        'framework': 'OWASP-LLM07, OWASP-A03, CWE-94'
    },
    {
        'id': 'TM-010',
        'category': 'command_injection',
        'pattern': r'&&\s*(rm|del|dd|format)',
        'severity': 'CRITICAL',
        'description': 'Chained destructive command',
        'framework': 'OWASP-LLM07, OWASP-A03, CWE-77'
    },

    # File System Manipulation
    {
        'id': 'TM-011',
        'category': 'file_manipulation',
        'pattern': r'(read|open|cat)\s+/etc/(passwd|shadow|hosts)',
        'severity': 'CRITICAL',
        'description': 'System file access attempt',
        'framework': 'OWASP-LLM07, OWASP-A01, CWE-22'
    },
    {
        'id': 'TM-012',
        'category': 'file_manipulation',
        'pattern': r'(delete|remove|unlink)\s+.{0,50}\.(log|conf|config|env)',
        'severity': 'HIGH',
        'description': 'Critical file deletion attempt',
        'framework': 'OWASP-LLM07, OWASP-A01, CWE-22'
    },
    {
        'id': 'TM-013',
        'category': 'file_manipulation',
        'pattern': r'\.\./\.\.',
        'severity': 'HIGH',
        'description': 'Path traversal attempt',
        'framework': 'OWASP-LLM07, OWASP-A01, CWE-22'
    },
    {
        'id': 'TM-014',
        'category': 'file_manipulation',
        'pattern': r'(write|modify|chmod)\s+.{0,50}(/bin|/sbin|/usr/bin)',
        'severity': 'CRITICAL',
        'description': 'System binary modification attempt',
        'framework': 'OWASP-LLM07, OWASP-A01, CWE-22'
    },
    {
        'id': 'TM-015',
        'category': 'file_manipulation',
        'pattern': r'(upload|write)\s+.{0,50}\.(exe|sh|bat|ps1)',
        'severity': 'HIGH',
        'description': 'Executable file upload attempt',
        'framework': 'OWASP-LLM07, OWASP-A01, CWE-434'
    },

    # Network Exploitation
    {
        'id': 'TM-016',
        'category': 'network_exploit',
        'pattern': r'(scan|nmap|probe)\s+(all\s+)?(ports?|network|hosts?)',
        'severity': 'HIGH',
        'description': 'Network scanning attempt',
        'framework': 'OWASP-LLM07, CWE-918'
    },
    {
        'id': 'TM-017',
        'category': 'network_exploit',
        'pattern': r'(connect|bind|listen)\s+(to|on)\s+(port|socket)',
        'severity': 'HIGH',
        'description': 'Network socket manipulation',
        'framework': 'OWASP-LLM07, CWE-918'
    },
    {
        'id': 'TM-018',
        'category': 'network_exploit',
        'pattern': r'(reverse|bind)\s+shell',
        'severity': 'CRITICAL',
        'description': 'Reverse/bind shell attempt',
        'framework': 'OWASP-LLM07, CWE-77'
    },
    {
        'id': 'TM-019',
        'category': 'network_exploit',
        'pattern': r'(exfiltrate|send|post)\s+to\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        'severity': 'CRITICAL',
        'description': 'Data exfiltration to IP address',
        'framework': 'OWASP-LLM06, CWE-918'
    },
    {
        'id': 'TM-020',
        'category': 'network_exploit',
        'pattern': r'(proxy|tunnel|forward)\s+(through|via)',
        'severity': 'MEDIUM',
        'description': 'Network tunneling attempt',
        'framework': 'OWASP-LLM07, CWE-918'
    },
]
