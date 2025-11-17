"""
Tool Misuse Attack Patterns

Detection patterns for malicious tool usage including:
- SQL injection
- Command injection
- File system manipulation
- Network exploitation
- Privilege escalation
"""

PATTERNS = [
    # SQL Injection
    {
        'id': 'TM-001',
        'category': 'sql_injection',
        'pattern': r'(delete|drop)\s+(from|table)\s+\w+',
        'severity': 'CRITICAL',
        'description': 'SQL DELETE/DROP command detected'
    },
    {
        'id': 'TM-002',
        'category': 'sql_injection',
        'pattern': r';\s*(drop|delete|truncate)\s+(table|database)',
        'severity': 'CRITICAL',
        'description': 'SQL injection with destructive command'
    },
    {
        'id': 'TM-003',
        'category': 'sql_injection',
        'pattern': r'(union|or)\s+\d+\s*=\s*\d+',
        'severity': 'HIGH',
        'description': 'SQL injection union/boolean attack'
    },
    {
        'id': 'TM-004',
        'category': 'sql_injection',
        'pattern': r'--\s*$',
        'severity': 'MEDIUM',
        'description': 'SQL comment injection'
    },
    {
        'id': 'TM-005',
        'category': 'sql_injection',
        'pattern': r';\s*exec\s*\(',
        'severity': 'CRITICAL',
        'description': 'SQL stored procedure execution attempt'
    },

    # Command Injection
    {
        'id': 'TM-006',
        'category': 'command_injection',
        'pattern': r';\s*(rm|del|format|mkfs)\s',
        'severity': 'CRITICAL',
        'description': 'Destructive shell command injection'
    },
    {
        'id': 'TM-007',
        'category': 'command_injection',
        'pattern': r'\|\s*(curl|wget|nc|netcat)',
        'severity': 'CRITICAL',
        'description': 'Network tool injection for exfiltration'
    },
    {
        'id': 'TM-008',
        'category': 'command_injection',
        'pattern': r'`[^`]+`',
        'severity': 'HIGH',
        'description': 'Backtick command substitution'
    },
    {
        'id': 'TM-009',
        'category': 'command_injection',
        'pattern': r'\$\([^\)]+\)',
        'severity': 'HIGH',
        'description': 'Command substitution syntax'
    },
    {
        'id': 'TM-010',
        'category': 'command_injection',
        'pattern': r'&&\s*(rm|del|dd|format)',
        'severity': 'CRITICAL',
        'description': 'Chained destructive command'
    },

    # File System Manipulation
    {
        'id': 'TM-011',
        'category': 'file_manipulation',
        'pattern': r'(read|open|cat)\s+/etc/(passwd|shadow|hosts)',
        'severity': 'CRITICAL',
        'description': 'System file access attempt'
    },
    {
        'id': 'TM-012',
        'category': 'file_manipulation',
        'pattern': r'(delete|remove|unlink)\s+.{0,50}\.(log|conf|config|env)',
        'severity': 'HIGH',
        'description': 'Critical file deletion attempt'
    },
    {
        'id': 'TM-013',
        'category': 'file_manipulation',
        'pattern': r'\.\./\.\.',
        'severity': 'HIGH',
        'description': 'Path traversal attempt'
    },
    {
        'id': 'TM-014',
        'category': 'file_manipulation',
        'pattern': r'(write|modify|chmod)\s+.{0,50}(/bin|/sbin|/usr/bin)',
        'severity': 'CRITICAL',
        'description': 'System binary modification attempt'
    },
    {
        'id': 'TM-015',
        'category': 'file_manipulation',
        'pattern': r'(upload|write)\s+.{0,50}\.(exe|sh|bat|ps1)',
        'severity': 'HIGH',
        'description': 'Executable file upload attempt'
    },

    # Network Exploitation
    {
        'id': 'TM-016',
        'category': 'network_exploit',
        'pattern': r'(scan|nmap|probe)\s+(all\s+)?(ports?|network|hosts?)',
        'severity': 'HIGH',
        'description': 'Network scanning attempt'
    },
    {
        'id': 'TM-017',
        'category': 'network_exploit',
        'pattern': r'(connect|bind|listen)\s+(to|on)\s+(port|socket)',
        'severity': 'HIGH',
        'description': 'Network socket manipulation'
    },
    {
        'id': 'TM-018',
        'category': 'network_exploit',
        'pattern': r'(reverse|bind)\s+shell',
        'severity': 'CRITICAL',
        'description': 'Reverse/bind shell attempt'
    },
    {
        'id': 'TM-019',
        'category': 'network_exploit',
        'pattern': r'(exfiltrate|send|post)\s+to\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        'severity': 'CRITICAL',
        'description': 'Data exfiltration to IP address'
    },
    {
        'id': 'TM-020',
        'category': 'network_exploit',
        'pattern': r'(proxy|tunnel|forward)\s+(through|via)',
        'severity': 'MEDIUM',
        'description': 'Network tunneling attempt'
    },
]
