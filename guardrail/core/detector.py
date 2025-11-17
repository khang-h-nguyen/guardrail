"""
Threat Detector - Pattern-based security threat detection

Scans text for security threats using pattern matching across multiple
attack categories.
"""

from typing import List, Dict
import re


class ThreatDetector:
    """
    Pattern-based threat detection for AI agent inputs/outputs.

    Uses regex patterns to identify prompt injection, jailbreaking,
    tool misuse, and other security threats in real-time.
    """

    def __init__(self):
        self.patterns = self._load_attack_patterns()

    def scan(self, text: str) -> List[Dict]:
        """
        Scan text for security threats.

        Args:
            text: Input text to scan

        Returns:
            List of detected threats with type, severity, and description
        """
        if not text:
            return []

        threats = []
        for pattern in self.patterns:
            if self._matches(text, pattern):
                threats.append({
                    'id': pattern['id'],
                    'category': pattern['category'],
                    'type': pattern['category'],  # Keep for backwards compatibility
                    'severity': pattern['severity'],
                    'description': pattern['description'],
                    'pattern': pattern['pattern']
                })
        return threats

    def _matches(self, text: str, pattern: Dict) -> bool:
        """Check if text matches attack pattern"""
        try:
            return re.search(pattern['pattern'], text, re.IGNORECASE) is not None
        except re.error:
            return False

    def _load_attack_patterns(self) -> List[Dict]:
        """Load all attack patterns from attack modules"""
        from guardrail.attacks import prompt_injection

        patterns = []

        # Load prompt injection patterns
        if hasattr(prompt_injection, 'PATTERNS'):
            patterns.extend(prompt_injection.PATTERNS)

        # Load tool misuse patterns (will be added next)
        try:
            from guardrail.attacks import tool_misuse
            if hasattr(tool_misuse, 'PATTERNS'):
                patterns.extend(tool_misuse.PATTERNS)
        except ImportError:
            pass

        return patterns
