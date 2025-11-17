"""
LangChain Callback Handler for Real-Time Security Monitoring

Integrates GuardRail threat detection into LangChain agents via callbacks.
Monitors prompts and tool invocations in real-time.
"""

from langchain_core.callbacks.base import BaseCallbackHandler
from guardrail.core.detector import ThreatDetector
from typing import Any, Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Raised when a security threat is detected and blocking is enabled"""
    pass


class GuardRailCallback(BaseCallbackHandler):
    """
    LangChain callback for real-time security monitoring.

    Monitors agent execution and detects security threats using
    pattern-based detection. Can log threats or block execution.

    Example:
        callback = GuardRailCallback(block_threats=True)
        agent = AgentExecutor(
            agent=my_agent,
            tools=tools,
            callbacks=[callback]
        )
    """

    def __init__(
        self,
        block_threats: bool = False,
        severity_threshold: str = "HIGH"
    ):
        """
        Initialize GuardRail callback.

        Args:
            block_threats: If True, raise SecurityError when threats detected
            severity_threshold: Minimum severity to block (CRITICAL, HIGH, MEDIUM, LOW)
        """
        super().__init__()
        self.detector = ThreatDetector()
        self.events = []
        self.block_threats = block_threats
        self.severity_threshold = severity_threshold
        self.severity_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any
    ) -> None:
        """
        Monitor prompts before LLM execution.

        Scans each prompt for security threats and optionally blocks execution.
        """
        for prompt in prompts:
            threats = self.detector.scan(prompt)
            if threats:
                self._handle_threats(threats, 'llm_start', prompt)

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any
    ) -> None:
        """
        Monitor tool invocations.

        Scans tool inputs for malicious patterns before execution.
        """
        threats = self.detector.scan(input_str)
        if threats:
            tool_name = serialized.get('name', 'unknown')
            self._handle_threats(threats, 'tool_start', input_str, tool_name)

    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        **kwargs: Any
    ) -> None:
        """Monitor chain inputs for threats"""
        # Scan text inputs
        for key, value in inputs.items():
            if isinstance(value, str):
                threats = self.detector.scan(value)
                if threats:
                    self._handle_threats(threats, 'chain_start', value, key)

    def on_llm_error(
        self,
        error: Exception,
        **kwargs: Any
    ) -> None:
        """Log LLM errors"""
        logger.error(f"LLM error: {error}")

    def on_tool_error(
        self,
        error: Exception,
        **kwargs: Any
    ) -> None:
        """Log tool errors"""
        logger.error(f"Tool error: {error}")

    def _handle_threats(
        self,
        threats: List[Dict],
        stage: str,
        text: str,
        context: Optional[str] = None
    ) -> None:
        """
        Handle detected threats.

        Logs the event and optionally blocks execution based on severity.
        """
        # Record event
        event = {
            'stage': stage,
            'text': text[:100],  # Truncate for logging
            'context': context,
            'threats': threats,
            'threat_count': len(threats)
        }
        self.events.append(event)

        # Log threat
        for threat in threats:
            logger.warning(
                f"Security threat detected at {stage}: "
                f"{threat['category']} - {threat['description']}"
            )

        # Block if configured and severity meets threshold
        if self.block_threats:
            for threat in threats:
                if self._should_block(threat['severity']):
                    raise SecurityError(
                        f"Blocked {threat['severity']} threat at {stage}: "
                        f"{threat['description']}"
                    )

    def _should_block(self, severity: str) -> bool:
        """Check if threat severity meets blocking threshold"""
        try:
            threat_level = self.severity_levels.index(severity)
            threshold_level = self.severity_levels.index(self.severity_threshold)
            return threat_level >= threshold_level
        except ValueError:
            return False

    def get_events(self) -> List[Dict]:
        """Get all recorded security events"""
        return self.events

    def clear_events(self) -> None:
        """Clear recorded events"""
        self.events = []

    def get_threat_summary(self) -> Dict:
        """
        Get summary of detected threats.

        Returns:
            Dictionary with threat counts by category and severity
        """
        if not self.events:
            return {
                'total_events': 0,
                'total_threats': 0,
                'by_category': {},
                'by_severity': {}
            }

        total_threats = sum(e['threat_count'] for e in self.events)
        by_category = {}
        by_severity = {}

        for event in self.events:
            for threat in event['threats']:
                category = threat['category']
                severity = threat['severity']

                by_category[category] = by_category.get(category, 0) + 1
                by_severity[severity] = by_severity.get(severity, 0) + 1

        return {
            'total_events': len(self.events),
            'total_threats': total_threats,
            'by_category': by_category,
            'by_severity': by_severity
        }
