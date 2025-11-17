"""
GuardRail - Security testing framework for LangChain AI agents
"""

__version__ = "0.1.0"

from .core.detector import ThreatDetector
from .integrations.langchain_callback import GuardRailCallback, SecurityError

__all__ = [
    'ThreatDetector',
    'GuardRailCallback',
    'SecurityError',
    '__version__'
]
