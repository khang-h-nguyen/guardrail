"""
Base attack class for GuardRail security testing.

All attack types inherit from BaseAttack and implement
the attack execution and vulnerability detection logic.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Dict, Any
from pydantic import BaseModel


class Severity(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackResult(BaseModel):
    """Result of a single attack"""
    attack_name: str
    payload: str
    response: str
    vulnerable: bool
    severity: Severity
    description: str


class BaseAttack(ABC):
    """
    Base class for all security attacks.

    Each attack type (prompt injection, tool misuse, etc.)
    inherits from this and implements run() and detect().
    """

    name: str
    category: str
    severity: Severity
    payloads: List[str]

    @abstractmethod
    def run(self, agent_prompt: str) -> List[AttackResult]:
        """Execute attack against agent"""
        pass

    @abstractmethod
    def detect_vulnerability(self, response: str, agent_prompt: str) -> bool:
        """Detect if attack succeeded"""
        pass
