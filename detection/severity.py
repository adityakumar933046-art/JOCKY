"""
JOCKY Severity Classification Model.

Provides deterministic, ordinal severity levels for cybersecurity risk assessment.
"""

from enum import Enum
from functools import total_ordering


@total_ordering
class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self]

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank == other.rank
        if isinstance(other, str):
            return self.value == other.upper()
        return False

    def __hash__(self) -> int:
        return hash(self.value)

    def __str__(self) -> str:
        return self.value

    @classmethod
    def from_string(cls, name: str) -> "Severity":
        try:
            return cls[name.upper()]
        except KeyError:
            return cls.INFO
