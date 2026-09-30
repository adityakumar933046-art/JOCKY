"""
JOCKY Abstract Syntax Tree (AST) definitions.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ASTNode:
    """Base class for all AST nodes with source position tracking."""
    line: int = 1
    column: int = 1


@dataclass
class CommandNode(ASTNode):
    """Base class for JOCKY command statements."""
    pass


@dataclass
class Program(ASTNode):
    """Root node representing an entire JOCKY program."""
    statements: List[CommandNode] = field(default_factory=list)


@dataclass
class SystemInfoCommand(CommandNode):
    """Represents 'SYSTEM INFO' command."""
    pass


@dataclass
class ScanCommand(CommandNode):
    """Represents 'SCAN <TARGET>' command.
    
    Targets include: PROCESSES, NETWORK, FILES, DRIVERS, SERVICES.
    """
    target: str = ""


@dataclass
class AnalyzeCommand(CommandNode):
    """Represents 'ANALYZE <TARGET>' command.
    
    Targets include: PERSISTENCE, MEMORY, NETWORK.
    """
    target: str = ""


@dataclass
class ReportCommand(CommandNode):
    """Represents 'REPORT "<report_name>"' command."""
    target: str = ""


@dataclass
class DetectCommand(CommandNode):
    """Represents 'DETECT' or 'DETECT THREATS' command."""
    target: str = "THREATS"

