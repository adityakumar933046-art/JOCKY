"""
JOCKY Intermediate Representation (IR).

Linear, simplified instruction stream suitable for direct execution
by forensic interpreters and runtimes.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from compiler.ast import (
    Program,
    CommandNode,
    SystemInfoCommand,
    ScanCommand,
    AnalyzeCommand,
    ReportCommand,
    DetectCommand,
)


@dataclass
class IRInstruction:
    opcode: str
    target: Optional[str] = None
    line: int = 1

    def to_dict(self) -> Dict[str, Any]:
        result = {"opcode": self.opcode, "line": self.line}
        if self.target is not None:
            result["target"] = self.target
        return result

    def __repr__(self) -> str:
        if self.target is not None:
            return f"IRInstruction(opcode={self.opcode!r}, target={self.target!r})"
        return f"IRInstruction(opcode={self.opcode!r})"


class IRGenerator:
    """Generates linear IR instructions from a validated JOCKY AST."""

    def generate(self, program: Program) -> List[IRInstruction]:
        instructions: List[IRInstruction] = []

        for stmt in program.statements:
            if isinstance(stmt, SystemInfoCommand):
                instructions.append(
                    IRInstruction(opcode="SYSTEM_INFO", target=None, line=stmt.line)
                )
            elif isinstance(stmt, ScanCommand):
                instructions.append(
                    IRInstruction(opcode="SCAN", target=stmt.target, line=stmt.line)
                )
            elif isinstance(stmt, AnalyzeCommand):
                instructions.append(
                    IRInstruction(opcode="ANALYZE", target=stmt.target, line=stmt.line)
                )
            elif isinstance(stmt, ReportCommand):
                instructions.append(
                    IRInstruction(opcode="REPORT", target=stmt.target, line=stmt.line)
                )
            elif isinstance(stmt, DetectCommand):
                instructions.append(
                    IRInstruction(opcode="DETECT", target=stmt.target, line=stmt.line)
                )
            else:
                raise ValueError(f"Unknown AST node during IR generation: {type(stmt).__name__}")

        return instructions
