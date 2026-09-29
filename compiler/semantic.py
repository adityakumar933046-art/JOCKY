"""
JOCKY Semantic Analyzer.

Performs static validation of the AST:
- Rejects unknown commands and targets
- Rejects invalid command combinations (e.g. REPORT without prior collection, empty script, duplicate reports)
- Collects and reports multiple errors with line and column numbers
"""

from typing import List, Set
from compiler.ast import (
    Program,
    CommandNode,
    SystemInfoCommand,
    ScanCommand,
    AnalyzeCommand,
    ReportCommand,
)


class SemanticError(Exception):
    def __init__(self, message: str, line: int, column: int):
        self.message = message
        self.line = line
        self.column = column
        super().__init__(f"[Semantic Error at Line {line}:Col {column}] {message}")

    def __str__(self) -> str:
        return f"[Semantic Error at Line {self.line}:Col {self.column}] {self.message}"


class SemanticAnalyzer:
    VALID_SCAN_TARGETS: Set[str] = {
        "PROCESSES",
        "NETWORK",
        "FILES",
        "DRIVERS",
        "SERVICES",
    }

    VALID_ANALYZE_TARGETS: Set[str] = {
        "PERSISTENCE",
        "MEMORY",
        "NETWORK",
    }

    def __init__(self):
        self.errors: List[SemanticError] = []

    def analyze(self, program: Program) -> List[SemanticError]:
        self.errors.clear()

        if not program.statements:
            self.errors.append(
                SemanticError("Empty investigation program: no commands provided.", program.line, program.column)
            )
            return self.errors

        evidence_collected = False
        report_count = 0
        prev_signature = None

        for stmt in program.statements:
            current_signature = None

            if isinstance(stmt, SystemInfoCommand):
                evidence_collected = True
                current_signature = ("SYSTEM_INFO", "")

            elif isinstance(stmt, ScanCommand):
                target = stmt.target
                if target not in self.VALID_SCAN_TARGETS:
                    allowed = ", ".join(sorted(self.VALID_SCAN_TARGETS))
                    self.errors.append(
                        SemanticError(
                            f"Unknown SCAN target '{target}'. Allowed targets are: {allowed}",
                            stmt.line,
                            stmt.column,
                        )
                    )
                else:
                    evidence_collected = True
                current_signature = ("SCAN", target)

            elif isinstance(stmt, AnalyzeCommand):
                target = stmt.target
                if target not in self.VALID_ANALYZE_TARGETS:
                    allowed = ", ".join(sorted(self.VALID_ANALYZE_TARGETS))
                    self.errors.append(
                        SemanticError(
                            f"Unknown ANALYZE target '{target}'. Allowed targets are: {allowed}",
                            stmt.line,
                            stmt.column,
                        )
                    )
                else:
                    evidence_collected = True
                current_signature = ("ANALYZE", target)

            elif isinstance(stmt, ReportCommand):
                report_count += 1
                if not stmt.target.strip():
                    self.errors.append(
                        SemanticError("REPORT target name cannot be empty.", stmt.line, stmt.column)
                    )

                if not evidence_collected:
                    self.errors.append(
                        SemanticError(
                            f"Invalid command combination: Cannot execute REPORT \"{stmt.target}\" before any forensic collection or analysis has taken place.",
                            stmt.line,
                            stmt.column,
                        )
                    )

                if report_count > 1:
                    self.errors.append(
                        SemanticError(
                            f"Invalid command combination: Multiple REPORT commands detected ('{stmt.target}'). Only one final report is allowed per script.",
                            stmt.line,
                            stmt.column,
                        )
                    )
                current_signature = ("REPORT", stmt.target)

            else:
                self.errors.append(
                    SemanticError(f"Unknown AST command node '{type(stmt).__name__}'.", stmt.line, stmt.column)
                )

            # Check redundant consecutive commands
            if current_signature and current_signature == prev_signature and current_signature[0] != "REPORT":
                self.errors.append(
                    SemanticError(
                        f"Redundant consecutive command '{current_signature[0]} {current_signature[1]}'.",
                        stmt.line,
                        stmt.column,
                    )
                )

            prev_signature = current_signature

        return self.errors
