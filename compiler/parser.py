"""
JOCKY Parser.

Parses a stream of JOCKY tokens into an Abstract Syntax Tree (AST).
"""

from typing import List, Optional
from compiler.lexer import Token, TokenType
from compiler.ast import (
    Program,
    CommandNode,
    SystemInfoCommand,
    ScanCommand,
    AnalyzeCommand,
    ReportCommand,
)


class ParserError(Exception):
    def __init__(self, message: str, line: int, column: int):
        self.message = message
        self.line = line
        self.column = column
        super().__init__(f"Parser Error at {line}:{column}: {message}")


class Parser:
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0

    def _peek(self, offset: int = 0) -> Token:
        idx = self.pos + offset
        if idx < len(self.tokens):
            return self.tokens[idx]
        return self.tokens[-1]  # Return EOF token

    def _advance(self) -> Token:
        tok = self._peek()
        if self.pos < len(self.tokens):
            self.pos += 1
        return tok

    def _match(self, *expected_types: TokenType) -> bool:
        if self._peek().type in expected_types:
            self._advance()
            return True
        return False

    def _expect(self, expected_type: TokenType, error_msg: Optional[str] = None) -> Token:
        current = self._peek()
        if current.type == expected_type:
            return self._advance()
        msg = error_msg or f"Expected token {expected_type.name}, found {current.type.name} ('{current.value}')"
        raise ParserError(msg, current.line, current.column)

    def parse(self) -> Program:
        statements: List[CommandNode] = []
        start_line = self._peek().line
        start_col = self._peek().column

        # Skip leading newlines
        while self._match(TokenType.NEWLINE):
            pass

        while self._peek().type != TokenType.EOF:
            stmt = self._parse_statement()
            if stmt:
                statements.append(stmt)

            # Consume mandatory newline or allow EOF
            if self._peek().type == TokenType.NEWLINE:
                while self._match(TokenType.NEWLINE):
                    pass
            elif self._peek().type != TokenType.EOF:
                current = self._peek()
                raise ParserError(
                    f"Expected newline after command, found {current.type.name} ('{current.value}')",
                    current.line,
                    current.column,
                )

        return Program(statements=statements, line=start_line, column=start_col)

    def _parse_statement(self) -> CommandNode:
        current = self._peek()

        if current.type == TokenType.SYSTEM:
            return self._parse_system()
        elif current.type == TokenType.SCAN:
            return self._parse_scan()
        elif current.type == TokenType.ANALYZE:
            return self._parse_analyze()
        elif current.type == TokenType.REPORT:
            return self._parse_report()
        else:
            raise ParserError(
                f"Unexpected command or token '{current.value}' (type {current.type.name})",
                current.line,
                current.column,
            )

    def _parse_system(self) -> SystemInfoCommand:
        sys_tok = self._advance()
        info_tok = self._peek()
        if info_tok.type == TokenType.INFO:
            self._advance()
            return SystemInfoCommand(line=sys_tok.line, column=sys_tok.column)
        raise ParserError(
            f"Expected 'INFO' after 'SYSTEM', found '{info_tok.value}'",
            info_tok.line,
            info_tok.column,
        )

    def _parse_scan(self) -> ScanCommand:
        scan_tok = self._advance()
        target_tok = self._peek()

        # Target can be any keyword (PROCESSES, NETWORK, FILES, DRIVERS, SERVICES) or an IDENTIFIER
        valid_types = (
            TokenType.PROCESSES,
            TokenType.NETWORK,
            TokenType.FILES,
            TokenType.DRIVERS,
            TokenType.SERVICES,
            TokenType.IDENTIFIER,
        )

        if target_tok.type in valid_types:
            self._advance()
            return ScanCommand(target=target_tok.value.upper(), line=scan_tok.line, column=scan_tok.column)
        elif target_tok.type in (TokenType.NEWLINE, TokenType.EOF):
            raise ParserError("Missing target for 'SCAN' command", scan_tok.line, scan_tok.column)
        else:
            # Let semantic analyzer handle if it's an unrecognized target keyword, or consume it
            consumed = self._advance()
            return ScanCommand(target=consumed.value.upper(), line=scan_tok.line, column=scan_tok.column)

    def _parse_analyze(self) -> AnalyzeCommand:
        analyze_tok = self._advance()
        target_tok = self._peek()

        valid_types = (
            TokenType.PERSISTENCE,
            TokenType.MEMORY,
            TokenType.NETWORK,
            TokenType.IDENTIFIER,
        )

        if target_tok.type in valid_types:
            self._advance()
            return AnalyzeCommand(target=target_tok.value.upper(), line=analyze_tok.line, column=analyze_tok.column)
        elif target_tok.type in (TokenType.NEWLINE, TokenType.EOF):
            raise ParserError("Missing target for 'ANALYZE' command", analyze_tok.line, analyze_tok.column)
        else:
            consumed = self._advance()
            return AnalyzeCommand(target=consumed.value.upper(), line=analyze_tok.line, column=analyze_tok.column)

    def _parse_report(self) -> ReportCommand:
        report_tok = self._advance()
        target_tok = self._peek()

        if target_tok.type == TokenType.STRING:
            self._advance()
            return ReportCommand(target=target_tok.value, line=report_tok.line, column=report_tok.column)
        elif target_tok.type in (TokenType.NEWLINE, TokenType.EOF):
            raise ParserError("Missing report name string for 'REPORT' command", report_tok.line, report_tok.column)
        else:
            raise ParserError(
                f"Expected string literal for 'REPORT', found {target_tok.type.name} ('{target_tok.value}')",
                target_tok.line,
                target_tok.column,
            )
