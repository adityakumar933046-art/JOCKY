"""
Unit tests for the JOCKY Parser.
"""

import pytest
from compiler.lexer import Lexer
from compiler.parser import Parser, ParserError
from compiler.ast import (
    Program,
    SystemInfoCommand,
    ScanCommand,
    AnalyzeCommand,
    ReportCommand,
)


def _parse_source(source: str) -> Program:
    tokens = Lexer(source).tokenize()
    return Parser(tokens).parse()


def test_parse_valid_program():
    source = """
    SYSTEM INFO
    SCAN PROCESSES
    SCAN NETWORK
    ANALYZE MEMORY
    REPORT "report_01"
    """
    ast = _parse_source(source)
    assert len(ast.statements) == 5

    assert isinstance(ast.statements[0], SystemInfoCommand)
    assert isinstance(ast.statements[1], ScanCommand)
    assert ast.statements[1].target == "PROCESSES"
    assert isinstance(ast.statements[2], ScanCommand)
    assert ast.statements[2].target == "NETWORK"
    assert isinstance(ast.statements[3], AnalyzeCommand)
    assert ast.statements[3].target == "MEMORY"
    assert isinstance(ast.statements[4], ReportCommand)
    assert ast.statements[4].target == "report_01"


def test_parse_all_scan_targets():
    source = """
    SCAN PROCESSES
    SCAN NETWORK
    SCAN FILES
    SCAN DRIVERS
    SCAN SERVICES
    """
    ast = _parse_source(source)
    targets = [stmt.target for stmt in ast.statements if isinstance(stmt, ScanCommand)]
    assert targets == ["PROCESSES", "NETWORK", "FILES", "DRIVERS", "SERVICES"]


def test_parse_all_analyze_targets():
    source = """
    ANALYZE PERSISTENCE
    ANALYZE MEMORY
    ANALYZE NETWORK
    """
    ast = _parse_source(source)
    targets = [stmt.target for stmt in ast.statements if isinstance(stmt, AnalyzeCommand)]
    assert targets == ["PERSISTENCE", "MEMORY", "NETWORK"]


def test_parse_missing_scan_target():
    source = "SCAN\n"
    with pytest.raises(ParserError) as exc_info:
        _parse_source(source)
    assert "Missing target for 'SCAN'" in str(exc_info.value)


def test_parse_missing_report_string():
    source = "REPORT\n"
    with pytest.raises(ParserError) as exc_info:
        _parse_source(source)
    assert "Missing report name string" in str(exc_info.value)


def test_parse_invalid_system_keyword():
    source = "SYSTEM METADATA"
    with pytest.raises(ParserError) as exc_info:
        _parse_source(source)
    assert "Expected 'INFO' after 'SYSTEM'" in str(exc_info.value)


def test_parse_unexpected_command():
    source = "UNSUPPORTED_COMMAND\n"
    with pytest.raises(ParserError) as exc_info:
        _parse_source(source)
    assert "Unexpected command or token 'UNSUPPORTED_COMMAND'" in str(exc_info.value)
