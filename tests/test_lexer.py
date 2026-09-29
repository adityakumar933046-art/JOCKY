"""
Unit tests for the JOCKY Lexer.
"""

import pytest
from compiler.lexer import Lexer, TokenType, LexerError


def test_valid_keywords():
    source = "SYSTEM INFO SCAN PROCESSES NETWORK FILES DRIVERS SERVICES ANALYZE PERSISTENCE MEMORY REPORT"
    lexer = Lexer(source)
    tokens = lexer.tokenize()

    expected_types = [
        TokenType.SYSTEM,
        TokenType.INFO,
        TokenType.SCAN,
        TokenType.PROCESSES,
        TokenType.NETWORK,
        TokenType.FILES,
        TokenType.DRIVERS,
        TokenType.SERVICES,
        TokenType.ANALYZE,
        TokenType.PERSISTENCE,
        TokenType.MEMORY,
        TokenType.REPORT,
        TokenType.NEWLINE,
        TokenType.EOF,
    ]
    assert [t.type for t in tokens] == expected_types


def test_case_insensitivity():
    source = "system info scan processes"
    lexer = Lexer(source)
    tokens = lexer.tokenize()

    assert tokens[0].type == TokenType.SYSTEM
    assert tokens[1].type == TokenType.INFO
    assert tokens[2].type == TokenType.SCAN
    assert tokens[3].type == TokenType.PROCESSES


def test_string_literal():
    source = 'REPORT "incident_2026_host1"'
    lexer = Lexer(source)
    tokens = lexer.tokenize()

    assert tokens[0].type == TokenType.REPORT
    assert tokens[1].type == TokenType.STRING
    assert tokens[1].value == "incident_2026_host1"


def test_string_escapes():
    source = r'"line1\nline2\t\"quoted\""'
    lexer = Lexer(source)
    tokens = lexer.tokenize()

    assert tokens[0].type == TokenType.STRING
    assert tokens[0].value == 'line1\nline2\t"quoted"'


def test_unterminated_string():
    source = 'REPORT "unclosed string'
    lexer = Lexer(source)
    with pytest.raises(LexerError) as exc_info:
        lexer.tokenize()
    assert "Unterminated string literal" in str(exc_info.value)


def test_comments_and_whitespace():
    source = """
    # Initial system sweep
    SYSTEM INFO  # Check host details

    # Scan active processes
    SCAN PROCESSES
    """
    lexer = Lexer(source)
    tokens = lexer.tokenize()

    types = [t.type for t in tokens if t.type != TokenType.NEWLINE and t.type != TokenType.EOF]
    assert types == [
        TokenType.SYSTEM,
        TokenType.INFO,
        TokenType.SCAN,
        TokenType.PROCESSES,
    ]


def test_invalid_characters():
    source = "SCAN @PROCESSES"
    lexer = Lexer(source)
    with pytest.raises(LexerError) as exc_info:
        lexer.tokenize()
    assert "Unexpected character: '@'" in str(exc_info.value)
    assert exc_info.value.line == 1
    assert exc_info.value.column == 6


def test_line_column_tracking():
    source = "SYSTEM INFO\nSCAN PROCESSES"
    lexer = Lexer(source)
    tokens = lexer.tokenize()

    assert tokens[0].type == TokenType.SYSTEM
    assert tokens[0].line == 1
    assert tokens[0].column == 1

    scan_tok = [t for t in tokens if t.type == TokenType.SCAN][0]
    assert scan_tok.line == 2
    assert scan_tok.column == 1
