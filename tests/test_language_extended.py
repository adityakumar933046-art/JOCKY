"""
Unit tests for extended JOCKY language commands, direct scan tokens, and DETECT keyword.
"""

import pytest
from compiler.lexer import Lexer, TokenType
from compiler.parser import Parser
from compiler.compiler import Compiler
from runtime.interpreter import ForensicInterpreter


def test_tokenize_extended_commands():
    source = """
    SYSTEM_INFO
    PROCESS_SCAN
    NETWORK_SCAN
    SERVICE_SCAN
    DRIVER_SCAN
    PERSISTENCE_SCAN
    MEMORY_SCAN
    FILE_SCAN
    DETECT
    REPORT "scan_report"
    """
    lexer = Lexer(source)
    tokens = lexer.tokenize()
    types = [t.type for t in tokens if t.type not in (TokenType.NEWLINE, TokenType.EOF)]

    assert types == [
        TokenType.SYSTEM_INFO,
        TokenType.PROCESS_SCAN,
        TokenType.NETWORK_SCAN,
        TokenType.SERVICE_SCAN,
        TokenType.DRIVER_SCAN,
        TokenType.PERSISTENCE_SCAN,
        TokenType.MEMORY_SCAN,
        TokenType.FILE_SCAN,
        TokenType.DETECT,
        TokenType.REPORT,
        TokenType.STRING,
    ]


def test_comment_styles():
    source = """
    # Hash comment
    SYSTEM_INFO
    // Double-slash comment
    PROCESS_SCAN
    """
    compiler = Compiler()
    res = compiler.compile(source)
    assert res.success is True
    assert len(res.ir) == 2
    assert res.ir[0].opcode == "SYSTEM_INFO"
    assert res.ir[1].opcode == "SCAN"
    assert res.ir[1].target == "PROCESSES"


def test_compile_complete_program():
    source = """
    SYSTEM_INFO
    PROCESS_SCAN
    NETWORK_SCAN
    SERVICE_SCAN
    DRIVER_SCAN
    PERSISTENCE_SCAN
    MEMORY_SCAN
    FILE_SCAN
    DETECT
    REPORT "summary_report"
    """
    compiler = Compiler()
    res = compiler.compile(source)
    assert res.success is True
    assert len(res.ir) == 10

    opcodes = [(inst.opcode, inst.target) for inst in res.ir]
    assert opcodes == [
        ("SYSTEM_INFO", None),
        ("SCAN", "PROCESSES"),
        ("SCAN", "NETWORK"),
        ("SCAN", "SERVICES"),
        ("SCAN", "DRIVERS"),
        ("ANALYZE", "PERSISTENCE"),
        ("ANALYZE", "MEMORY"),
        ("SCAN", "FILES"),
        ("DETECT", "THREATS"),
        ("REPORT", "summary_report"),
    ]


def test_simulation_execution():
    source = """
    SYSTEM_INFO
    PROCESS_SCAN
    DETECT
    REPORT "mini"
    """
    compiler = Compiler()
    compile_res = compiler.compile(source)
    assert compile_res.success is True

    interpreter = ForensicInterpreter(mode="simulation", quiet=True)
    exec_res = interpreter.execute(compile_res.ir)
    assert exec_res.success is True
    assert any("threat detection" in line.lower() for line in exec_res.output_lines)


def test_detect_before_collection_fails():
    source = """
    DETECT
    REPORT "invalid"
    """
    compiler = Compiler()
    res = compiler.compile(source)
    assert res.success is False
    assert any("before any forensic collection" in err for err in res.errors)
