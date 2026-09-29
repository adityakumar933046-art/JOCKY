"""
Unit tests for the JOCKY Semantic Analyzer, IR Generator, Compiler, and Simulation Interpreter.
"""

from compiler.compiler import Compiler
from compiler.semantic import SemanticAnalyzer
from compiler.lexer import Lexer
from compiler.parser import Parser
from compiler.ir import IRGenerator, IRInstruction
from runtime.interpreter import ForensicInterpreter


def _get_ast(source: str):
    tokens = Lexer(source).tokenize()
    return Parser(tokens).parse()


def test_semantic_unknown_scan_target():
    source = "SCAN UNKNOWN_TARGET\n"
    ast = _get_ast(source)
    analyzer = SemanticAnalyzer()
    errors = analyzer.analyze(ast)

    assert len(errors) == 1
    assert "Unknown SCAN target 'UNKNOWN_TARGET'" in errors[0].message


def test_semantic_unknown_analyze_target():
    source = "ANALYZE BAD_TARGET\n"
    ast = _get_ast(source)
    analyzer = SemanticAnalyzer()
    errors = analyzer.analyze(ast)

    assert len(errors) == 1
    assert "Unknown ANALYZE target 'BAD_TARGET'" in errors[0].message


def test_semantic_report_before_collection():
    source = 'REPORT "premature_report"\n'
    ast = _get_ast(source)
    analyzer = SemanticAnalyzer()
    errors = analyzer.analyze(ast)

    assert any("before any forensic collection" in e.message for e in errors)


def test_semantic_multiple_reports():
    source = """
    SYSTEM INFO
    REPORT "report_1"
    REPORT "report_2"
    """
    ast = _get_ast(source)
    analyzer = SemanticAnalyzer()
    errors = analyzer.analyze(ast)

    assert any("Multiple REPORT commands detected" in e.message for e in errors)


def test_semantic_multiple_errors_reported_in_one_pass():
    source = """
    SCAN UNKNOWN_ONE
    SCAN UNKNOWN_TWO
    ANALYZE INVALID_THREE
    """
    ast = _get_ast(source)
    analyzer = SemanticAnalyzer()
    errors = analyzer.analyze(ast)

    assert len(errors) >= 3
    assert any("UNKNOWN_ONE" in e.message for e in errors)
    assert any("UNKNOWN_TWO" in e.message for e in errors)
    assert any("INVALID_THREE" in e.message for e in errors)


def test_semantic_redundant_consecutive_commands():
    source = """
    SYSTEM INFO
    SCAN PROCESSES
    SCAN PROCESSES
    """
    ast = _get_ast(source)
    analyzer = SemanticAnalyzer()
    errors = analyzer.analyze(ast)

    assert any("Redundant consecutive command" in e.message for e in errors)


def test_ir_generation():
    source = """
    SYSTEM INFO
    SCAN PROCESSES
    ANALYZE MEMORY
    REPORT "final_report"
    """
    ast = _get_ast(source)
    ir = IRGenerator().generate(ast)

    assert len(ir) == 4
    assert ir[0] == IRInstruction(opcode="SYSTEM_INFO", target=None, line=2)
    assert ir[1] == IRInstruction(opcode="SCAN", target="PROCESSES", line=3)
    assert ir[2] == IRInstruction(opcode="ANALYZE", target="MEMORY", line=4)
    assert ir[3] == IRInstruction(opcode="REPORT", target="final_report", line=5)


def test_compiler_end_to_end_success():
    source = """
    SYSTEM INFO
    SCAN PROCESSES
    REPORT "rep"
    """
    compiler = Compiler()
    result = compiler.compile(source)

    assert result.success is True
    assert len(result.errors) == 0
    assert len(result.ir) == 3


def test_compiler_end_to_end_failure():
    source = """
    REPORT "empty_report"
    SCAN NOT_A_TARGET
    """
    compiler = Compiler()
    result = compiler.compile(source)

    assert result.success is False
    assert len(result.errors) > 0


def test_simulation_interpreter_execution():
    instructions = [
        IRInstruction(opcode="SYSTEM_INFO"),
        IRInstruction(opcode="SCAN", target="PROCESSES"),
        IRInstruction(opcode="SCAN", target="NETWORK"),
        IRInstruction(opcode="REPORT", target="report_out"),
    ]
    interpreter = ForensicInterpreter(mode="simulation", quiet=True)
    res = interpreter.execute(instructions)

    assert res.success is True
    assert res.mode == "simulation"
    assert any("→ Collect system information" in line for line in res.output_lines)
    assert any("→ Scan processes" in line for line in res.output_lines)
    assert any("→ Scan network" in line for line in res.output_lines)
    assert any("→ Generate report: report_out" in line for line in res.output_lines)
