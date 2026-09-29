"""
JOCKY Compiler Orchestrator.

Combines the Lexer, Parser, Semantic Analyzer, and IR Generator
into a single compiler interface.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from compiler.lexer import Lexer, Token, LexerError
from compiler.parser import Parser, ParserError
from compiler.ast import Program
from compiler.semantic import SemanticAnalyzer, SemanticError
from compiler.ir import IRGenerator, IRInstruction


@dataclass
class CompilerResult:
    success: bool
    tokens: List[Token] = field(default_factory=list)
    ast: Optional[Program] = None
    ir: Optional[List[IRInstruction]] = None
    errors: List[str] = field(default_factory=list)


class Compiler:
    def __init__(self):
        self.semantic_analyzer = SemanticAnalyzer()
        self.ir_generator = IRGenerator()

    def compile(self, source: str) -> CompilerResult:
        errors: List[str] = []

        # 1. Lexing
        try:
            lexer = Lexer(source)
            tokens = lexer.tokenize()
        except LexerError as e:
            return CompilerResult(
                success=False,
                errors=[str(e)],
            )
        except Exception as e:
            return CompilerResult(
                success=False,
                errors=[f"Unexpected Lexer Error: {e}"],
            )

        # 2. Parsing
        try:
            parser = Parser(tokens)
            ast = parser.parse()
        except ParserError as e:
            return CompilerResult(
                success=False,
                tokens=tokens,
                errors=[str(e)],
            )
        except Exception as e:
            return CompilerResult(
                success=False,
                tokens=tokens,
                errors=[f"Unexpected Parser Error: {e}"],
            )

        # 3. Semantic Analysis
        semantic_errors = self.semantic_analyzer.analyze(ast)
        if semantic_errors:
            return CompilerResult(
                success=False,
                tokens=tokens,
                ast=ast,
                errors=[str(err) for err in semantic_errors],
            )

        # 4. IR Generation
        try:
            ir = self.ir_generator.generate(ast)
        except Exception as e:
            return CompilerResult(
                success=False,
                tokens=tokens,
                ast=ast,
                errors=[f"IR Generation Error: {e}"],
            )

        return CompilerResult(
            success=True,
            tokens=tokens,
            ast=ast,
            ir=ir,
            errors=[],
        )
