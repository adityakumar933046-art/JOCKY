"""
JOCKY Lexer (Tokenizer).

Tokenizes JOCKY digital-forensics source code into a stream of tokens.
"""

from enum import Enum, auto
from dataclasses import dataclass
from typing import List, Optional


class TokenType(Enum):
    # Keywords
    SYSTEM = auto()
    INFO = auto()
    SCAN = auto()
    PROCESSES = auto()
    NETWORK = auto()
    FILES = auto()
    DRIVERS = auto()
    SERVICES = auto()
    ANALYZE = auto()
    PERSISTENCE = auto()
    MEMORY = auto()
    REPORT = auto()

    # Literals & Identifiers
    IDENTIFIER = auto()
    STRING = auto()

    # Layout & Control
    NEWLINE = auto()
    EOF = auto()


KEYWORDS = {
    "SYSTEM": TokenType.SYSTEM,
    "INFO": TokenType.INFO,
    "SCAN": TokenType.SCAN,
    "PROCESSES": TokenType.PROCESSES,
    "NETWORK": TokenType.NETWORK,
    "FILES": TokenType.FILES,
    "DRIVERS": TokenType.DRIVERS,
    "SERVICES": TokenType.SERVICES,
    "ANALYZE": TokenType.ANALYZE,
    "PERSISTENCE": TokenType.PERSISTENCE,
    "MEMORY": TokenType.MEMORY,
    "REPORT": TokenType.REPORT,
}


@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    column: int

    def __repr__(self) -> str:
        return f"Token({self.type.name}, {self.value!r}, line={self.line}, col={self.column})"


class LexerError(Exception):
    def __init__(self, message: str, line: int, column: int):
        self.message = message
        self.line = line
        self.column = column
        super().__init__(f"Lexer Error at {line}:{column}: {message}")


class Lexer:
    def __init__(self, source: str):
        self.source = source
        self.pos = 0
        self.line = 1
        self.column = 1
        self.length = len(source)

    def _peek(self, offset: int = 0) -> Optional[str]:
        idx = self.pos + offset
        if idx < self.length:
            return self.source[idx]
        return None

    def _advance(self) -> Optional[str]:
        if self.pos >= self.length:
            return None
        char = self.source[self.pos]
        self.pos += 1
        if char == '\n':
            self.line += 1
            self.column = 1
        else:
            self.column += 1
        return char

    def tokenize(self) -> List[Token]:
        tokens: List[Token] = []

        while self.pos < self.length:
            char = self._peek()

            # Ignore horizontal whitespace
            if char in (' ', '\t', '\r'):
                self._advance()
                continue

            # Comments start with '#'
            if char == '#':
                while self._peek() is not None and self._peek() != '\n':
                    self._advance()
                continue

            # Newlines
            if char == '\n':
                token_line = self.line
                token_col = self.column
                self._advance()
                # Avoid producing duplicate consecutive NEWLINE tokens
                if tokens and tokens[-1].type != TokenType.NEWLINE:
                    tokens.append(Token(TokenType.NEWLINE, "\n", token_line, token_col))
                continue

            # String literals
            if char == '"':
                tokens.append(self._read_string())
                continue

            # Identifiers and Keywords
            if char.isalpha() or char == '_':
                tokens.append(self._read_identifier_or_keyword())
                continue

            # Unrecognized character
            token_line = self.line
            token_col = self.column
            bad_char = self._advance()
            raise LexerError(f"Unexpected character: {bad_char!r}", token_line, token_col)

        # Ensure trailing newline if tokens exist and last wasn't newline
        if tokens and tokens[-1].type != TokenType.NEWLINE:
            tokens.append(Token(TokenType.NEWLINE, "\n", self.line, self.column))

        # Always append EOF
        tokens.append(Token(TokenType.EOF, "", self.line, self.column))
        return tokens

    def _read_string(self) -> Token:
        start_line = self.line
        start_col = self.column
        self._advance()  # consume opening quote
        chars = []

        while self.pos < self.length:
            char = self._peek()
            if char is None or char == '\n':
                raise LexerError("Unterminated string literal", start_line, start_col)
            if char == '"':
                self._advance()  # consume closing quote
                return Token(TokenType.STRING, "".join(chars), start_line, start_col)
            if char == '\\':
                self._advance()
                escaped = self._advance()
                if escaped == 'n':
                    chars.append('\n')
                elif escaped == 't':
                    chars.append('\t')
                elif escaped == '"':
                    chars.append('"')
                elif escaped == '\\':
                    chars.append('\\')
                elif escaped is not None:
                    chars.append(escaped)
                else:
                    raise LexerError("Unterminated escape sequence in string", start_line, start_col)
            else:
                chars.append(self._advance())

        raise LexerError("Unterminated string literal", start_line, start_col)

    def _read_identifier_or_keyword(self) -> Token:
        start_line = self.line
        start_col = self.column
        chars = []

        while self.pos < self.length:
            char = self._peek()
            if char is not None and (char.isalnum() or char == '_'):
                chars.append(self._advance())
            else:
                break

        val = "".join(chars)
        upper_val = val.upper()

        if upper_val in KEYWORDS:
            return Token(KEYWORDS[upper_val], upper_val, start_line, start_col)
        else:
            return Token(TokenType.IDENTIFIER, val, start_line, start_col)
