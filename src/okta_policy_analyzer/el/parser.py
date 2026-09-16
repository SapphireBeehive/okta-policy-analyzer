"""Tokenizer and recursive-descent parser for the Okta EL Boolean subset.

Grammar (EBNF)::

    expr      := ternary
    ternary   := or ( "?" ternary ":" ternary )?
    or        := and ( ("||" | OR) and )*
    and       := eq ( ("&&" | AND) eq )*
    eq        := rel ( ("==" | "!=") rel )*
    rel       := add ( ("<" | "<=" | ">" | ">=") add )*
    add       := mul ( ("+" | "-") mul )*
    mul       := unary ( ("*" | "/" | "%") unary )*
    unary     := ("!" | NOT | "-") unary | primary
    primary   := literal | array | "(" expr ")" | name ( "(" args ")" )?
    name      := IDENT ( "." IDENT )*
    array     := "{" ( expr ( "," expr )* )? "}"
    args      := ( expr ( "," expr )* )?
    literal   := STRING | NUMBER | "true" | "false" | "null"

``AND``/``OR``/``NOT`` keywords (SpEL style, case-insensitive) are accepted as synonyms of ``&&``/``||``/``!``.
Strings use double or single quotes with backslash escapes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .ast import ArrayLit, Attr, BinOp, Call, Expr, Literal, Ternary, UnaryOp


class ELSyntaxError(ValueError):
    pass


@dataclass(frozen=True)
class Token:
    kind: str  # STRING NUMBER IDENT OP EOF
    value: str
    pos: int


_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
  | (?P<number>\d+(?:\.\d+)?)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op>==|!=|<=|>=|&&|\|\||[!<>?:(){},.+\-*/%\[\]])
    """,
    re.VERBOSE,
)

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "'": "'", "\\": "\\"}


def _unescape(s: str) -> str:
    body = s[1:-1]
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            out.append(_ESCAPES.get(body[i + 1], body[i + 1]))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise ELSyntaxError(f"unexpected character {text[pos]!r} at {pos}")
        kind = m.lastgroup
        assert kind is not None
        if kind != "ws":
            tokens.append(Token(kind.upper(), m.group(kind), pos))
        pos = m.end()
    tokens.append(Token("EOF", "", len(text)))
    return tokens


class _Parser:
    def __init__(self, text: str):
        self.text = text
        self.toks = tokenize(text)
        self.i = 0

    # -- helpers ------------------------------------------------------------
    @property
    def cur(self) -> Token:
        return self.toks[self.i]

    def _advance(self) -> Token:
        t = self.toks[self.i]
        self.i += 1
        return t

    def _is_op(self, *ops: str) -> bool:
        return self.cur.kind == "OP" and self.cur.value in ops

    def _is_kw(self, *kws: str) -> bool:
        return self.cur.kind == "IDENT" and self.cur.value.upper() in kws

    def _expect_op(self, op: str) -> None:
        if not self._is_op(op):
            raise ELSyntaxError(f"expected {op!r} at {self.cur.pos} in {self.text!r}, got {self.cur.value!r}")
        self._advance()

    # -- grammar ------------------------------------------------------------
    def parse(self) -> Expr:
        e = self.ternary()
        if self.cur.kind != "EOF":
            raise ELSyntaxError(f"unexpected token {self.cur.value!r} at {self.cur.pos} in {self.text!r}")
        return e

    def ternary(self) -> Expr:
        c = self.or_()
        if self._is_op("?"):
            self._advance()
            t = self.ternary()
            self._expect_op(":")
            o = self.ternary()
            return Ternary(c, t, o)
        return c

    def or_(self) -> Expr:
        e = self.and_()
        while self._is_op("||") or self._is_kw("OR"):
            self._advance()
            e = BinOp("||", e, self.and_())
        return e

    def and_(self) -> Expr:
        e = self.eq()
        while self._is_op("&&") or self._is_kw("AND"):
            self._advance()
            e = BinOp("&&", e, self.eq())
        return e

    def eq(self) -> Expr:
        e = self.rel()
        while self._is_op("==", "!="):
            op = self._advance().value
            e = BinOp(op, e, self.rel())
        return e

    def rel(self) -> Expr:
        e = self.add()
        while self._is_op("<", "<=", ">", ">="):
            op = self._advance().value
            e = BinOp(op, e, self.add())
        return e

    def add(self) -> Expr:
        e = self.mul()
        while self._is_op("+", "-"):
            op = self._advance().value
            e = BinOp(op, e, self.mul())
        return e

    def mul(self) -> Expr:
        e = self.unary()
        while self._is_op("*", "/", "%"):
            op = self._advance().value
            e = BinOp(op, e, self.unary())
        return e

    def unary(self) -> Expr:
        if self._is_op("!") or self._is_kw("NOT"):
            self._advance()
            return UnaryOp("!", self.unary())
        if self._is_op("-"):
            self._advance()
            return UnaryOp("-", self.unary())
        return self.primary()

    def primary(self) -> Expr:
        t = self.cur
        if t.kind == "STRING":
            self._advance()
            return Literal(_unescape(t.value))
        if t.kind == "NUMBER":
            self._advance()
            return Literal(float(t.value) if "." in t.value else int(t.value))
        if self._is_op("("):
            self._advance()
            e = self.ternary()
            self._expect_op(")")
            return e
        if self._is_op("{"):
            return self.array()
        if t.kind == "IDENT":
            low = t.value.lower()
            if low in ("true", "false"):
                self._advance()
                return Literal(low == "true")
            if low == "null":
                self._advance()
                return Literal(None)
            return self.name_or_call()
        raise ELSyntaxError(f"unexpected token {t.value!r} at {t.pos} in {self.text!r}")

    def array(self) -> Expr:
        self._expect_op("{")
        items: list[Expr] = []
        if not self._is_op("}"):
            items.append(self.ternary())
            while self._is_op(","):
                self._advance()
                items.append(self.ternary())
        self._expect_op("}")
        return ArrayLit(tuple(items))

    def name_or_call(self) -> Expr:
        parts = [self._advance().value]
        while self._is_op("."):
            self._advance()
            if self.cur.kind != "IDENT":
                raise ELSyntaxError(f"expected identifier after '.' at {self.cur.pos} in {self.text!r}")
            parts.append(self._advance().value)
        if self._is_op("("):
            self._advance()
            args: list[Expr] = []
            if not self._is_op(")"):
                args.append(self.ternary())
                while self._is_op(","):
                    self._advance()
                    args.append(self.ternary())
            self._expect_op(")")
            return Call(".".join(parts), tuple(args))
        if self._is_op("["):
            raise ELSyntaxError(f"indexing is not supported at {self.cur.pos} in {self.text!r}")
        return Attr(tuple(parts))


def parse(text: str) -> Expr:
    """Parse an Okta EL expression. Raises :class:`ELSyntaxError` on unsupported syntax."""
    if not text or not text.strip():
        raise ELSyntaxError("empty expression")
    return _Parser(text).parse()
