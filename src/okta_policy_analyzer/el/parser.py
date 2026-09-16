"""Tokenizer and recursive-descent parser for Okta Expression Language (both dialects).

The parser accepts the whole SpEL-derived grammar Okta documents, so that every real tenant expression parses
and can be printed, hashed and reported; a separate interpretation pass (``smt.el_encoder`` / ``interpreter``)
decides which sub-terms get exact semantics and which become opaque atoms.

Grammar (EBNF; precedence lowest to highest)::

    expr       := ternary
    ternary    := or ( "?" ternary ":" ternary | "?:" ternary )?           (* ternary / Elvis *)
    or         := and ( ("||" | OR) and )*
    and        := eq ( ("&&" | AND) eq )*
    eq         := rel ( ("==" | "!=" | EQ | NE) rel )*
    rel        := add ( ("<" | "<=" | ">" | ">=" | LT | LE | GT | GE | MATCHES) add )*
    add        := mul ( ("+" | "-") mul )*
    mul        := unary ( ("*" | "/" | "%") unary )*
    unary      := ("!" | NOT | "-" | "+") unary | postfix
    postfix    := primary ( "." IDENT ( "(" args ")" )? | "[" expr "]" | ".![" expr "]" )*
    primary    := literal | collection | "(" expr ")" | IDENT ( "(" args ")" )?
    collection := "{" "}" | "{" ":" "}" | "{" expr ( "," expr )* "}" | "{" entry ( "," entry )* "}"
    entry      := ( STRING | IDENT ) ":" expr
    args       := ( expr ( "," expr )* )?
    literal    := STRING | NUMBER | "true" | "false" | "null"

Keywords (``and or not eq ne lt gt le ge matches true false null``) are case-insensitive. ``!``/``not`` bind
like SpEL's unary operators (tighter than relational operators). Strings use single or double quotes; an
embedded quote is doubled (SpEL) or backslash-escaped; other backslashes are kept verbatim so regexes survive.

Shapes produced: a dotted identifier chain is one :class:`Attr`; ``Namespace.fn(...)`` with an upper-case first
segment (``String``, ``Arrays``, ``Convert``, ``Time``, ...) is a static :class:`Call`; any other call with a
receiver is a :class:`MethodCall`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .ast import (
    ArrayLit,
    Attr,
    BinOp,
    Call,
    Elvis,
    Expr,
    Index,
    Literal,
    MapLit,
    MethodCall,
    Projection,
    Property,
    Ternary,
    UnaryOp,
)


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
  | (?P<string>"(?:""|\\.|[^"\\])*"|'(?:''|\\.|[^'\\])*')
  | (?P<number>\d+(?:\.\d+)?)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op>\.!\[|==|!=|<=|>=|&&|\|\||\?:|[!<>?:(){},.+\-*/%\[\]])
    """,
    re.VERBOSE,
)

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "'": "'", "\\": "\\"}

_TEXT_EQ = {"EQ": "==", "NE": "!="}
_TEXT_REL = {"LT": "<", "GT": ">", "LE": "<=", "GE": ">=", "MATCHES": "matches"}


def _unescape(s: str) -> str:
    quote = s[0]
    body = s[1:-1]
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == quote and i + 1 < len(body) and body[i + 1] == quote:
            out.append(quote)  # SpEL doubled quote
            i += 2
        elif ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt in _ESCAPES:
                out.append(_ESCAPES[nxt])
            else:
                out.append(ch + nxt)  # unknown escape (e.g. regex ``\d``): keep verbatim
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


def is_static_namespace(path: tuple[str, ...]) -> bool:
    """``String``, ``Arrays``, ``Convert``, ``Time``, ``Iso3166Convert``, ``Groups``... — static function namespaces."""
    return bool(path) and path[0][:1].isupper()


class _Parser:
    def __init__(self, text: str):
        self.text = text
        self.toks = tokenize(text)
        self.i = 0

    # -- helpers ------------------------------------------------------------
    @property
    def cur(self) -> Token:
        return self.toks[self.i]

    def _peek(self, n: int = 1) -> Token:
        return self.toks[min(self.i + n, len(self.toks) - 1)]

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

    def _error(self, what: str) -> ELSyntaxError:
        return ELSyntaxError(f"{what} at {self.cur.pos} in {self.text!r}")

    # -- grammar ------------------------------------------------------------
    def parse(self) -> Expr:
        e = self.ternary()
        if self.cur.kind != "EOF":
            raise self._error(f"unexpected token {self.cur.value!r}")
        return e

    def ternary(self) -> Expr:
        c = self.or_()
        if self._is_op("?:"):
            self._advance()
            return Elvis(c, self.ternary())
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
        while True:
            if self._is_op("==", "!="):
                op = self._advance().value
            elif self._is_kw(*_TEXT_EQ):
                op = _TEXT_EQ[self._advance().value.upper()]
            else:
                return e
            e = BinOp(op, e, self.rel())

    def rel(self) -> Expr:
        e = self.add()
        while True:
            if self._is_op("<", "<=", ">", ">="):
                op = self._advance().value
            elif self._is_kw(*_TEXT_REL):
                op = _TEXT_REL[self._advance().value.upper()]
            else:
                return e
            e = BinOp(op, e, self.add())

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
        if self._is_op("-", "+"):
            op = self._advance().value
            return UnaryOp(op, self.unary())
        return self.postfix()

    def postfix(self) -> Expr:
        e = self.primary()
        while True:
            if self._is_op("."):
                self._advance()
                if self.cur.kind != "IDENT":
                    raise self._error("expected identifier after '.'")
                name = self._advance().value
                if self._is_op("("):
                    args = self.arguments()
                    if isinstance(e, Attr) and is_static_namespace(e.path):
                        e = Call(".".join((*e.path, name)), args)
                    else:
                        e = MethodCall(e, name, args)
                elif isinstance(e, Attr):
                    e = Attr((*e.path, name))
                else:
                    e = Property(e, name)
            elif self._is_op("["):
                self._advance()
                idx = self.ternary()
                self._expect_op("]")
                e = Index(e, idx)
            elif self._is_op(".!["):
                self._advance()
                body = self.ternary()
                self._expect_op("]")
                e = Projection(e, body)
            else:
                return e

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
            return self.collection()
        if t.kind == "IDENT":
            low = t.value.lower()
            if low in ("true", "false"):
                self._advance()
                return Literal(low == "true")
            if low == "null":
                self._advance()
                return Literal(None)
            self._advance()
            if self._is_op("("):
                return Call(t.value, self.arguments())
            return Attr((t.value,))
        raise self._error(f"unexpected token {t.value!r}")

    def arguments(self) -> tuple[Expr, ...]:
        self._expect_op("(")
        args: list[Expr] = []
        if not self._is_op(")"):
            args.append(self.ternary())
            while self._is_op(","):
                self._advance()
                args.append(self.ternary())
        self._expect_op(")")
        return tuple(args)

    def collection(self) -> Expr:
        self._expect_op("{")
        if self._is_op("}"):
            self._advance()
            return ArrayLit(())
        if self._is_op(":"):
            self._advance()
            self._expect_op("}")
            return MapLit(())
        if self.cur.kind in ("STRING", "IDENT") and self._peek().kind == "OP" and self._peek().value == ":":
            entries: list[tuple[str, Expr]] = [self._map_entry()]
            while self._is_op(","):
                self._advance()
                entries.append(self._map_entry())
            self._expect_op("}")
            return MapLit(tuple(entries))
        items: list[Expr] = [self.ternary()]
        while self._is_op(","):
            self._advance()
            items.append(self.ternary())
        self._expect_op("}")
        return ArrayLit(tuple(items))

    def _map_entry(self) -> tuple[str, Expr]:
        t = self.cur
        if t.kind == "STRING":
            key = _unescape(t.value)
        elif t.kind == "IDENT":
            key = t.value
        else:
            raise self._error("expected a map key (string or identifier)")
        self._advance()
        self._expect_op(":")
        return key, self.ternary()


def parse(text: str) -> Expr:
    """Parse an Okta EL expression. Raises :class:`ELSyntaxError` on malformed input."""
    if not text or not text.strip():
        raise ELSyntaxError("empty expression")
    return _Parser(text).parse()
