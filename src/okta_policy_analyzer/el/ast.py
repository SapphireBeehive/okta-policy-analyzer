"""AST for Okta Expression Language (a SpEL subset).

Every node prints itself back with :meth:`Expr.source` such that ``parse(e.source()) == e``; the printed form is
also the canonical key under which uninterpreted fragments are shared between the SMT encoder and the reference
interpreter.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Expr:
    def source(self) -> str:  # pragma: no cover - overridden
        raise NotImplementedError


def _quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _postfix_target(e: Expr) -> str:
    """Source of ``e`` in a position where a postfix operator (``.x``, ``[i]``) follows.

    Binary, ternary and Elvis nodes already print parenthesised; unary operators and negative numbers would
    otherwise re-parse with the postfix bound to their operand.
    """
    if isinstance(e, UnaryOp):
        return f"({e.source()})"
    if isinstance(e, Literal) and isinstance(e.value, int | float) and not isinstance(e.value, bool):
        if e.value < 0:
            return f"({e.source()})"
    return e.source()


@dataclass(frozen=True)
class Literal(Expr):
    value: str | int | float | bool | None

    def source(self) -> str:
        v = self.value
        if isinstance(v, bool):
            return "true" if v else "false"
        if v is None:
            return "null"
        if isinstance(v, str):
            return _quote(v)
        return repr(v)


@dataclass(frozen=True)
class Attr(Expr):
    """A dotted reference such as ``user.department`` or ``user.profile.title``."""

    path: tuple[str, ...]

    def source(self) -> str:
        return ".".join(self.path)

    @property
    def normalized(self) -> str:
        """``user.profile.x`` and ``user.x`` denote the same profile attribute."""
        p = list(self.path)
        if len(p) >= 3 and p[0] == "user" and p[1] == "profile":
            p = ["user", *p[2:]]
        return ".".join(p)


@dataclass(frozen=True)
class ArrayLit(Expr):
    """Inline list/set ``{1, 2, 3}``; ``{}`` is the empty collection."""

    items: tuple[Expr, ...] = field(default_factory=tuple)

    def source(self) -> str:
        return "{" + ", ".join(i.source() for i in self.items) + "}"


@dataclass(frozen=True)
class MapLit(Expr):
    """Inline map ``{'group.id': {'a', 'b'}, 'operator': 'EXACT'}``; keys are strings (quoted or identifiers)."""

    entries: tuple[tuple[str, Expr], ...] = field(default_factory=tuple)

    def source(self) -> str:
        if not self.entries:
            return "{:}"
        return "{" + ", ".join(f"{_quote(k)}: {v.source()}" for k, v in self.entries) + "}"

    def get(self, key: str) -> Expr | None:
        for k, v in self.entries:
            if k == key:
                return v
        return None


@dataclass(frozen=True)
class Call(Expr):
    """Static function call; ``name`` is the dotted function name, e.g. ``String.stringContains``."""

    name: str
    args: tuple[Expr, ...]

    def source(self) -> str:
        return f"{self.name}({', '.join(a.source() for a in self.args)})"


@dataclass(frozen=True)
class MethodCall(Expr):
    """Method call on a value: ``user.profile.email.toLowerCase()``, ``user.isMemberOf({...})``."""

    target: Expr
    name: str
    args: tuple[Expr, ...] = field(default_factory=tuple)

    def source(self) -> str:
        return f"{_postfix_target(self.target)}.{self.name}({', '.join(a.source() for a in self.args)})"


@dataclass(frozen=True)
class Property(Expr):
    """Property access on a non-identifier target: ``user.getLinkedObject("manager").lastName``.

    Property access on identifiers folds into :class:`Attr`; this node only appears on other targets.
    """

    target: Expr
    name: str

    def source(self) -> str:
        return f"{_postfix_target(self.target)}.{self.name}"


@dataclass(frozen=True)
class Index(Expr):
    """Indexer ``arr[0]``."""

    target: Expr
    index: Expr

    def source(self) -> str:
        return f"{_postfix_target(self.target)}[{self.index.source()}]"


@dataclass(frozen=True)
class Projection(Expr):
    """SpEL collection projection ``user.getGroups(...).![profile.name]``."""

    target: Expr
    body: Expr

    def source(self) -> str:
        return f"{_postfix_target(self.target)}.![{self.body.source()}]"


@dataclass(frozen=True)
class UnaryOp(Expr):
    op: str  # "!", "-" or "+"
    operand: Expr

    def source(self) -> str:
        return f"{self.op}({self.operand.source()})"


@dataclass(frozen=True)
class BinOp(Expr):
    op: str  # && || == != < <= > >= matches + - * / %
    left: Expr
    right: Expr

    def source(self) -> str:
        return f"({self.left.source()} {self.op} {self.right.source()})"


@dataclass(frozen=True)
class Ternary(Expr):
    cond: Expr
    then: Expr
    other: Expr

    def source(self) -> str:
        return f"({self.cond.source()} ? {self.then.source()} : {self.other.source()})"


@dataclass(frozen=True)
class Elvis(Expr):
    """``a ?: b`` — ``a`` unless it is null or the empty string, else ``b``."""

    left: Expr
    right: Expr

    def source(self) -> str:
        return f"({self.left.source()} ?: {self.right.source()})"
