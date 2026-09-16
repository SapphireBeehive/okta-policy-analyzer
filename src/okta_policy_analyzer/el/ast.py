"""AST for the supported Okta EL subset."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Expr:
    def source(self) -> str:  # pragma: no cover - overridden
        raise NotImplementedError


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
            return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
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
    items: tuple[Expr, ...] = field(default_factory=tuple)

    def source(self) -> str:
        return "{" + ", ".join(i.source() for i in self.items) + "}"


@dataclass(frozen=True)
class Call(Expr):
    """Function call; ``name`` is the dotted function name, e.g. ``String.stringContains``."""

    name: str
    args: tuple[Expr, ...]

    def source(self) -> str:
        return f"{self.name}({', '.join(a.source() for a in self.args)})"


@dataclass(frozen=True)
class UnaryOp(Expr):
    op: str  # "!" or "-"
    operand: Expr

    def source(self) -> str:
        return f"{self.op}({self.operand.source()})"


@dataclass(frozen=True)
class BinOp(Expr):
    op: str  # && || == != < <= > >= + - * / %
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
