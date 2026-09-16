"""Okta Expression Language (EL) support: parser, AST, concrete evaluator and atom extraction.

Okta EL is a SpEL-derived expression language used in group rules (``conditions.expression.value``) and
in Identity Engine authentication-policy custom conditions (``conditions.elCondition.condition``).
We support the Boolean subset that matters for policy analysis; everything else is preserved as an
opaque sub-expression that the formal model treats as a free (uninterpreted) predicate.
"""

from .ast import (
    ArrayLit,
    Attr,
    BinOp,
    Call,
    Expr,
    Literal,
    Ternary,
    UnaryOp,
)
from .evaluator import EvalError, Unknown, evaluate
from .parser import ELSyntaxError, parse

__all__ = [
    "ArrayLit",
    "Attr",
    "BinOp",
    "Call",
    "ELSyntaxError",
    "EvalError",
    "Expr",
    "Literal",
    "Ternary",
    "UnaryOp",
    "Unknown",
    "evaluate",
    "parse",
]
