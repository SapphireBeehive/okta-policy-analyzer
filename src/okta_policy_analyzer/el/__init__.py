"""Okta Expression Language (EL) support: parser, AST, concrete evaluator and atom recognisers.

Okta EL is a SpEL-derived expression language used in group rules (``conditions.expression.value``) and
in Identity Engine authentication-policy custom conditions (``conditions.elCondition.condition``).
The parser accepts the whole documented grammar; the evaluator interprets the documented function catalogue;
the recognisers in :mod:`.evaluator` classify the Boolean fragments that get exact semantics in the formal
model — everything else is preserved as an opaque sub-expression that the model treats as a free predicate.
"""

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
from .evaluator import Env, EvalError, GroupCriterion, Unknown, evaluate
from .parser import ELSyntaxError, parse

__all__ = [
    "ArrayLit",
    "Attr",
    "BinOp",
    "Call",
    "ELSyntaxError",
    "Elvis",
    "Env",
    "EvalError",
    "Expr",
    "GroupCriterion",
    "Index",
    "Literal",
    "MapLit",
    "MethodCall",
    "Projection",
    "Property",
    "Ternary",
    "UnaryOp",
    "Unknown",
    "evaluate",
    "parse",
]
