"""Translate an Okta EL AST into a z3 Boolean over the Universe's variables.

Interpreted precisely:
    ``user.<attr> == literal`` / ``!=`` (strings, numbers, booleans, null), ``&&``, ``||``, ``!``, ternary,
    ``isMemberOfGroup``, ``isMemberOfAnyGroup``, ``isMemberOfAllGroups``, ``isMemberOfGroupName``,
    ``isMemberOfGroupNameStartsWith`` / ``Contains`` / ``Regex`` (resolved against the snapshot's group names),
    and string predicates ``String.stringContains`` / ``startsWith`` / ``endsWith`` / ``toLowerCase(...) ==``
    on a profile attribute against a literal (linked to the attribute's other literal values).

Everything else becomes an *opaque* free Boolean named after its source text — a sound over-approximation
(the analyses report "possible if <fragment>" rather than dropping the condition).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import z3

from ..el.ast import Attr, BinOp, Call, Expr, Literal, Ternary, UnaryOp

if TYPE_CHECKING:
    from .universe import Universe


class ELEncoder:
    def __init__(self, universe: Universe):
        self.u = universe

    # ------------------------------------------------------------------------------ entry
    def encode_bool(self, expr: Expr) -> z3.BoolRef:
        result = self._bool(expr)
        return result if result is not None else self.u.opaque(expr.source())

    # ------------------------------------------------------------------------------ helpers
    def _bool(self, e: Expr) -> z3.BoolRef | None:
        if isinstance(e, Literal):
            if isinstance(e.value, bool):
                return z3.BoolVal(e.value)
            return None
        if isinstance(e, UnaryOp) and e.op == "!":
            inner = self._bool(e.operand)
            return z3.Not(inner) if inner is not None else z3.Not(self.u.opaque(e.operand.source()))
        if isinstance(e, BinOp):
            if e.op in ("&&", "||"):
                left = self._bool(e.left)
                right = self._bool(e.right)
                left = left if left is not None else self.u.opaque(e.left.source())
                right = right if right is not None else self.u.opaque(e.right.source())
                return z3.And(left, right) if e.op == "&&" else z3.Or(left, right)
            if e.op in ("==", "!="):
                eq = self._equality(e.left, e.right)
                if eq is None:
                    eq = self._equality(e.right, e.left)
                if eq is None:
                    return None
                return eq if e.op == "==" else z3.Not(eq)
            return None  # arithmetic comparisons on attributes are opaque
        if isinstance(e, Ternary):
            c = self._bool(e.cond)
            t = self._bool(e.then)
            o = self._bool(e.other)
            if c is None or t is None or o is None:
                return None
            return z3.If(c, t, o)
        if isinstance(e, Call):
            return self._call(e)
        if isinstance(e, Attr):
            # a bare boolean attribute: user.contractor
            if e.path[0] == "user":
                return self.u.attr_equals(e.normalized, True)
            return None
        return None

    def _equality(self, left: Expr, right: Expr) -> z3.BoolRef | None:
        """left == right where left is an attribute (or string function of one) and right a literal."""
        if not isinstance(right, Literal):
            return None
        lit = right.value
        if isinstance(left, Attr) and left.path[0] == "user":
            return self.u.attr_equals(left.normalized, lit)
        if (
            isinstance(left, Call)
            and left.name in ("String.toLowerCase", "String.toUpperCase")
            and len(left.args) == 1
        ):
            arg = left.args[0]
            if isinstance(arg, Attr) and arg.path[0] == "user" and isinstance(lit, str):
                fn = str.lower if left.name.endswith("LowerCase") else str.upper
                return self.u.predicate(
                    left.name,
                    arg.normalized,
                    lit,
                    lambda v, fn=fn, lit=lit: v is not None and fn(str(v)) == lit,
                )
        if isinstance(left, Call) and self._bool_call_name(left):
            b = self._call(left)
            if b is not None and isinstance(lit, bool):
                return b if lit else z3.Not(b)
        return None

    @staticmethod
    def _bool_call_name(c: Call) -> bool:
        return c.name.startswith("isMemberOf") or c.name in (
            "String.stringContains",
            "String.startsWith",
            "String.endsWith",
            "Arrays.contains",
            "Arrays.isEmpty",
        )

    def _call(self, c: Call) -> z3.BoolRef | None:
        u = self.u
        t = u.tenant
        name = c.name
        if name == "isMemberOfGroup" and len(c.args) == 1 and isinstance(c.args[0], Literal):
            return self._member(str(c.args[0].value))
        if name in ("isMemberOfAnyGroup", "isMemberOfAllGroups") and len(c.args) == 1:
            ids = _literal_list(c.args[0])
            if ids is None:
                return None
            parts = [self._member(str(i)) for i in ids]
            if not parts:
                return z3.BoolVal(False)
            return z3.Or(*parts) if name == "isMemberOfAnyGroup" else z3.And(*parts)
        if name == "isMemberOfGroupName" and len(c.args) == 1 and isinstance(c.args[0], Literal):
            matches = [g.id for g in t.groups.values() if g.name == str(c.args[0].value)]
            return self._any_member(matches)
        if (
            name
            in ("isMemberOfGroupNameStartsWith", "isMemberOfGroupNameContains", "isMemberOfGroupNameRegex")
            and len(c.args) == 1
            and isinstance(c.args[0], Literal)
        ):
            needle = str(c.args[0].value)
            if name.endswith("StartsWith"):
                matches = [g.id for g in t.groups.values() if g.name.startswith(needle)]
            elif name.endswith("Contains"):
                matches = [g.id for g in t.groups.values() if needle in g.name]
            else:
                try:
                    rx = re.compile(needle)
                except re.error:
                    return None
                matches = [g.id for g in t.groups.values() if rx.search(g.name)]
            return self._any_member(matches)
        if name in ("String.stringContains", "String.startsWith", "String.endsWith") and len(c.args) == 2:
            a, b = c.args
            if (
                isinstance(a, Attr)
                and a.path[0] == "user"
                and isinstance(b, Literal)
                and isinstance(b.value, str)
            ):
                lit = b.value
                if name == "String.stringContains":
                    truth = lambda v, lit=lit: v is not None and lit in str(v)  # noqa: E731
                elif name == "String.startsWith":
                    truth = lambda v, lit=lit: v is not None and str(v).startswith(lit)  # noqa: E731
                else:
                    truth = lambda v, lit=lit: v is not None and str(v).endswith(lit)  # noqa: E731
                return u.predicate(name, a.normalized, lit, truth)
            return None
        if name == "Arrays.contains" and len(c.args) == 2:
            a, b = c.args
            if isinstance(a, Attr) and a.path[0] == "user" and isinstance(b, Literal):
                lit = b.value
                return u.predicate(
                    name, a.normalized, lit, lambda v, lit=lit: isinstance(v, list | tuple) and lit in v
                )
            return None
        if name == "Arrays.isEmpty" and len(c.args) == 1:
            a = c.args[0]
            if isinstance(a, Attr) and a.path[0] == "user":
                return u.predicate(
                    name,
                    a.normalized,
                    None,
                    lambda v: v is None or (isinstance(v, list | tuple) and len(v) == 0),
                )
            return None
        return None

    def _member(self, gid: str) -> z3.BoolRef:
        u = self.u
        if gid not in u.member:
            # a group referenced only inside an expression: register it as an empty (deleted) group
            u.group_ids.append(gid)
            u.member[gid] = z3.Bool(f"member[{gid}]")
            if gid not in u.tenant.groups:
                u._axioms.append(z3.Not(u.member[gid]))
        return u.member[gid]

    def _any_member(self, ids: list[str]) -> z3.BoolRef:
        if not ids:
            return z3.BoolVal(False)
        return z3.Or(*[self._member(i) for i in ids]) if len(ids) > 1 else self._member(ids[0])


def _literal_list(e: Expr) -> list[Any] | None:
    from ..el.ast import ArrayLit

    if isinstance(e, ArrayLit) and all(isinstance(i, Literal) for i in e.items):
        return [i.value for i in e.items]  # type: ignore[union-attr]
    if isinstance(e, Literal):
        return [e.value]
    return None
