"""Translate an Okta EL AST into a z3 Boolean over the Universe's variables.

Interpretation policy (research report section 3.8). Exact atoms:

* ``user.<attr> == literal`` / ``!=`` (also ``user.profile.<attr>``, ``user.status``,
  ``user.getInternalProperty("status")``), bare Boolean attributes, ``&&``, ``||``, ``!``, ternary and Elvis with
  Boolean branches, ``==``/``!=`` between Booleans;
* classic group functions ``isMemberOfGroup`` / ``isMemberOfAnyGroup`` / ``isMemberOfAllGroups`` /
  ``isMemberOfGroupName`` / ``...StartsWith`` / ``...Contains`` / ``...Regex`` and Identity Engine
  ``user.isMemberOf({criteria})``, ``Arrays.isEmpty(user.getGroups(c))``, ``user.getGroups(c).size() > 0``,
  ``user.getGroups(c).![id].contains('00g…')`` — all resolved closed-world against the snapshot's groups into a
  disjunction of ``member[g]`` (a criteria set matching no existing group is ``false`` and recorded as an
  assumption);
* string predicates on a profile attribute against a literal: ``String.stringContains`` / ``startsWith`` /
  ``endsWith`` and the ``.contains()`` / ``.startsWith()`` / ``.endsWith()`` methods, ``toLowerCase``/``toUpperCase``
  (static or method form) compared with a literal, ``matches`` with a literal regex, ``Arrays.contains``,
  ``Arrays.isEmpty`` / ``.isEmpty()`` — as ``pred:`` variables linked to the attribute's literal values;
* context atoms sharing the structured-condition variables: ``security.risk.level == 'HIGH'``,
  ``device.profile.managed`` / ``registered`` (bare or ``== true/false``), ``device.profile.platform == 'MACOS'``.

Everything else becomes an *opaque* free Boolean named after its source text — a sound over-approximation
(the analyses report "possible if <fragment>" rather than dropping the condition). A non-Boolean opaque term
compared with a literal makes the whole comparison opaque.

``interpreter.Interpreter`` mirrors this module construct by construct (both use the recognisers in
``el.evaluator``); the differential tests check they agree.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import z3

from ..el.ast import ArrayLit, Attr, BinOp, Call, Elvis, Expr, Literal, MethodCall, Ternary, UnaryOp
from ..el.evaluator import (
    Criteria,
    bool_typed,
    context_bool,
    context_equality,
    count_comparison,
    equality_predicate,
    group_satisfies,
    membership_atom,
    predicate_atom,
    string_term,
)
from ..model import DevicePlatform, RiskLevel

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
    def _bool_or_opaque(self, e: Expr) -> z3.BoolRef:
        b = self._bool(e)
        return b if b is not None else self.u.opaque(e.source())

    def _bool(self, e: Expr) -> z3.BoolRef | None:  # noqa: C901 - flat dispatch
        if isinstance(e, Literal):
            if isinstance(e.value, bool):
                return z3.BoolVal(e.value)
            return None
        if isinstance(e, UnaryOp) and e.op == "!":
            return z3.Not(self._bool_or_opaque(e.operand))
        if isinstance(e, BinOp):
            if e.op in ("&&", "||"):
                left = self._bool_or_opaque(e.left)
                right = self._bool_or_opaque(e.right)
                return z3.And(left, right) if e.op == "&&" else z3.Or(left, right)
            cc = count_comparison(e)
            if cc is not None:
                return self._count_compare(*cc, e.source())
            if e.op in ("==", "!="):
                eq = self._equality(e.left, e.right)
                if eq is None:
                    eq = self._equality(e.right, e.left)
                if eq is None and bool_typed(e.left) and bool_typed(e.right):
                    eq = self._bool_or_opaque(e.left) == self._bool_or_opaque(e.right)
                if eq is None:
                    return None
                return eq if e.op == "==" else z3.Not(eq)
            if e.op == "matches":
                return self._predicate(e)
            return None  # arithmetic comparisons on attributes are opaque
        if isinstance(e, Ternary):
            c = self._bool(e.cond)
            t = self._bool(e.then)
            o = self._bool(e.other)
            if c is None or t is None or o is None:
                return None
            return z3.If(c, t, o)
        if isinstance(e, Elvis):
            return self._elvis(e)
        if isinstance(e, Call | MethodCall):
            return self._call(e)
        if isinstance(e, Attr):
            kind = context_bool(e)
            if kind is not None:
                return self._context(kind, True)
            if e.path[0] == "user" and len(e.path) > 1:
                # a bare boolean attribute: user.contractor
                return self.u.attr_equals(e.normalized, True)
            return None
        return None

    def _elvis(self, e: Elvis) -> z3.BoolRef | None:
        """``a ?: b`` with Boolean branches: a Boolean-typed ``a`` is never null so the result is ``a``; a bare
        attribute may be null, in which case ``b`` applies."""
        if isinstance(e.left, Attr) and e.left.path[0] == "user" and len(e.left.path) > 1:
            right = self._bool(e.right)
            if right is None:
                return None
            path = e.left.normalized
            return z3.If(self.u.attr_equals(path, None), right, self.u.attr_equals(path, True))
        if bool_typed(e.left) and bool_typed(e.right):
            return self._bool_or_opaque(e.left)
        return None

    def _equality(self, left: Expr, right: Expr) -> z3.BoolRef | None:
        """left == right where right is a literal and left an attribute, a string function of one, a context
        attribute or a Boolean-typed expression (against ``true``/``false``)."""
        if not isinstance(right, Literal):
            return None
        lit = right.value
        if isinstance(left, Attr):
            ctx = context_equality(left, lit)
            if ctx is not None:
                return self._context(*ctx)
            if left.path[0] == "user" and len(left.path) > 1:
                return self.u.attr_equals(left.normalized, lit)
            return None
        term = string_term(left)
        if term is not None:
            if not term.transforms:  # user.getInternalProperty("status")
                return self.u.attr_equals(term.path, lit)
            if isinstance(lit, str):
                pa = equality_predicate(term, lit)
                return self.u.predicate(pa.function, pa.path, pa.literal, pa.truth)
            return None
        if isinstance(lit, bool) and bool_typed(left):
            b = self._bool_or_opaque(left)
            return b if lit else z3.Not(b)
        return None

    def _context(self, kind: str, value: Any) -> z3.BoolRef | None:
        u = self.u
        if kind == "risk":
            levels = {r.value: r for r in RiskLevel}
            return u.risk_is(levels[value]) if value in levels else z3.BoolVal(False)
        if kind == "managed":
            return u.managed if value else z3.Not(u.managed)
        if kind == "registered":
            return u.registered if value else z3.Not(u.registered)
        if kind == "platform":
            return u.platform_is(DevicePlatform(value))
        return None

    def _predicate(self, e: Expr) -> z3.BoolRef | None:
        pa = predicate_atom(e)
        if pa is None:
            return None
        return self.u.predicate(pa.function, pa.path, pa.literal, pa.truth)

    def _call(self, c: Call | MethodCall) -> z3.BoolRef | None:
        ma = membership_atom(c)
        if ma is not None:
            criteria, negated = ma
            d = self._membership(criteria, c.source())
            return z3.Not(d) if negated else d
        p = self._predicate(c)
        if p is not None:
            return p
        if isinstance(c, Call):
            return self._static_group_call(c)
        return None

    def _static_group_call(self, c: Call) -> z3.BoolRef | None:
        t = self.u.tenant
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
        return None

    # ------------------------------------------------------------------------------ membership
    def matching_groups(self, criteria: Criteria) -> list[str]:
        """Snapshot groups satisfying every criterion (closed world), in snapshot order."""
        return [g.id for g in self.u.tenant.groups.values() if group_satisfies(criteria, g.id, g.name, g.type)]

    def _membership(self, criteria: Criteria, source: str) -> z3.BoolRef:
        ids = self.matching_groups(criteria)
        if not ids:
            self._note(f"closed world: {source} matches no existing group and is treated as false")
        return self._any_member(ids)

    def _count_compare(self, criteria: Criteria, op: str, n: int, source: str) -> z3.BoolRef:
        """``|{g matching criteria : member[g]}| op n`` as a cardinality constraint over the member variables."""
        ids = self.matching_groups(criteria)
        if not ids:
            self._note(f"closed world: {source} matches no existing group; the group count is always 0")
        members = [self._member(i) for i in ids]
        if op == ">":
            op, n = ">=", n + 1
        elif op == "<":
            op, n = "<=", n - 1
        if op == ">=":
            if n <= 0:
                return z3.BoolVal(True)
            if n == 1:
                return self._any_member(ids)
            return z3.AtLeast(*members, n) if len(members) >= n else z3.BoolVal(False)
        if op == "<=":
            if n < 0:
                return z3.BoolVal(False)
            if n == 0:
                return z3.Not(self._any_member(ids))
            return z3.AtMost(*members, n) if len(members) > n else z3.BoolVal(True)
        # == / !=
        if n < 0 or n > len(members):
            eq: z3.BoolRef = z3.BoolVal(False)
        elif n == 0:
            eq = z3.Not(self._any_member(ids))
        else:
            eq = z3.PbEq([(m, 1) for m in members], n)
        return eq if op == "==" else z3.Not(eq)

    def _note(self, text: str) -> None:
        if text not in self.u.assumptions:
            self.u.assumptions.append(text)

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
    if isinstance(e, ArrayLit) and all(isinstance(i, Literal) for i in e.items):
        return [i.value for i in e.items]  # type: ignore[union-attr]
    if isinstance(e, Literal):
        return [e.value]
    return None
