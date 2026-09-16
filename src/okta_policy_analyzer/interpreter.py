"""Reference interpreter: evaluate policies for ONE concrete world (user + request context).

This is the executable specification of the semantics the SMT encoder must agree with. It is deliberately
simple and direct (no solver). It powers the ``explain`` command and the differential tests, which sample
worlds and check that the rule the interpreter picks is exactly the rule whose effective-match formula the
encoder makes true.

The world carries the truth value of every *opaque* expression fragment explicitly, so that the interpreter
and the encoder treat uninterpretable expressions identically.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .el.ast import ArrayLit, Attr, BinOp, Call, Elvis, Expr, Literal, MethodCall, Ternary, UnaryOp
from .el.evaluator import (
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
from .model import (
    DevicePlatform,
    PlatformSpec,
    Policy,
    RiskLevel,
    Rule,
    RuleConditions,
    Status,
    Tenant,
)

MOBILE = {DevicePlatform.ANDROID, DevicePlatform.IOS}
DESKTOP = {DevicePlatform.MACOS, DevicePlatform.WINDOWS, DevicePlatform.CHROMEOS, DevicePlatform.LINUX}
_OS_TO_PLATFORM = {
    "IOS": DevicePlatform.IOS,
    "ANDROID": DevicePlatform.ANDROID,
    "OSX": DevicePlatform.MACOS,
    "MACOS": DevicePlatform.MACOS,
    "WINDOWS": DevicePlatform.WINDOWS,
    "CHROMEOS": DevicePlatform.CHROMEOS,
    "LINUX": DevicePlatform.LINUX,
    "OTHER": DevicePlatform.OTHER,
}


@dataclass
class World:
    groups: set[str] = field(default_factory=set)  # group ids the user belongs to (Everyone implied)
    user_id: str | None = None  # the specific user, if any rule names them
    user_type: str | None = None  # user type id
    attrs: dict[str, Any] = field(default_factory=dict)  # normalised attribute path -> value
    zones: set[str] = field(default_factory=set)  # zone ids the request IP is inside
    registered: bool = False
    managed: bool = False
    platform: DevicePlatform = DevicePlatform.OTHER
    assurances: set[str] = field(default_factory=set)  # device assurance policy ids satisfied
    risk: RiskLevel = RiskLevel.LOW
    auth_type: str = "WEB"  # WEB | LDAP_INTERFACE | RADIUS
    idp: str = "OKTA"  # OKTA | idp id | OTHER
    opaque: dict[str, bool] = field(
        default_factory=dict
    )  # truth of uninterpretable fragments (by source text)
    predicates: dict[str, bool] = field(
        default_factory=dict
    )  # truth of string predicates when attr is "other"

    def in_group(self, gid: str, tenant: Tenant) -> bool:
        if gid == tenant.everyone_group_id:
            return True
        return gid in self.groups


class Interpreter:
    def __init__(self, tenant: Tenant):
        self.t = tenant
        self._names = {g.id: g.name for g in tenant.groups.values()}

    # ------------------------------------------------------------------------------ rules
    def rule_matches(self, rule: Rule, w: World) -> bool:
        return self.conditions_match(rule.conditions, w)

    def conditions_match(self, c: RuleConditions, w: World) -> bool:  # noqa: C901 - direct transcription
        t = self.t
        if c.people:
            p = c.people
            if p.groups_include or p.users_include:
                inc = any(w.in_group(g, t) for g in p.groups_include) or (
                    w.user_id is not None and w.user_id in p.users_include
                )
                if not inc:
                    return False
            if any(w.in_group(g, t) for g in p.groups_exclude):
                return False
            if w.user_id is not None and w.user_id in p.users_exclude:
                return False
        if c.network:
            n = c.network
            if n.include and not any(z in w.zones for z in n.include):
                return False
            if n.exclude and any(z in w.zones for z in n.exclude):
                return False
        if c.device:
            d = c.device
            if d.registered is not None and w.registered != d.registered:
                return False
            if d.managed is not None and w.managed != d.managed:
                return False
            if d.assurance_include and not any(a in w.assurances for a in d.assurance_include):
                return False
            if d.platform_types and w.platform not in d.platform_types:
                return False
        if c.platform:
            if c.platform.include and not any(self._platform_spec(s, w) for s in c.platform.include):
                return False
            if any(self._platform_spec(s, w) for s in c.platform.exclude):
                return False
        if c.risk_level is not None and w.risk != c.risk_level:
            return False
        if c.user_type:
            if c.user_type.include and w.user_type not in c.user_type.include:
                return False
            if w.user_type is not None and w.user_type in c.user_type.exclude:
                return False
        if c.el:
            if c.el.ast is None:
                if not w.opaque.get(c.el.text, False):
                    return False
            elif not self.eval_bool(c.el.ast, w):
                return False
        if c.behaviors and not any(w.opaque.get(f"behavior {b} detected", False) for b in c.behaviors):
            return False
        if c.auth_type and w.auth_type != c.auth_type:
            return False
        if c.idp:
            if c.idp.provider == "OKTA" and w.idp != "OKTA":
                return False
            if c.idp.provider == "SPECIFIC_IDP" and w.idp not in c.idp.idp_ids:
                return False
        return True

    def _platform_spec(self, s: PlatformSpec, w: World) -> bool:
        t = (s.type or "ANY").upper()
        if t == "MOBILE" and w.platform not in MOBILE:
            return False
        if t == "DESKTOP" and w.platform not in DESKTOP:
            return False
        if t == "OTHER" and w.platform != DevicePlatform.OTHER:
            return False
        if s.os_type and s.os_type.upper() != "ANY":
            mapped = _OS_TO_PLATFORM.get(s.os_type.upper())
            if mapped is not None and w.platform != mapped:
                return False
        if s.os_expression and not w.opaque.get(f"os version {s.os_expression}", False):
            return False
        return True

    # ------------------------------------------------------------------------------ policies
    def first_matching_rule(self, policy: Policy, w: World) -> Rule | None:
        for r in policy.active_rules():
            if self.rule_matches(r, w):
                return r
        return None

    def policy_applies(self, policy: Policy, w: World) -> bool:
        if policy.group_include:
            return any(w.in_group(g, self.t) for g in policy.group_include)
        return policy.system

    def select(self, policies: list[Policy], w: World) -> tuple[Policy, Rule] | None:
        """Priority-ordered selection with fall-through when a policy has no matching rule."""
        for pol in policies:
            if not pol.is_active or not self.policy_applies(pol, w):
                continue
            r = self.first_matching_rule(pol, w)
            if r is not None:
                return pol, r
        return None

    # ------------------------------------------------------------------------------ EL (mirrors ELEncoder)
    def eval_bool(self, e: Expr, w: World) -> bool:
        r = self._bool(e, w)
        return r if r is not None else w.opaque.get(e.source(), False)

    def _bool_or_opaque(self, e: Expr, w: World) -> bool:
        b = self._bool(e, w)
        return b if b is not None else w.opaque.get(e.source(), False)

    def _bool(self, e: Expr, w: World) -> bool | None:  # noqa: C901
        if isinstance(e, Literal):
            return e.value if isinstance(e.value, bool) else None
        if isinstance(e, UnaryOp) and e.op == "!":
            return not self._bool_or_opaque(e.operand, w)
        if isinstance(e, BinOp):
            if e.op in ("&&", "||"):
                lft = self._bool_or_opaque(e.left, w)
                rgt = self._bool_or_opaque(e.right, w)
                return (lft and rgt) if e.op == "&&" else (lft or rgt)
            cc = count_comparison(e)
            if cc is not None:
                return self._count_compare(*cc, w)
            if e.op in ("==", "!="):
                eq = self._equality(e.left, e.right, w)
                if eq is None:
                    eq = self._equality(e.right, e.left, w)
                if eq is None and bool_typed(e.left) and bool_typed(e.right):
                    eq = self._bool_or_opaque(e.left, w) == self._bool_or_opaque(e.right, w)
                if eq is None:
                    return None
                return eq if e.op == "==" else not eq
            if e.op == "matches":
                return self._predicate_atom(e, w)
            return None
        if isinstance(e, Ternary):
            c = self._bool(e.cond, w)
            t = self._bool(e.then, w)
            o = self._bool(e.other, w)
            if c is None or t is None or o is None:
                return None
            return t if c else o
        if isinstance(e, Elvis):
            return self._elvis(e, w)
        if isinstance(e, Call | MethodCall):
            return self._call(e, w)
        if isinstance(e, Attr):
            kind = context_bool(e)
            if kind is not None:
                return self._context(kind, True, w)
            if e.path[0] == "user" and len(e.path) > 1:
                return w.attrs.get(e.normalized) is True
            return None
        return None

    def _elvis(self, e: Elvis, w: World) -> bool | None:
        if isinstance(e.left, Attr) and e.left.path[0] == "user" and len(e.left.path) > 1:
            right = self._bool(e.right, w)
            if right is None:
                return None
            v = w.attrs.get(e.left.normalized)
            return right if v is None else v is True
        if bool_typed(e.left) and bool_typed(e.right):
            return self._bool_or_opaque(e.left, w)
        return None

    def _equality(self, left: Expr, right: Expr, w: World) -> bool | None:
        if not isinstance(right, Literal):
            return None
        lit = right.value
        if isinstance(left, Attr):
            ctx = context_equality(left, lit)
            if ctx is not None:
                return self._context(*ctx, w)
            if left.path[0] == "user" and len(left.path) > 1:
                return w.attrs.get(left.normalized) == lit
            return None
        term = string_term(left)
        if term is not None:
            if not term.transforms:
                return w.attrs.get(term.path) == lit
            if isinstance(lit, str):
                pa = equality_predicate(term, lit)
                return self._predicate(pa.function, pa.path, pa.literal, pa.truth, w)
            return None
        if isinstance(lit, bool) and bool_typed(left):
            b = self._bool_or_opaque(left, w)
            return b if lit else not b
        return None

    def _context(self, kind: str, value: Any, w: World) -> bool | None:
        if kind == "risk":
            return w.risk.value == value
        if kind == "managed":
            return w.managed == value
        if kind == "registered":
            return w.registered == value
        if kind == "platform":
            return w.platform == DevicePlatform(value)
        return None

    def _predicate(self, function: str, path: str, literal: Any, truth, w: World) -> bool:  # noqa: ANN001
        name = f"pred:{function}({path},{literal!r})"
        if path in w.attrs and w.attrs[path] != "<other>":
            try:
                return bool(truth(w.attrs[path]))
            except Exception:  # noqa: BLE001
                return w.predicates.get(name, False)
        return w.predicates.get(name, False)

    def _predicate_atom(self, e: Expr, w: World) -> bool | None:
        pa = predicate_atom(e)
        if pa is None:
            return None
        return self._predicate(pa.function, pa.path, pa.literal, pa.truth, w)

    def _call(self, c: Call | MethodCall, w: World) -> bool | None:
        ma = membership_atom(c)
        if ma is not None:
            criteria, negated = ma
            d = any(w.in_group(g, self.t) for g in self.matching_groups(criteria))
            return not d if negated else d
        p = self._predicate_atom(c, w)
        if p is not None:
            return p
        if isinstance(c, Call):
            return self._static_group_call(c, w)
        return None

    def _static_group_call(self, c: Call, w: World) -> bool | None:
        t = self.t
        name = c.name
        if name == "isMemberOfGroup" and len(c.args) == 1 and isinstance(c.args[0], Literal):
            return w.in_group(str(c.args[0].value), t)
        if name in ("isMemberOfAnyGroup", "isMemberOfAllGroups") and len(c.args) == 1:
            ids = _literal_list(c.args[0])
            if ids is None:
                return None
            vals = [w.in_group(str(i), t) for i in ids]
            return any(vals) if name == "isMemberOfAnyGroup" else all(vals)
        if name == "isMemberOfGroupName" and len(c.args) == 1 and isinstance(c.args[0], Literal):
            return any(w.in_group(g.id, t) for g in t.groups.values() if g.name == str(c.args[0].value))
        if (
            name
            in ("isMemberOfGroupNameStartsWith", "isMemberOfGroupNameContains", "isMemberOfGroupNameRegex")
            and len(c.args) == 1
            and isinstance(c.args[0], Literal)
        ):
            needle = str(c.args[0].value)
            if name.endswith("StartsWith"):
                ids = [g.id for g in t.groups.values() if g.name.startswith(needle)]
            elif name.endswith("Contains"):
                ids = [g.id for g in t.groups.values() if needle in g.name]
            else:
                try:
                    rx = re.compile(needle)
                except re.error:
                    return None
                ids = [g.id for g in t.groups.values() if rx.search(g.name)]
            return any(w.in_group(i, t) for i in ids)
        return None

    def matching_groups(self, criteria: Criteria) -> list[str]:
        """Snapshot groups satisfying every criterion (closed world) — same resolution as the encoder."""
        return [g.id for g in self.t.groups.values() if group_satisfies(criteria, g.id, g.name, g.type)]

    def _count_compare(self, criteria: Criteria, op: str, n: int, w: World) -> bool:
        count = sum(1 for g in self.matching_groups(criteria) if w.in_group(g, self.t))
        return {
            ">": count > n,
            ">=": count >= n,
            "<": count < n,
            "<=": count <= n,
            "==": count == n,
            "!=": count != n,
        }[op]


def _literal_list(e: Expr) -> list[Any] | None:
    if isinstance(e, ArrayLit) and all(isinstance(i, Literal) for i in e.items):
        return [i.value for i in e.items]  # type: ignore[union-attr]
    if isinstance(e, Literal):
        return [e.value]
    return None


def world_from_user(tenant: Tenant, user_id: str, **context: Any) -> World:
    """Build a World for a concrete user from the snapshot (requires ``--with-users`` data)."""
    for u in tenant.users:
        if u.id == user_id or u.login == user_id:
            attrs = {f"user.{k}": v for k, v in u.profile.items()}
            w = World(groups=set(u.group_ids), user_id=u.id, user_type=u.user_type_id, attrs=attrs)
            for k, v in context.items():
                setattr(w, k, v)
            return w
    raise KeyError(f"user {user_id} not in snapshot")


def active_group_rule_closure(tenant: Tenant, w: World) -> set[str]:
    """Groups the active group rules would add for this world (one round; Okta rules do not chain)."""
    from .el.evaluator import Env, Unknown, evaluate

    added: set[str] = set()
    names = frozenset(tenant.group_name(g) for g in w.groups)
    env = Env(
        attrs=w.attrs,
        group_ids=frozenset(w.groups),
        group_names=names,
        groups=[
            (g, tenant.group_name(g), tenant.groups[g].type if g in tenant.groups else "OKTA_GROUP")
            for g in w.groups
        ],
    )
    for gr in tenant.group_rules:
        if gr.status != Status.ACTIVE or gr.expr_ast is None:
            continue
        if w.user_id and w.user_id in gr.exclude_user_ids:
            continue
        if any(g in w.groups for g in gr.exclude_group_ids):
            continue
        try:
            if evaluate(gr.expr_ast, env) is True:
                added.update(gr.target_group_ids)
        except Unknown:
            continue
    return added
