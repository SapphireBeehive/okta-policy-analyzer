"""TLA+ export: the same policy semantics as a TLC-checkable specification.

For one authentication policy (plus the global session policies) we emit a module whose ``Init`` picks a user
record and a context record non-deterministically from finite domains, asserts the domain axioms, and whose
``Next`` stutters. Every property is an invariant over that single state, so TLC's counterexample is a
concrete witness world — the TLA+ counterpart of the z3 witness.

The operators are produced by *translating the z3 formulas* the analyzer already uses (rule matches, axioms),
so the two backends cannot drift apart. The state space is the product of the finite domains of the variables
the policy references (groups, zones, device assurance, platform, risk, ...); it is sliced to those variables
and reported in the module header. TLA+ is a secondary backend: for large tenants the product explodes and
the z3 analyses remain the primary tool.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import z3

from .analysis import Analyzer
from .assertions import Assertion
from .assurance import Strength, classify_rule
from .model import Access, Policy, SignOnAction
from .smt.dnf import var_names
from .smt.universe import AUTH_TYPES, PLATFORMS, RISKS, Universe

_ID_RE = re.compile(r"[^A-Za-z0-9_]")


def tla_ident(s: str) -> str:
    s = _ID_RE.sub("_", s)
    if not s or not s[0].isalpha():
        s = "M_" + s
    return s


def tla_str(s: str) -> str:
    return '"' + s.replace('"', "'") + '"'


@dataclass
class TLAExport:
    module_name: str
    tla: str
    cfg: str
    estimated_states: int
    invariants: list[str] = field(default_factory=list)
    reachability_probes: dict[str, str] = field(default_factory=dict)  # invariant name -> rule name

    def write(self, directory: str | Path) -> tuple[Path, Path]:
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        tla = d / f"{self.module_name}.tla"
        cfg = d / f"{self.module_name}.cfg"
        tla.write_text(self.tla)
        cfg.write_text(self.cfg)
        return tla, cfg


class TLAExporter:
    def __init__(self, analyzer: Analyzer):
        self.an = analyzer
        self.u: Universe = analyzer.u
        self.t = analyzer.t

    # ------------------------------------------------------------------------------ slicing
    def _slice(self, formulas: list[z3.BoolRef]) -> tuple[set[str], list[z3.BoolRef], dict[str, bool]]:
        """Variables referenced by the formulas, closed under axioms that share a variable.

        Returns the variable names to keep, the axioms to emit, and Boolean variables that unit axioms force to
        a constant (these are substituted and dropped from the state space). Axioms that pin a specific user's
        memberships are only pulled in when the policy's own formulas mention that user (otherwise they would
        drag every group of the tenant into the state space).
        """
        direct: set[str] = set()
        for f in formulas:
            direct |= var_names(f)
        names = set(direct)
        axioms = self.an.axioms
        ax_names = [var_names(a) for a in axioms]
        constants: dict[str, bool] = {}
        for a in axioms:
            lit = _unit_literal(a)
            if lit is not None:
                constants[lit[0]] = lit[1]
        kept: set[int] = set()
        changed = True
        while changed:
            changed = False
            for i, an_ in enumerate(ax_names):
                if (
                    i in kept
                    or not an_
                    or _is_domain_bound(axioms[i])
                    or _unit_literal(axioms[i]) is not None
                ):
                    continue
                if not an_ & names:
                    continue
                if _is_pinned_user_axiom(axioms[i]) and not any(
                    n.startswith("user_is[") and n in direct for n in an_
                ):
                    continue
                kept.add(i)
                if not an_ <= names:
                    names |= an_
                    changed = True
        names -= set(constants)
        return names, [axioms[i] for i in sorted(kept)], constants

    # ------------------------------------------------------------------------------ export
    def export_policy(
        self, policy: Policy, assertions: list[Assertion] | None = None, module_name: str | None = None
    ) -> TLAExport:
        u = self.u
        ep = self.an.enc.access_policy(policy)
        session = self.an.enc.session_policies
        formulas = (
            list(ep.match) + [sep.applies for sep in session] + [m for sep in session for m in sep.match]
        )
        names, axioms, constants = self._slice(formulas)
        mod = module_name or tla_ident(f"Policy_{policy.name}")
        groups = sorted(g for g in u.group_ids if g != u.everyone and f"member[{g}]" in names)
        zones = sorted(z for z in u.zone_ids if f"zone[{z}]" in names)
        assurances = sorted(d for d in u.assurance_ids if f"assurance[{d}]" in names)
        users = sorted(x for x in u.user_ids if f"user_is[{x}]" in names)
        attrs = sorted(p for p in u.attr_vars if f"attr:{p}" in names)
        preds = sorted(n for n in u.pred_vars if n in names)
        opaques = sorted(f"opaque:{k}" for k in u.opaque_vars if f"opaque:{k}" in names)
        use_platform = "dev_platform" in names or assurances != []
        use_risk = "risk" in names
        use_auth = "auth_type" in names
        use_idp = "idp" in names
        use_type = "user_type" in names
        use_dev = "dev_registered" in names or "dev_managed" in names or assurances != []
        # unused dimensions collapse to a single value; enum domains keep only the values the formulas mention (+ OTHER)
        mentioned = _mentioned_constants(formulas + axioms)
        platforms = (
            _enum_domain(
                [p.value for p in PLATFORMS],
                mentioned.get("dev_platform", set()),
                lambda k: PLATFORMS[k].value,
            )
            if use_platform
            else ["OTHER"]
        )
        user_types = (
            _enum_domain(
                [*u.user_type_ids, "OTHER"],
                mentioned.get("user_type", set()),
                lambda k: u.user_type_ids[k] if k < len(u.user_type_ids) else "OTHER",
            )
            if use_type
            else ["OTHER"]
        )
        idps = (
            _enum_domain(
                ["OKTA", *u.idp_ids, "OTHER"],
                mentioned.get("idp", set()),
                lambda k: "OKTA" if k == 0 else (u.idp_ids[k - 1] if k - 1 < len(u.idp_ids) else "OTHER"),
            )
            if use_idp
            else ["OKTA"]
        )
        risks = [r.value for r in RISKS] if use_risk else ["LOW"]
        auth_types = list(AUTH_TYPES) if use_auth else ["WEB"]
        attr_domains = {p: [_lit(x) for x in u.attr_literals[p]] + ["OTHER"] for p in attrs}

        est = 2 ** len(groups) * 2 ** len(zones) * 2 ** len(assurances) * (len(users) + 1)
        est *= len(user_types) * len(platforms) * len(risks) * len(auth_types) * len(idps)
        for p in attrs:
            est *= len(attr_domains[p])
        est *= 2 ** len(preds) * 2 ** len(opaques)
        if use_dev:
            est *= 4

        tr = _Translator(u, set(names), constants)
        lines: list[str] = []
        w = lines.append
        w(f"---------------------------- MODULE {mod} ----------------------------")
        w(
            f"\\* Generated by okta-policy-analyzer from policy {policy.name!r} ({policy.id}) of {self.t.org_url}"
        )
        w(f"\\* Apps: {', '.join(self.t.app_label(a) for a in policy.app_ids) or '(none)'}")
        w(
            f"\\* Sliced state space: ~{est:,} worlds (groups={len(groups)}, zones={len(zones)}, assurance={len(assurances)}, attrs={len(attrs)}, opaque={len(opaques)})"
        )
        w("\\* Check with:  java -cp tla2tools.jar tlc2.TLC -workers auto " + mod)
        w("EXTENDS Naturals, FiniteSets")
        w("")
        w("Groups == " + _set(groups))
        w("Zones == " + _set(zones))
        w("Assurances == " + _set(assurances))
        w("UserIds == " + _set([*users, "NONE"]))
        w("UserTypes == " + _set(user_types))
        w("Platforms == " + _set(platforms))
        w("Risks == " + _set(risks))
        w("AuthTypes == " + _set(auth_types))
        w("Idps == " + _set(idps))
        w("Preds == " + _set(preds))
        w("Opaques == " + _set(opaques))
        for p in attrs:
            w(f"Dom_{tla_ident(p)} == " + _set(attr_domains[p]))
        w("")
        w("VARIABLES user, ctx")
        w("vars == <<user, ctx>>")
        w("")
        attr_fields = "".join(f", attr_{tla_ident(p)}: Dom_{tla_ident(p)}" for p in attrs)
        w(
            f"UserRecords == [groups: SUBSET Groups, id: UserIds, type: UserTypes, pred: [Preds -> BOOLEAN]{attr_fields}]"
        )
        dev_dom = "BOOLEAN" if use_dev else "{FALSE}"
        w(
            f"CtxRecords == [zones: SUBSET Zones, registered: {dev_dom}, managed: {dev_dom}, platform: Platforms, assurances: SUBSET Assurances,"
        )
        w("               risk: Risks, authType: AuthTypes, idp: Idps, opaque: [Opaques -> BOOLEAN]]")
        if constants:
            w(
                "\\* Variables forced to a constant by unit axioms were substituted: "
                + ", ".join(f"{k}={v}" for k, v in sorted(constants.items()))
            )
        w("")
        w("\\* Domain axioms (translated from the analyzer's z3 encoding)")
        ax_lines = [tr.expr(a) for a in axioms]
        ax_lines = [a for a in ax_lines if a != "TRUE"]
        if ax_lines:
            w("Axioms ==")
            for a in ax_lines:
                w(f"    /\\ {a}")
        else:
            w("Axioms == TRUE")
        w("")
        w("\\* Authentication policy rules in evaluation order (first match decides)")
        rule_names = []
        for i, rule in enumerate(ep.rules):
            name = f"Match_{i}"
            rule_names.append(name)
            w(f"\\* rule {rule.priority}: {rule.name}")
            w(f"{name} == {tr.expr(ep.match[i])}")
        w("")
        w("Decision ==")
        for i, rule in enumerate(ep.rules):
            kw = "IF" if i == 0 else "ELSE IF"
            w(f"    {kw} Match_{i} THEN {tla_str(rule.id)}")
        w('    ELSE "NO_MATCH"')
        w("")
        w("\\* Strength class of the decision (weakest accepted authentication path)")
        w("Strength ==")
        w("    CASE")
        cases = []
        for rule in ep.rules:
            ra = classify_rule(rule, self.an.catalogue)
            label = Strength.DENY.name if ra.access == Access.DENY else ra.weakest.name
            cases.append(f"Decision = {tla_str(rule.id)} -> {tla_str(label)}")
        cases.append(f'Decision = "NO_MATCH" -> {tla_str(Strength.DENY.name)}')
        w("      " + "\n      [] ".join(cases))
        w("")
        w("Allowed == Strength /= " + tla_str(Strength.DENY.name))
        w("")
        # session policies
        w("\\* Global session policies: first policy that applies AND has a matching rule decides")
        sess_decisions = []
        for pi, sep in enumerate(session):
            w(f"\\* session policy {sep.policy.priority}: {sep.policy.name}")
            w(f"SApplies_{pi} == {tr.expr(sep.applies)}")
            for ri in range(len(sep.rules)):
                w(f"SMatch_{pi}_{ri} == {tr.expr(sep.match[ri])}")
            any_match = " \\/ ".join(f"SMatch_{pi}_{ri}" for ri in range(len(sep.rules))) or "FALSE"
            w(f"SDecides_{pi} == SApplies_{pi} /\\ ({any_match})")
            sess_decisions.append(pi)
        w("SessionDecision ==")
        for pi in sess_decisions:
            sep = session[pi]
            for ri, rule in enumerate(sep.rules):
                cond = " /\\ ".join(
                    [
                        f"SDecides_{pi}",
                        *[f"~SDecides_{q}" for q in range(pi)],
                        *[f"~SMatch_{pi}_{r2}" for r2 in range(ri)],
                        f"SMatch_{pi}_{ri}",
                    ]
                )
                kw = "IF" if (pi == 0 and ri == 0) else "ELSE IF"
                w(f"    {kw} {cond} THEN {tla_str(rule.id)}")
        w('    ELSE "NO_SESSION"')
        w("SessionDenied ==")
        denies = [
            tla_str(r.id)
            for sep in session
            for r in sep.rules
            if isinstance(r.action, SignOnAction) and r.action.access == Access.DENY
        ]
        w("    SessionDecision \\in " + _set_raw([*denies, '"NO_SESSION"']))
        w("")
        w("Init ==")
        w("    /\\ user \\in UserRecords")
        w("    /\\ ctx \\in CtxRecords")
        w("    /\\ Axioms")
        w("Next == UNCHANGED vars")
        w("Spec == Init /\\ [][Next]_vars")
        w("")
        w("\\* ---- Properties -------------------------------------------------------------------")
        invariants: list[str] = []
        probes: dict[str, str] = {}
        w("\\* Sanity: exactly one rule decides (the catch-all guarantees a decision)")
        w('SomeRuleDecides == Decision /= "NO_MATCH"')
        invariants.append("SomeRuleDecides")
        w("\\* Reachability probes: TLC reports a violation (with a witness world) iff the rule is reachable")
        for i, rule in enumerate(ep.rules):
            name = f"Unreachable_{i}"
            w(f"{name} == Decision /= {tla_str(rule.id)}")
            probes[name] = rule.name
        for a in assertions or []:
            try:
                inv_name, text = self._assertion_invariant(a, tr)
            except ValueError as e:
                w(f"\\* assertion {a.name!r} not exportable: {e}")
                continue
            w(f"\\* assertion: {a.name} — {a.description}")
            w(f"{inv_name} == {text}")
            invariants.append(inv_name)
        w("")
        w("=============================================================================")
        cfg = "\n".join(
            [
                "SPECIFICATION Spec",
                "CHECK_DEADLOCK FALSE",
                "INVARIANTS",
                *[f"    {n}" for n in invariants],
                "",
            ]
        )
        return TLAExport(mod, "\n".join(lines) + "\n", cfg, est, invariants, probes)

    def _assertion_invariant(self, a: Assertion, tr: _Translator) -> tuple[str, str]:
        checker_premise = self._premise_tla(a.when, tr)
        e = a.expect
        conds: list[str] = []
        if "access" in e:
            conds.append("Allowed" if str(e["access"]).upper() == "ALLOW" else "~Allowed")
        if "min_strength" in e:
            ok = [s.name for s in Strength if s >= Strength[str(e["min_strength"])]] + [Strength.DENY.name]
            conds.append("Strength \\in " + _set(ok))
        if "max_strength" in e:
            ok = [s.name for s in Strength if s <= Strength[str(e["max_strength"])]]
            conds.append("Strength \\in " + _set(ok))
        if "rules_any" in e:
            ids = (
                [r.id for r in self.t.policy_rules(e["rules_any"])] if hasattr(self.t, "policy_rules") else []
            )
            names = set(e["rules_any"])
            ids = [r.id for p in self.t.access_policies for r in p.rules if r.name in names or r.id in names]
            conds.append("Decision \\in " + _set(ids))
        if "rules_none" in e:
            names = set(e["rules_none"])
            ids = [r.id for p in self.t.access_policies for r in p.rules if r.name in names or r.id in names]
            conds.append("Decision \\notin " + _set(ids))
        if not conds:
            raise ValueError("expectation has no exportable clause")
        if a.with_session_policy:
            raise ValueError("with_session_policy assertions are not exported")
        body = " /\\ ".join(conds)
        return f"Assert_{tla_ident(a.name)}", f"({checker_premise}) => ({body})"

    def _premise_tla(self, when: dict, tr: _Translator) -> str:  # noqa: C901
        parts: list[str] = []
        t = self.t

        def gid(name: str) -> str:
            if name in t.groups:
                return name
            for g in t.groups.values():
                if g.name == name:
                    return g.id
            raise ValueError(f"unknown group {name!r}")

        def zid(name: str) -> str:
            if name in t.zones:
                return name
            for z in t.zones.values():
                if z.name == name:
                    return z.id
            raise ValueError(f"unknown zone {name!r}")

        for key, value in when.items():
            if key == "groups_any":
                parts.append("(" + " \\/ ".join(tr.member(gid(g)) for g in value) + ")")
            elif key == "groups_all":
                parts.extend(tr.member(gid(g)) for g in value)
            elif key == "groups_none":
                parts.extend(f"~{tr.member(gid(g))}" for g in value)
            elif key == "zones_any":
                parts.append("(" + " \\/ ".join(f"{tla_str(zid(z))} \\in ctx.zones" for z in value) + ")")
            elif key == "zones_none":
                parts.extend(f"{tla_str(zid(z))} \\notin ctx.zones" for z in value)
            elif key == "registered":
                parts.append("ctx.registered" if value else "~ctx.registered")
            elif key == "managed":
                parts.append("ctx.managed" if value else "~ctx.managed")
            elif key == "risk":
                levels = value if isinstance(value, list) else [value]
                parts.append("ctx.risk \\in " + _set([str(x).upper() for x in levels]))
            elif key == "platforms_any":
                parts.append("ctx.platform \\in " + _set([str(x).upper() for x in value]))
            elif key == "assurance_any":
                ids = [
                    d
                    if d in t.device_assurances
                    else next((x.id for x in t.device_assurances.values() if x.name == d), d)
                    for d in value
                ]
                parts.append("(" + " \\/ ".join(f"{tla_str(i)} \\in ctx.assurances" for i in ids) + ")")
            else:
                raise ValueError(f"premise clause {key!r} not exportable")
        return " /\\ ".join(parts) if parts else "TRUE"


# ------------------------------------------------------------------------------------------ z3 -> TLA+


class _Translator:
    def __init__(self, u: Universe, names: set[str], constants: dict[str, bool] | None = None):
        self.u = u
        self.names = names
        self.constants = constants or {}

    def member(self, gid: str) -> str:
        if gid == self.u.everyone:
            return "TRUE"
        return f"{tla_str(gid)} \\in user.groups"

    def expr(self, e: z3.ExprRef) -> str:  # noqa: C901
        if z3.is_true(e):
            return "TRUE"
        if z3.is_false(e):
            return "FALSE"
        if z3.is_const(e) and e.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            return self._var(e.decl().name())
        d = e.decl().kind()
        ch = (
            [self.expr(c) for c in e.children()]
            if d not in (z3.Z3_OP_EQ, z3.Z3_OP_DISTINCT, z3.Z3_OP_LE, z3.Z3_OP_GE, z3.Z3_OP_LT, z3.Z3_OP_GT)
            else []
        )
        if d == z3.Z3_OP_AND:
            return "(" + " /\\ ".join(ch) + ")" if ch else "TRUE"
        if d == z3.Z3_OP_OR:
            return "(" + " \\/ ".join(ch) + ")" if ch else "FALSE"
        if d == z3.Z3_OP_NOT:
            return f"~{ch[0]}"
        if d == z3.Z3_OP_IMPLIES:
            return f"({ch[0]} => {ch[1]})"
        if d == z3.Z3_OP_IFF:
            return f"({ch[0]} <=> {ch[1]})"
        if d == z3.Z3_OP_ITE:
            return f"(IF {ch[0]} THEN {ch[1]} ELSE {ch[2]})"
        if d == z3.Z3_OP_XOR:
            return f"({ch[0]} /= {ch[1]})"
        if d == z3.Z3_OP_PB_AT_MOST or d == z3.Z3_OP_PB_LE:
            return "TRUE"  # at-most-one specific user: guaranteed by the single-valued user.id field
        if d in (z3.Z3_OP_EQ, z3.Z3_OP_DISTINCT):
            a, b = e.children()
            if z3.is_bool(a):
                s = f"({self.expr(a)} <=> {self.expr(b)})"
                return s if d == z3.Z3_OP_EQ else f"~{s}"
            s = self._int_eq(a, b)
            return s if d == z3.Z3_OP_EQ else f"~{s}"
        if d in (z3.Z3_OP_LE, z3.Z3_OP_GE, z3.Z3_OP_LT, z3.Z3_OP_GT):
            return "TRUE"  # domain bounds are enforced by the finite record domains
        raise ValueError(f"cannot translate z3 node {e.decl().name()} ({e})")

    def _int_eq(self, a: z3.ExprRef, b: z3.ExprRef) -> str:
        if z3.is_int_value(a):
            a, b = b, a
        if not (z3.is_const(a) and z3.is_int_value(b)):
            raise ValueError(f"unsupported integer comparison {a} == {b}")
        name = a.decl().name()
        k = b.as_long()
        u = self.u
        if name == "user_type":
            label = u.user_type_ids[k] if k < len(u.user_type_ids) else "OTHER"
            return f"user.type = {tla_str(label)}"
        if name == "dev_platform":
            return f"ctx.platform = {tla_str(PLATFORMS[k].value)}"
        if name == "risk":
            return f"ctx.risk = {tla_str(RISKS[k].value)}"
        if name == "auth_type":
            return f"ctx.authType = {tla_str(AUTH_TYPES[k])}"
        if name == "idp":
            label = "OKTA" if k == 0 else (u.idp_ids[k - 1] if k - 1 < len(u.idp_ids) else "OTHER")
            return f"ctx.idp = {tla_str(label)}"
        if name.startswith("attr:"):
            path = name[5:]
            lits = u.attr_literals[path]
            label = _lit(lits[k]) if k < len(lits) else "OTHER"
            return f"user.attr_{tla_ident(path)} = {tla_str(label)}"
        raise ValueError(f"unknown integer variable {name}")

    def _var(self, name: str) -> str:
        if name in self.constants:
            return "TRUE" if self.constants[name] else "FALSE"
        if name.startswith("member["):
            return self.member(name[7:-1])
        if name.startswith("zone["):
            return f"{tla_str(name[5:-1])} \\in ctx.zones"
        if name.startswith("assurance["):
            return f"{tla_str(name[10:-1])} \\in ctx.assurances"
        if name.startswith("user_is["):
            return f"user.id = {tla_str(name[8:-1])}"
        if name == "dev_registered":
            return "ctx.registered"
        if name == "dev_managed":
            return "ctx.managed"
        if name.startswith("pred:"):
            return f"user.pred[{tla_str(name)}]"
        if name.startswith("opaque:"):
            return f"ctx.opaque[{tla_str(name)}]"
        raise ValueError(f"unknown variable {name}")


def _lit(x: object) -> str:
    from .smt.universe import NULL

    if x == NULL:
        return "NULL"
    if isinstance(x, bool):
        return "true" if x else "false"
    return str(x)


def _set(items: list[str]) -> str:
    return "{" + ", ".join(tla_str(i) for i in items) + "}"


def _set_raw(items: list[str]) -> str:
    return "{" + ", ".join(items) + "}"


def _unit_literal(a: z3.BoolRef) -> tuple[str, bool] | None:
    """``var`` or ``Not(var)`` for a Boolean variable."""
    if z3.is_const(a) and a.decl().kind() == z3.Z3_OP_UNINTERPRETED and z3.is_bool(a):
        return a.decl().name(), True
    if z3.is_not(a):
        c = a.children()[0]
        if z3.is_const(c) and c.decl().kind() == z3.Z3_OP_UNINTERPRETED and z3.is_bool(c):
            return c.decl().name(), False
    return None


def _is_pinned_user_axiom(a: z3.BoolRef) -> bool:
    """``user_is[u] => (member[g] == const)`` or ``user_is[u] => user_type == k``."""
    if not z3.is_implies(a):
        return False
    lhs = a.children()[0]
    return z3.is_const(lhs) and lhs.decl().name().startswith("user_is[")


def _mentioned_constants(formulas: list[z3.BoolRef]) -> dict[str, set[int]]:
    """Integer constants each enum variable is compared with (``var == k``) anywhere in the formulas."""
    out: dict[str, set[int]] = {}
    seen: set[int] = set()
    stack = list(formulas)
    while stack:
        e = stack.pop()
        if e.get_id() in seen:
            continue
        seen.add(e.get_id())
        if z3.is_eq(e):
            a, b = e.children()
            if z3.is_int_value(a):
                a, b = b, a
            if z3.is_const(a) and z3.is_int_value(b):
                out.setdefault(a.decl().name(), set()).add(b.as_long())
        if z3.is_app(e):
            stack.extend(e.children())
    return out


def _enum_domain(full: list[str], mentioned: set[int], label) -> list[str]:  # noqa: ANN001
    """Keep the mentioned enum values plus one representative for 'any other value'."""
    keep = [label(k) for k in sorted(mentioned) if k < len(full)]
    other = next((v for v in full if v not in keep), None)
    if other is not None:
        keep.append(other)
    return keep or full


def _is_domain_bound(a: z3.BoolRef) -> bool:
    """Axioms like 0 <= risk <= 2 are enforced by the finite domains in TLA+."""
    kinds = {z3.Z3_OP_LE, z3.Z3_OP_GE, z3.Z3_OP_LT, z3.Z3_OP_GT}
    if a.decl().kind() in kinds:
        return True
    if a.decl().kind() == z3.Z3_OP_AND and all(c.decl().kind() in kinds for c in a.children()):
        return True
    return False


# ------------------------------------------------------------------------------------------ TLC


@dataclass
class TLCResult:
    ok: bool
    violated: list[str]
    states: int | None
    output: str
    error: str | None = None
    witnesses: dict[str, str] = field(default_factory=dict)  # invariant -> violating state (TLA+ syntax)

    def witness_for(self, invariant: str) -> str | None:
        return self.witnesses.get(invariant)


def _tlc_cmd(jar: str | Path, cfg_name: str, module: str, workers: str) -> list[str]:
    return [
        "java",
        "-XX:+UseParallelGC",
        "-cp",
        str(jar),
        "tlc2.TLC",
        "-workers",
        workers,
        "-config",
        cfg_name,
        "-nowarning",
        "-noTE",
        module,
    ]


def _parse_tlc(out: str, returncode: int) -> TLCResult:
    violated = sorted(set(re.findall(r"Invariant (\w+) is violated", out)))
    constant_false = sorted(set(re.findall(r"The invariant of (\w+) is equal to FALSE", out)))
    witnesses: dict[str, str] = {}
    for m in re.finditer(
        r"Invariant (\w+) is violated by the initial state:\n(.*?)(?:\n\n|\nComputed|\Z)", out, re.S
    ):
        witnesses.setdefault(m.group(1), m.group(2).strip())
    for c in constant_false:
        witnesses.setdefault(c, "(violated in every world: the property is a constant FALSE)")
    violated = sorted(set(violated) | set(constant_false))
    m = re.search(r"(\d+) states generated, (\d+) distinct states found", out)
    states = int(m.group(2)) if m else None
    other_errors = [
        line
        for line in out.splitlines()
        if line.startswith("Error:") and "is violated" not in line and "is equal to FALSE" not in line
    ]
    err = (
        "\n".join(other_errors)[:2000]
        if other_errors
        else (None if (returncode == 0 or violated) else f"TLC exit code {returncode}")
    )
    return TLCResult(
        ok=not other_errors, violated=violated, states=states, output=out, error=err, witnesses=witnesses
    )


def run_tlc(
    tla_path: str | Path,
    jar: str | Path,
    *,
    workers: str = "auto",
    timeout: int = 600,
    invariants: list[str] | None = None,
) -> TLCResult:
    """Run TLC once on a module. With ``invariants`` a temporary .cfg with exactly those invariants is used.

    TLC stops at the first violated invariant, so a single run reports at most one violation (with its
    witness world). Use :func:`run_tlc_each` to get a verdict for every property.
    """
    tla_path = Path(tla_path)
    cfg_path = tla_path.with_suffix(".cfg")
    if invariants is not None:
        base = cfg_path.read_text().split("INVARIANTS")[0].rstrip("\n")
        cfg_path = tla_path.with_name(tla_path.stem + "_" + tla_ident("_".join(invariants))[:40] + ".cfg")
        cfg_path.write_text(base + "\nINVARIANTS\n" + "\n".join(f"    {i}" for i in invariants) + "\n")
    try:
        proc = subprocess.run(
            _tlc_cmd(jar, cfg_path.name, tla_path.name, workers),
            cwd=tla_path.parent,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return TLCResult(False, [], None, "", error="java not found")
    except subprocess.TimeoutExpired:
        return TLCResult(False, [], None, "", error=f"TLC timed out after {timeout}s")
    finally:
        if invariants is not None and cfg_path.exists():
            cfg_path.unlink()
    return _parse_tlc(proc.stdout + proc.stderr, proc.returncode)


def run_tlc_each(
    tla_path: str | Path,
    jar: str | Path,
    invariants: list[str],
    *,
    timeout: int = 600,
    parallel: int | None = None,
) -> dict[str, TLCResult]:
    """One TLC run per invariant (in parallel processes) so every property gets its own verdict and witness."""
    import os
    from concurrent.futures import ThreadPoolExecutor

    n = parallel or max(1, (os.cpu_count() or 2) // 2)
    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = {
            inv: pool.submit(run_tlc, tla_path, jar, workers="1", timeout=timeout, invariants=[inv])
            for inv in invariants
        }
        return {inv: f.result() for inv, f in futures.items()}
