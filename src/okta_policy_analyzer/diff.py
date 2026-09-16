"""Formal diff of two snapshots: what changed in who can do what.

Both snapshots are encoded against ONE symbolic universe (the newer snapshot's inventory: groups, zones,
device assurance, authenticators, group rules), because Okta ids are stable and a "world" must mean the same
thing on both sides. Groups or zones that exist only in the old snapshot are treated as deleted (empty).
For every app present in both snapshots the outcome functions are compared:

    changed      := ∃ world. class_old(world) ≠ class_new(world)
    new_access   := ∃ world. allowed_new ∧ ¬allowed_old
    lost_access  := ∃ world. allowed_old ∧ ¬allowed_new
    weaker       := ∃ world. allowed_new ∧ allowed_old ∧ class_new < class_old
    stronger     := ∃ world. allowed_new ∧ allowed_old ∧ class_new > class_old

and summarised as EQUIVALENT, MORE_PERMISSIVE, LESS_PERMISSIVE or INCOMPARABLE, each with WHO/WHEN
descriptions and a witness. A structural diff (rules added / removed / reordered / edited) is attached.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any

import z3

from .analysis import AnalysisOptions, Analyzer
from .assurance import Catalogue, Strength, classify_rule
from .model import Access, Policy, Tenant
from .smt.encoder import EncodedPolicy, PolicyEncoder


@dataclass
class RuleChange:
    kind: str  # added | removed | edited | reordered
    rule: str
    detail: str = ""


@dataclass
class AppDiff:
    app: str
    old_policy: str
    new_policy: str
    verdict: str  # EQUIVALENT | MORE_PERMISSIVE | LESS_PERMISSIVE | INCOMPARABLE
    changed_who: list[str] = field(default_factory=list)
    changed_when: list[str] = field(default_factory=list)
    new_access: list[str] = field(default_factory=list)
    lost_access: list[str] = field(default_factory=list)
    weaker: list[str] = field(default_factory=list)
    stronger: list[str] = field(default_factory=list)
    witness_weaker: str | None = None
    witness_new_access: str | None = None
    old_weakest: str = ""
    new_weakest: str = ""
    rule_changes: list[RuleChange] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class DiffResult:
    old_fetched_at: str
    new_fetched_at: str
    apps: list[AppDiff]
    apps_added: list[str]
    apps_removed: list[str]
    assumptions: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "old_fetched_at": self.old_fetched_at,
            "new_fetched_at": self.new_fetched_at,
            "apps": [a.to_dict() for a in self.apps],
            "apps_added": self.apps_added,
            "apps_removed": self.apps_removed,
            "assumptions": self.assumptions,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @property
    def more_permissive(self) -> list[AppDiff]:
        return [a for a in self.apps if a.verdict in ("MORE_PERMISSIVE", "INCOMPARABLE")]


def _class_formulas(
    an: Analyzer, enc: PolicyEncoder, ep: EncodedPolicy, catalogue: Catalogue
) -> dict[Strength, z3.BoolRef]:
    """For each strength class, the formula 'this policy decides class c' (DENY includes no-match)."""
    by: dict[Strength, list[z3.BoolRef]] = {}
    for i, rule in enumerate(ep.rules):
        ra = classify_rule(rule, catalogue)
        c = ra.weakest if ra.access == Access.ALLOW else Strength.DENY
        by.setdefault(c, []).append(ep.effective[i])
    by.setdefault(Strength.DENY, []).append(ep.no_match)
    return {c: z3.Or(*fs) if len(fs) > 1 else fs[0] for c, fs in by.items()}


def diff_tenants(old: Tenant, new: Tenant, options: AnalysisOptions | None = None) -> DiffResult:
    an = Analyzer(new, options)  # universe + axioms from the NEW snapshot
    old_enc = PolicyEncoder(an.u)  # separate cache; same variables
    catalogue = an.catalogue
    old_policies = {p.id: p for p in old.access_policies}
    old_app_policy = {
        a.id: a.access_policy_id for a in old.apps.values() if a.access_policy_id in old_policies
    }
    new_app_policy = {
        a.id: a.access_policy_id
        for a in new.apps.values()
        if new.policy(a.access_policy_id or "") is not None
    }
    common = sorted(set(old_app_policy) & set(new_app_policy), key=lambda i: new.app_label(i))
    apps: list[AppDiff] = []
    for app_id in common:
        pol_old = old_policies[old_app_policy[app_id]]
        pol_new = new.policy(new_app_policy[app_id])
        assert pol_new is not None
        ep_old = old_enc.encode_policy(pol_old)
        ep_new = an.enc.access_policy(pol_new)
        apps.append(
            _diff_app(an, new.app_label(app_id), pol_old, pol_new, ep_old, ep_new, old_enc, catalogue)
        )
    assumptions = list(an.u.assumptions) + [
        "diff: both snapshots are evaluated in the newer snapshot's world (groups, zones, device assurance, authenticators, group rules)"
    ]
    return DiffResult(
        old_fetched_at=old.fetched_at,
        new_fetched_at=new.fetched_at,
        apps=apps,
        apps_added=sorted(new.app_label(i) for i in set(new_app_policy) - set(old_app_policy)),
        apps_removed=sorted(old.app_label(i) for i in set(old_app_policy) - set(new_app_policy)),
        assumptions=sorted(set(assumptions)),
    )


def _diff_app(
    an: Analyzer,
    label: str,
    pol_old: Policy,
    pol_new: Policy,
    ep_old: EncodedPolicy,
    ep_new: EncodedPolicy,
    old_enc: PolicyEncoder,
    catalogue: Catalogue,
) -> AppDiff:
    co = _class_formulas(an, old_enc, ep_old, catalogue)
    cn = _class_formulas(an, an.enc, ep_new, catalogue)
    classes = sorted(set(co) | set(cn))
    f_old = {c: co.get(c, z3.BoolVal(False)) for c in classes}
    f_new = {c: cn.get(c, z3.BoolVal(False)) for c in classes}
    allowed_old = (
        z3.Or(*[f_old[c] for c in classes if c > Strength.NO_PATH])
        if any(c > Strength.NO_PATH for c in classes)
        else z3.BoolVal(False)
    )
    allowed_new = (
        z3.Or(*[f_new[c] for c in classes if c > Strength.NO_PATH])
        if any(c > Strength.NO_PATH for c in classes)
        else z3.BoolVal(False)
    )
    changed = z3.Or(*[z3.Xor(f_old[c], f_new[c]) for c in classes])
    new_access = z3.And(allowed_new, z3.Not(allowed_old))
    lost_access = z3.And(allowed_old, z3.Not(allowed_new))
    weaker = (
        z3.Or(
            *[z3.And(f_new[a], f_old[b]) for a in classes for b in classes if a < b and a > Strength.NO_PATH]
        )
        if len(classes) > 1
        else z3.BoolVal(False)
    )
    stronger = (
        z3.Or(
            *[z3.And(f_new[a], f_old[b]) for a in classes for b in classes if a > b and b > Strength.NO_PATH]
        )
        if len(classes) > 1
        else z3.BoolVal(False)
    )
    d = AppDiff(app=label, old_policy=pol_old.name, new_policy=pol_new.name, verdict="EQUIVALENT")
    if not an.sat(changed):
        d.verdict = "EQUIVALENT"
    else:
        d.changed_who = an.lines(an.who(changed))
        d.changed_when = an.lines(an.when(changed))
        more = an.sat(z3.Or(new_access, weaker))
        less = an.sat(z3.Or(lost_access, stronger))
        d.verdict = (
            "INCOMPARABLE"
            if (more and less)
            else ("MORE_PERMISSIVE" if more else ("LESS_PERMISSIVE" if less else "EQUIVALENT"))
        )
        if an.sat(new_access):
            d.new_access = an.lines(an.who(new_access))
            d.witness_new_access = an.witness_text(new_access)
        if an.sat(lost_access):
            d.lost_access = an.lines(an.who(lost_access))
        if an.sat(weaker):
            d.weaker = an.lines(an.who(weaker))
            d.witness_weaker = an.witness_text(weaker)
        if an.sat(stronger):
            d.stronger = an.lines(an.who(stronger))
    d.old_weakest = _weakest(an, f_old).label
    d.new_weakest = _weakest(an, f_new).label
    d.rule_changes = _rule_changes(pol_old, pol_new)
    return d


def _weakest(an: Analyzer, f: dict[Strength, z3.BoolRef]) -> Strength:
    for c in sorted(f):
        if c > Strength.DENY and an.sat(f[c]):
            return c
    return Strength.DENY


def _rule_changes(old: Policy, new: Policy) -> list[RuleChange]:
    out: list[RuleChange] = []
    o = {r.id: r for r in old.rules}
    n = {r.id: r for r in new.rules}
    for rid in n.keys() - o.keys():
        out.append(RuleChange("added", n[rid].name))
    for rid in o.keys() - n.keys():
        out.append(RuleChange("removed", o[rid].name))
    for rid in o.keys() & n.keys():
        ro, rn = o[rid], n[rid]
        if (
            _sig(ro.conditions) != _sig(rn.conditions)
            or _sig(ro.action) != _sig(rn.action)
            or ro.status != rn.status
        ):
            out.append(RuleChange("edited", rn.name, "conditions/actions/status changed"))
    old_order = [r.id for r in old.active_rules() if r.id in n]
    new_order = [r.id for r in new.active_rules() if r.id in o]
    if old_order != new_order:
        out.append(RuleChange("reordered", new.name, " → ".join(n[i].name for i in new_order)))
    return out


def _sig(obj: Any) -> str:
    return json.dumps(asdict(obj) if is_dataclass(obj) else obj, sort_keys=True, default=str)
