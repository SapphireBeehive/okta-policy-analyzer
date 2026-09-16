"""Encode rule matching, ordered first-match evaluation and policy selection as z3 formulas.

Semantics (Okta Identity Engine):

* A rule matches when **all** of its conditions hold; an absent condition is "any".
* ``people``: the user matches when they are in *any* included group **or** are an included user
  (an empty include means everyone), **and** are not an excluded user or member of an excluded group.
  Exclusion always wins.
* ``network``: connection ZONE with ``include`` matches inside any included zone; ``exclude`` matches
  outside every excluded zone. Zones may overlap.
* Rules of a policy are evaluated in priority order and the **first** matching *active* rule decides.
* Global session and enrollment policies are themselves chosen by priority: policies are considered in priority
  order; the first *active* policy whose group condition holds for the user **and** that has a matching rule is
  applied. A group-matching policy none of whose rules match falls through to the next policy (Okta Policy API:
  "If none of the policy rules have conditions that can be met, then the next policy in the list is considered").
* A ``system`` (default) policy without an explicit group assignment applies to everyone; a custom policy without
  group assignment applies to nobody.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property

import z3

from ..model import Policy, PolicyType, Rule, RuleConditions, Tenant
from .el_encoder import ELEncoder
from .universe import DESKTOP, MOBILE, PLATFORMS, Universe

_OS_TO_PLATFORM = {
    "IOS": "IOS",
    "ANDROID": "ANDROID",
    "OSX": "MACOS",
    "MACOS": "MACOS",
    "WINDOWS": "WINDOWS",
    "CHROMEOS": "CHROMEOS",
    "LINUX": "LINUX",
    "OTHER": "OTHER",
}


@dataclass
class EncodedPolicy:
    policy: Policy
    rules: list[Rule]  # active rules in evaluation order
    match: list[z3.BoolRef]  # match_i
    effective: list[z3.BoolRef]  # eff_i = match_i ∧ ¬∨_{j<i} match_j (within the policy)
    no_match: z3.BoolRef  # ¬∨ match_i
    applies: z3.BoolRef  # policy-level group condition holds (True for ACCESS_POLICY)
    selected: z3.BoolRef  # this policy decides: applies ∧ some rule matches ∧ no earlier policy decided
    reachable: z3.BoolRef  # applies ∧ no earlier policy decided (the policy is consulted)

    def decides(self, i: int) -> z3.BoolRef:
        """Rule i of this policy is the one applied to the world."""
        return z3.And(self.reachable, self.effective[i])

    def rule_index(self, rule_id: str) -> int:
        for i, r in enumerate(self.rules):
            if r.id == rule_id:
                return i
        raise KeyError(rule_id)


class PolicyEncoder:
    def __init__(self, universe: Universe):
        self.u = universe
        self.tenant: Tenant = universe.tenant
        self.el = ELEncoder(universe)
        self._match_cache: dict[str, z3.BoolRef] = {}
        self._encoded: dict[str, EncodedPolicy] = {}

    # ------------------------------------------------------------------------------ conditions
    def match(self, rule: Rule) -> z3.BoolRef:
        if rule.id not in self._match_cache:
            self._match_cache[rule.id] = self._conditions(rule.conditions)
        return self._match_cache[rule.id]

    def people(self, rule: Rule) -> z3.BoolRef:
        """Only the people (users/groups/user type) part of a rule's conditions: the population it targets."""
        c = rule.conditions
        return self._conditions(RuleConditions(people=c.people, user_type=c.user_type))

    def _conditions(self, c: RuleConditions) -> z3.BoolRef:
        u = self.u
        parts: list[z3.BoolRef] = []
        if c.people:
            p = c.people
            include: list[z3.BoolRef] = [u.member[g] for g in p.groups_include if g in u.member]
            include += [u.user_is[x] for x in p.users_include if x in u.user_is]
            if p.groups_include or p.users_include:
                parts.append(z3.Or(*include) if include else z3.BoolVal(False))
            exclude: list[z3.BoolRef] = [u.member[g] for g in p.groups_exclude if g in u.member]
            exclude += [u.user_is[x] for x in p.users_exclude if x in u.user_is]
            if exclude:
                parts.append(z3.Not(z3.Or(*exclude)))
        if c.network:
            n = c.network
            if n.include:
                parts.append(
                    z3.Or(*[u.zone[z] for z in n.include if z in u.zone])
                    if any(z in u.zone for z in n.include)
                    else z3.BoolVal(False)
                )
            if n.exclude:
                ex = [u.zone[z] for z in n.exclude if z in u.zone]
                if ex:
                    parts.append(z3.Not(z3.Or(*ex)))
        if c.device:
            d = c.device
            if d.registered is True:
                parts.append(u.registered)
            elif d.registered is False:
                parts.append(z3.Not(u.registered))
            if d.managed is True:
                parts.append(u.managed)
            elif d.managed is False:
                parts.append(z3.Not(u.managed))
            if d.assurance_include:
                parts.append(
                    z3.Or(*[u.assurance[a] for a in d.assurance_include if a in u.assurance])
                    if any(a in u.assurance for a in d.assurance_include)
                    else z3.BoolVal(False)
                )
            if d.platform_types:
                parts.append(u.platform_in(d.platform_types))
        if c.platform:
            inc = [self._platform_spec(s) for s in c.platform.include]
            if c.platform.include:
                parts.append(z3.Or(*inc))
            for s in c.platform.exclude:
                parts.append(z3.Not(self._platform_spec(s)))
        if c.risk_level is not None:
            parts.append(u.risk_is(c.risk_level))
        if c.user_type:
            if c.user_type.include:
                parts.append(z3.Or(*[u.user_type_is(t) for t in c.user_type.include]))
            for t in c.user_type.exclude:
                parts.append(z3.Not(u.user_type_is(t)))
        if c.el:
            parts.append(self.el.encode_bool(c.el.ast) if c.el.ast is not None else u.opaque(c.el.text))
        if c.behaviors:
            parts.append(z3.Or(*[u.opaque(f"behavior {b} detected") for b in c.behaviors]))
        if c.auth_type:
            parts.append(u.auth_type_is(c.auth_type))
        if c.idp:
            if c.idp.provider == "OKTA":
                parts.append(u.idp_is_okta())
            elif c.idp.provider == "SPECIFIC_IDP":
                parts.append(
                    z3.Or(*[u.idp_is(i) for i in c.idp.idp_ids]) if c.idp.idp_ids else z3.BoolVal(False)
                )
        return z3.And(*parts) if parts else z3.BoolVal(True)

    def _platform_spec(self, s) -> z3.BoolRef:  # noqa: ANN001
        u = self.u
        parts: list[z3.BoolRef] = []
        t = (s.type or "ANY").upper()
        if t == "MOBILE":
            parts.append(u.platform_in(MOBILE))
        elif t == "DESKTOP":
            parts.append(u.platform_in(DESKTOP))
        elif t == "OTHER":
            parts.append(u.platform_in([p for p in PLATFORMS if p.value == "OTHER"]))
        if s.os_type and s.os_type.upper() not in ("ANY",):
            mapped = _OS_TO_PLATFORM.get(s.os_type.upper())
            if mapped:
                parts.append(u.platform_in([p for p in PLATFORMS if p.value == mapped]))
        if s.os_expression:
            parts.append(u.opaque(f"os version {s.os_expression}"))
        return z3.And(*parts) if parts else z3.BoolVal(True)

    # ------------------------------------------------------------------------------ policies
    def encode_policy(
        self,
        policy: Policy,
        *,
        applies: z3.BoolRef | None = None,
        earlier_decided: list[z3.BoolRef] | None = None,
    ) -> EncodedPolicy:
        key = policy.id
        standalone = applies is None and not earlier_decided
        if standalone and key in self._encoded:
            return self._encoded[key]
        rules = policy.active_rules()
        matches = [self.match(r) for r in rules]
        effective: list[z3.BoolRef] = []
        for i, m in enumerate(matches):
            prior = matches[:i]
            effective.append(z3.And(m, z3.Not(z3.Or(*prior))) if prior else m)
        any_match = z3.Or(*matches) if matches else z3.BoolVal(False)
        no_match = z3.Not(any_match)
        applies_f = applies if applies is not None else z3.BoolVal(True)
        not_earlier = z3.Not(z3.Or(*earlier_decided)) if earlier_decided else z3.BoolVal(True)
        reachable = z3.And(applies_f, not_earlier)
        selected = z3.And(reachable, any_match)
        ep = EncodedPolicy(policy, rules, matches, effective, no_match, applies_f, selected, reachable)
        if standalone:
            self._encoded[key] = ep
        return ep

    def policy_applies(self, pol: Policy) -> z3.BoolRef:
        """Policy-level group condition. Default (system) policies without groups apply to everyone."""
        u = self.u
        if pol.group_include:
            known = [u.member[g] for g in pol.group_include if g in u.member]
            return z3.Or(*known) if known else z3.BoolVal(False)
        if pol.system:
            return z3.BoolVal(True)
        u.assumptions.append(
            f"policy {pol.name!r} has no group assignment and is not a default policy; it applies to nobody"
        )
        return z3.BoolVal(False)

    def encode_prioritised(self, policies: list[Policy]) -> list[EncodedPolicy]:
        """Encode group-assigned policies (global session / enrollment) chosen by priority, with fall-through."""
        out: list[EncodedPolicy] = []
        decided: list[z3.BoolRef] = []
        for pol in policies:
            if not pol.is_active:
                continue
            ep = self.encode_policy(pol, applies=self.policy_applies(pol), earlier_decided=list(decided))
            out.append(ep)
            decided.append(ep.selected)
        return out

    def family_no_decision(self, encoded: list[EncodedPolicy]) -> z3.BoolRef:
        """No policy of the family decides (only possible if the default policy's catch-all is missing)."""
        return z3.Not(z3.Or(*[ep.selected for ep in encoded])) if encoded else z3.BoolVal(True)

    @cached_property
    def session_policies(self) -> list[EncodedPolicy]:
        return self.encode_prioritised(self.tenant.session_policies)

    @cached_property
    def enrollment_policies(self) -> list[EncodedPolicy]:
        return self.encode_prioritised(self.tenant.enrollment_policies)

    def access_policy(self, policy: Policy) -> EncodedPolicy:
        assert policy.type == PolicyType.ACCESS_POLICY
        return self.encode_policy(policy)

    # ------------------------------------------------------------------------------ solver
    def solver(self, *extra: z3.BoolRef) -> z3.Solver:
        s = z3.Solver()
        s.add(*self.u.axioms())
        if extra:
            s.add(*extra)
        return s

    def sat(self, *formulas: z3.BoolRef) -> bool:
        return self.solver(*formulas).check() == z3.sat

    def model(self, *formulas: z3.BoolRef) -> z3.ModelRef | None:
        s = self.solver(*formulas)
        return s.model() if s.check() == z3.sat else None
