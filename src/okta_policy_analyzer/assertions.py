"""User-written assertions about who must (not) be able to authenticate how, checked by the solver.

Assertions live in a YAML file::

    assertions:
      - name: contractors-denied-off-network
        description: Contractors may only reach standard apps from corp or VPN
        apps: [Salesforce, GitHub]          # app labels/ids, or `policy: <name|id>`, or `all_apps: true`
        when:                                # premise (all clauses AND-ed; lists are any-of unless noted)
          groups_any: [Contractors]
          zones_none: [Corporate Network, VPN]
        expect:                              # every clause must hold for every world satisfying the premise
          access: DENY

      - name: admins-phishing-resistant
        apps: [Okta Admin Console]
        when: {groups_any: [Okta Administrators]}
        expect: {min_strength: TWO_FA_PHISHING_RESISTANT}
        with_session_policy: true            # judge the strength after adding the global session policy

Premise clauses: ``groups_any``, ``groups_all``, ``groups_none``, ``users_any``, ``user_types_any``,
``attributes`` ({"user.department": "Finance"}), ``zones_any``, ``zones_none``, ``registered``, ``managed``,
``platforms_any``, ``assurance_any``, ``risk`` (level or list), ``auth_type``, ``idp``.
Expectations: ``access`` (ALLOW/DENY), ``min_strength``, ``max_strength`` (Strength names), ``passwordless``
(false = no passwordless path may exist), ``password_required`` (true), ``rules_any``, ``rules_none``.

A violated assertion comes back with a minimal counterexample (prime implicant) and a concrete world.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml
import z3

from .analysis import Analyzer
from .assurance import Strength, classify_rule, combined_rule_strength
from .model import Access, DevicePlatform, Policy, RiskLevel, SignOnAction
from .smt.encoder import EncodedPolicy


class AssertionError_(ValueError):
    pass


@dataclass
class Assertion:
    name: str
    description: str = ""
    apps: list[str] = field(default_factory=list)
    policy: str | None = None
    all_apps: bool = False
    when: dict[str, Any] = field(default_factory=dict)
    expect: dict[str, Any] = field(default_factory=dict)
    with_session_policy: bool = False

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Assertion:
        if "name" not in d:
            raise AssertionError_("assertion without a name")
        apps = d.get("apps") or ([d["app"]] if d.get("app") else [])
        return cls(
            name=str(d["name"]),
            description=str(d.get("description", "")),
            apps=[str(a) for a in apps],
            policy=d.get("policy"),
            all_apps=bool(d.get("all_apps", False)),
            when=dict(d.get("when") or {}),
            expect=dict(d.get("expect") or {}),
            with_session_policy=bool(d.get("with_session_policy", False)),
        )


@dataclass
class AssertionResult:
    assertion: Assertion
    policy: Policy
    holds: bool
    vacuous: bool = False  # premise unsatisfiable
    counterexample: str | None = None
    violating_rule: str | None = None
    violating_outcome: str | None = None
    who: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.assertion.name,
            "policy": self.policy.name,
            "holds": self.holds,
            "vacuous": self.vacuous,
            "counterexample": self.counterexample,
            "violating_rule": self.violating_rule,
            "violating_outcome": self.violating_outcome,
            "who": self.who,
            "error": self.error,
        }


def load_assertions(path: str) -> list[Assertion]:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    items = data.get("assertions", data) if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise AssertionError_("expected a list under 'assertions'")
    return [Assertion.from_dict(i) for i in items]


class AssertionChecker:
    def __init__(self, analyzer: Analyzer):
        self.an = analyzer
        self.t = analyzer.t
        self.u = analyzer.u
        self.enc = analyzer.enc

    # ------------------------------------------------------------------------------ resolution
    def _group(self, name: str) -> str:
        if name in self.u.member:
            return name
        for g in self.t.groups.values():
            if g.name == name:
                return g.id
        raise AssertionError_(f"unknown group {name!r}")

    def _zone(self, name: str) -> str:
        if name in self.u.zone:
            return name
        for z in self.t.zones.values():
            if z.name == name:
                return z.id
        raise AssertionError_(f"unknown zone {name!r}")

    def _policies(self, a: Assertion) -> list[Policy]:
        if a.all_apps:
            return list(self.t.access_policies)
        pols: list[Policy] = []
        if a.policy:
            p = self.t.policy(a.policy) or next(
                (p for p in self.t.access_policies if p.name == a.policy), None
            )
            if p is None:
                raise AssertionError_(f"unknown policy {a.policy!r}")
            pols.append(p)
        for label in a.apps:
            app = self.t.apps.get(label) or next((x for x in self.t.apps.values() if x.label == label), None)
            if app is None:
                raise AssertionError_(f"unknown app {label!r}")
            p = self.t.access_policy_for_app(app.id)
            if p is None:
                raise AssertionError_(f"app {label!r} has no authentication policy")
            if p not in pols:
                pols.append(p)
        if not pols:
            raise AssertionError_(f"assertion {a.name!r} names no app or policy")
        return pols

    # ------------------------------------------------------------------------------ premise
    def premise(self, when: dict[str, Any]) -> z3.BoolRef:  # noqa: C901
        u = self.u
        parts: list[z3.BoolRef] = []
        for key, value in when.items():
            if key == "groups_any":
                parts.append(z3.Or(*[u.member[self._group(g)] for g in value]))
            elif key == "groups_all":
                parts.extend(u.member[self._group(g)] for g in value)
            elif key == "groups_none":
                parts.extend(z3.Not(u.member[self._group(g)]) for g in value)
            elif key == "users_any":
                vs = []
                for uid in value:
                    for usr in self.t.users:
                        if usr.login == uid:
                            uid = usr.id
                    if uid not in u.user_is:
                        raise AssertionError_(
                            f"user {uid!r} is not referenced by any rule; only such users can be named"
                        )
                    vs.append(u.user_is[uid])
                parts.append(z3.Or(*vs))
            elif key == "user_types_any":
                ids = []
                for name in value:
                    ids.append(
                        name
                        if name in self.t.user_types
                        else next((t.id for t in self.t.user_types.values() if t.name == name), name)
                    )
                parts.append(z3.Or(*[u.user_type_is(i) for i in ids]))
            elif key == "attributes":
                for path, lit in value.items():
                    parts.append(u.attr_equals(path if path.startswith("user.") else f"user.{path}", lit))
            elif key == "zones_any":
                parts.append(z3.Or(*[u.zone[self._zone(z)] for z in value]))
            elif key == "zones_none":
                parts.extend(z3.Not(u.zone[self._zone(z)]) for z in value)
            elif key == "registered":
                parts.append(u.registered if value else z3.Not(u.registered))
            elif key == "managed":
                parts.append(u.managed if value else z3.Not(u.managed))
            elif key == "platforms_any":
                parts.append(u.platform_in([DevicePlatform(str(p).upper()) for p in value]))
            elif key == "assurance_any":
                ids = [
                    d
                    if d in u.assurance
                    else next((x.id for x in self.t.device_assurances.values() if x.name == d), d)
                    for d in value
                ]
                parts.append(
                    z3.Or(*[u.assurance[i] for i in ids if i in u.assurance])
                    if any(i in u.assurance for i in ids)
                    else z3.BoolVal(False)
                )
            elif key == "risk":
                levels = value if isinstance(value, list) else [value]
                parts.append(z3.Or(*[u.risk_is(RiskLevel(str(lv).upper())) for lv in levels]))
            elif key == "auth_type":
                parts.append(u.auth_type_is(str(value).upper()))
            elif key == "idp":
                parts.append(u.idp_is_okta() if str(value).upper() == "OKTA" else u.idp_is(str(value)))
            else:
                raise AssertionError_(f"unknown premise clause {key!r}")
        return z3.And(*parts) if parts else z3.BoolVal(True)

    # ------------------------------------------------------------------------------ expectations
    def rule_satisfies(
        self, rule_index: int, ep: EncodedPolicy, a: Assertion, session: SignOnAction | None
    ) -> tuple[bool, str]:
        """Does the outcome of rule i satisfy the expectation? Returns (ok, outcome description)."""
        rule = ep.rules[rule_index]
        ra = classify_rule(rule, self.an.catalogue)
        if session is not None:
            strength = combined_rule_strength(session, ra)
            access = Access.DENY if session.access == Access.DENY else ra.access
        else:
            strength = ra.weakest if ra.access == Access.ALLOW else Strength.DENY
            access = ra.access
        desc = f"{rule.name!r} -> {strength.label}"
        e = a.expect
        if "access" in e and access.value != str(e["access"]).upper():
            return False, desc
        if "min_strength" in e and (access == Access.DENY or strength < Strength[str(e["min_strength"])]):
            if not (access == Access.DENY and e.get("allow_deny", True) is False):
                if access == Access.DENY and e.get("deny_ok", True):
                    return True, desc  # DENY is always at least as strong as any requirement
                return False, desc
        if "max_strength" in e and access == Access.ALLOW and strength > Strength[str(e["max_strength"])]:
            return False, desc
        if (
            "passwordless" in e
            and e["passwordless"] is False
            and access == Access.ALLOW
            and ra.passwordless_possible
        ):
            if session is None or session.primary_factor.value != "PASSWORD_IDP":
                return False, desc
        if (
            "password_required" in e
            and e["password_required"]
            and access == Access.ALLOW
            and not ra.requires_password
        ):
            if session is None or session.primary_factor.value != "PASSWORD_IDP":
                return False, desc
        if "rules_any" in e and rule.name not in e["rules_any"] and rule.id not in e["rules_any"]:
            return False, desc
        if "rules_none" in e and (rule.name in e["rules_none"] or rule.id in e["rules_none"]):
            return False, desc
        return True, desc

    # ------------------------------------------------------------------------------ check
    def check(self, a: Assertion) -> list[AssertionResult]:
        results: list[AssertionResult] = []
        try:
            policies = self._policies(a)
            prem = self.premise(a.when)
        except AssertionError_ as e:
            return [
                AssertionResult(
                    a,
                    Policy(
                        "",
                        "",
                        self.t.access_policies[0].type if self.t.access_policies else None,
                        0,
                        None,
                        False,
                        [],
                    ),
                    False,
                    error=str(e),
                )
            ]  # type: ignore[arg-type]
        for pol in policies:
            ep = self.enc.access_policy(pol)
            if not self.an.sat(prem):
                results.append(AssertionResult(a, pol, True, vacuous=True))
                continue
            violations: list[tuple[z3.BoolRef, str, str]] = []
            if a.with_session_policy and self.enc.session_policies:
                for sep in self.enc.session_policies:
                    for k, srule in enumerate(sep.rules):
                        action = srule.action
                        if not isinstance(action, SignOnAction):
                            continue
                        for i in range(len(ep.rules)):
                            ok, desc = self.rule_satisfies(i, ep, a, action)
                            if not ok:
                                violations.append(
                                    (
                                        z3.And(sep.decides(k), ep.effective[i]),
                                        ep.rules[i].name,
                                        f"{desc} (session: {srule.name!r})",
                                    )
                                )
            else:
                for i in range(len(ep.rules)):
                    ok, desc = self.rule_satisfies(i, ep, a, None)
                    if not ok:
                        violations.append((ep.effective[i], ep.rules[i].name, desc))
            # falling through all rules counts as DENY
            if (
                a.expect.get("access", "DENY").upper() != "DENY"
                or "min_strength" in a.expect
                and not a.expect.get("deny_ok", True)
            ):
                violations.append((ep.no_match, "<no rule matched>", "DENY (no rule matched)"))
            found = None
            for f, rname, desc in violations:
                bad = z3.And(prem, f)
                if self.an.sat(bad):
                    found = (bad, rname, desc)
                    break
            if found is None:
                results.append(AssertionResult(a, pol, True))
            else:
                bad, rname, desc = found
                results.append(
                    AssertionResult(
                        a,
                        pol,
                        False,
                        counterexample=self.an.witness_text(bad),
                        violating_rule=rname,
                        violating_outcome=desc,
                        who=self.an.lines(self.an.who(bad)),
                    )
                )
        return results

    def check_all(self, assertions: list[Assertion]) -> list[AssertionResult]:
        out: list[AssertionResult] = []
        for a in assertions:
            out.extend(self.check(a))
        return out
