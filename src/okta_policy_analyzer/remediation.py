"""Turn a violated invariant into a policy change, prove the change fixes it, then (optionally) apply it.

The flow is *propose → verify in the model → confirm → apply → re-snapshot → re-verify*:

1. :func:`plan_fix` parses the plain-English invariant, checks it, and if it is VIOLATED synthesises the
   smallest policy change that makes it hold:

   * a **DENY** invariant ("Contractors can only reach Salesforce from the VPN") becomes one new DENY rule at
     the top of each violated policy whose conditions are exactly the invariant's premise;
   * a **strength** invariant ("Executives must use phishing-resistant MFA for Payroll") is fixed by raising
     the verification method of each rule the counterexamples land on, one at a time, until the invariant is
     proved (no new rule; nobody gains access);
   * an **ALLOW** invariant ("Everyone must be able to access Okta Dashboard") becomes an ALLOW rule at the top
     for the premise, flagged for review because it overrides everything below it for that population;
   * "must be handled by rule X" invariants are reported, not fixed (they are about existing rule order).

   The change is applied to an in-memory copy of the snapshot, the invariant is re-checked there, the two
   snapshots are formally diffed (who lost access, who got stronger requirements, and, if anything got
   *more* permissive, that too) and any HIGH/MEDIUM finding the change introduces is listed. The result is a
   :class:`FixPlan` of Okta API operations (``create`` / ``update`` rule bodies) that a human reviews.

2. :func:`apply_plan` executes the operations against the org (``POST``/``PUT`` on
   ``/api/v1/policies/{policyId}/rules``) and records what it did in an :class:`ApplyRecord` (created rule ids,
   previous bodies of updated rules) so :func:`rollback` can undo exactly that.

Nothing here writes to Okta unless :func:`apply_plan` is called explicitly; the CLI additionally requires
``--yes``.
"""

from __future__ import annotations

import copy
import json
from dataclasses import asdict, dataclass, field
from typing import Any

from .analysis import AnalysisOptions, Analyzer
from .assertions import Assertion
from .assurance import Strength
from .diff import diff_tenants
from .invariants import InvariantResult, check_invariants, parse_invariant
from .loader import load_tenant
from .model import DevicePlatform, PolicyType, Tenant
from .okta.snapshot import Snapshot

MAX_STRENGTHEN_ROUNDS = 12


# ------------------------------------------------------------------------------------------ data


@dataclass
class RuleOp:
    op: str  # "create" | "update"
    policy_id: str
    policy_name: str
    rule: dict[str, Any]  # full Okta rule body to POST/PUT
    rule_id: str | None = None  # update only
    previous: dict[str, Any] | None = None  # update only: the body before the change (for rollback)
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RuleOp:
        return cls(
            **{
                k: d.get(k)
                for k in ("op", "policy_id", "policy_name", "rule", "rule_id", "previous", "rationale")
            }
        )


@dataclass
class FixPlan:
    sentence: str
    reading: str
    before: str  # verdict on the current snapshot
    after: str | None  # verdict on the patched snapshot (None when nothing was proposed)
    ops: list[RuleOp]
    assertion: dict[str, Any] | None
    diff: list[dict[str, Any]] = field(default_factory=list)  # per-app formal diff
    new_findings: list[dict[str, Any]] = field(default_factory=list)  # findings introduced by the change
    caveats: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    before_detail: list[str] = field(default_factory=list)

    @property
    def fixes(self) -> bool:
        return bool(self.ops) and self.after == "PROVED"

    @property
    def status(self) -> str:
        if self.before in ("VACUOUS", "UNPARSED", "ERROR"):
            return self.before
        if self.problems:
            return "UNFIXABLE"
        if self.before == "PROVED":
            return "ALREADY_HOLDS"
        return "FIX_PROVED" if self.fixes else "FIX_INSUFFICIENT"

    def to_dict(self) -> dict[str, Any]:
        return {
            "sentence": self.sentence,
            "status": self.status,
            "reading": self.reading,
            "before": self.before,
            "after": self.after,
            "assertion": self.assertion,
            "ops": [o.to_dict() for o in self.ops],
            "diff": self.diff,
            "new_findings": self.new_findings,
            "caveats": self.caveats,
            "problems": self.problems,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FixPlan:
        return cls(
            sentence=d["sentence"],
            reading=d.get("reading", ""),
            before=d.get("before", ""),
            after=d.get("after"),
            ops=[RuleOp.from_dict(o) for o in d.get("ops", [])],
            assertion=d.get("assertion"),
            diff=d.get("diff", []),
            new_findings=d.get("new_findings", []),
            caveats=d.get("caveats", []),
            problems=d.get("problems", []),
        )

    def to_text(self) -> str:  # noqa: C901 - formatting
        lines = [f"{self.status}: {self.sentence}"]
        if self.reading:
            lines.append(f"  reading: {self.reading}")
        lines += [f"  {x}" for x in self.before_detail]
        for p in self.problems:
            lines.append(f"  cannot fix: {p}")
        if self.status == "ALREADY_HOLDS":
            lines.append("  the invariant already holds; nothing to change")
        for o in self.ops:
            verb = "CREATE rule" if o.op == "create" else f"UPDATE rule {o.rule_id}"
            lines.append(f"  {verb} in policy {o.policy_name!r}: {o.rule.get('name')!r}")
            if o.rationale:
                lines.append(f"    why: {o.rationale}")
            lines.append("    body:")
            body = {
                k: v
                for k, v in o.rule.items()
                if k in ("name", "priority", "status", "conditions", "actions")
            }
            lines += ["      " + ln for ln in json.dumps(body, indent=2, ensure_ascii=False).splitlines()]
        if self.after is not None:
            lines.append(f"  after the change the invariant is: {self.after}")
        for d in self.diff:
            if d["verdict"] == "EQUIVALENT":
                continue
            lines.append(
                f"  impact on {d['app']}: {d['verdict']} (weakest {d['old_weakest']} → {d['new_weakest']})"
            )
            for w in d.get("lost_access", []):
                lines.append(f"    - lost access:   {w}")
            for w in d.get("stronger", []):
                lines.append(f"    ^ stronger auth: {w}")
            for w in d.get("new_access", []):
                lines.append(f"    + NEW ACCESS:    {w}")
            for w in d.get("weaker", []):
                lines.append(f"    ~ WEAKER AUTH:   {w}")
        for f in self.new_findings:
            lines.append(f"  new finding ({f['severity']}): {f['title']}")
        for c in self.caveats:
            lines.append(f"  caveat: {c}")
        return "\n".join(lines)


# ------------------------------------------------------------------------------------------ synthesis

_DESKTOP = {
    DevicePlatform.MACOS: "OSX",
    DevicePlatform.WINDOWS: "WINDOWS",
    DevicePlatform.CHROMEOS: "CHROMEOS",
    DevicePlatform.LINUX: "LINUX",
}
_MOBILE = {DevicePlatform.IOS: "IOS", DevicePlatform.ANDROID: "ANDROID"}


def _ids(tenant: Tenant, names: list[str], table: dict[str, Any], label: str) -> list[str]:
    out = []
    for n in names:
        if n in table:
            out.append(n)
            continue
        hit = next(
            (k for k, v in table.items() if getattr(v, "name", None) == n or getattr(v, "label", None) == n),
            None,
        )
        if hit is None:
            raise ValueError(f"unknown {label} {n!r}")
        out.append(hit)
    return out


def _everyone_id(tenant: Tenant) -> str | None:
    return next((g.id for g in tenant.groups.values() if g.is_everyone), None)


def conditions_from_when(when: dict[str, Any], tenant: Tenant) -> dict[str, Any]:  # noqa: C901
    """Okta rule ``conditions`` that match exactly the worlds of an assertion premise."""
    c: dict[str, Any] = {}
    people: dict[str, Any] = {}
    groups_inc = _ids(tenant, when.get("groups_any", []), tenant.groups, "group")
    if "groups_all" in when:
        if len(when["groups_all"]) > 1:
            raise ValueError(
                "a rule cannot require membership of several groups at once; use a group rule or EL"
            )
        groups_inc += _ids(tenant, when["groups_all"], tenant.groups, "group")
    groups_exc = _ids(tenant, when.get("groups_none", []), tenant.groups, "group")
    users_inc: list[str] = []
    for u in when.get("users_any", []):
        users_inc.append(next((x.id for x in tenant.users if x.login == u), u))
    if groups_inc or groups_exc:
        people["groups"] = {}
        if groups_inc:
            people["groups"]["include"] = groups_inc
        elif not users_inc:
            ev = _everyone_id(tenant)
            if ev:
                people["groups"]["include"] = [ev]
        if groups_exc:
            people["groups"]["exclude"] = groups_exc
    if users_inc:
        people["users"] = {"include": users_inc}
    if people:
        c["people"] = people
    if "user_types_any" in when:
        c["userType"] = {"include": _ids(tenant, when["user_types_any"], tenant.user_types, "user type")}
    if "zones_any" in when or "zones_none" in when:
        net: dict[str, Any] = {"connection": "ZONE"}
        if "zones_any" in when:
            net["include"] = _ids(tenant, when["zones_any"], tenant.zones, "zone")
        if "zones_none" in when:
            net["exclude"] = _ids(tenant, when["zones_none"], tenant.zones, "zone")
        if "include" in net and "exclude" in net:
            raise ValueError("Okta network conditions are either include or exclude, not both")
        c["network"] = net
    dev: dict[str, Any] = {}
    if when.get("managed") is True:
        dev["managed"] = True
        dev["registered"] = True
    elif when.get("managed") is False:
        dev["managed"] = False
    if when.get("registered") is True:
        dev["registered"] = True
    elif when.get("registered") is False:
        if dev.get("managed"):
            raise ValueError("a managed device is always registered")
        dev["registered"] = False
    if "assurance_any" in when:
        dev["assurance"] = {
            "include": _ids(
                tenant, when["assurance_any"], tenant.device_assurances, "device assurance policy"
            )
        }
        dev.setdefault("registered", True)
    if dev:
        c["device"] = dev
    if "platforms_any" in when:
        inc = []
        for p in when["platforms_any"]:
            plat = DevicePlatform(str(p).upper())
            if plat in _DESKTOP:
                inc.append({"type": "DESKTOP", "os": {"type": _DESKTOP[plat]}})
            elif plat in _MOBILE:
                inc.append({"type": "MOBILE", "os": {"type": _MOBILE[plat]}})
            else:
                raise ValueError(f"platform {p!r} cannot be expressed as an Okta platform condition")
        c["platform"] = {"include": inc}
    if "risk" in when:
        levels = when["risk"] if isinstance(when["risk"], list) else [when["risk"]]
        if len(levels) != 1:
            raise ValueError("a rule matches exactly one risk level")
        c["riskScore"] = {"level": str(levels[0]).upper()}
    if "attributes" in when:
        clauses = []
        for path, lit in when["attributes"].items():
            attr = path.split(".", 1)[1] if path.startswith("user.") else path
            clauses.append(f"user.profile.{attr} == {json.dumps(str(lit))}")
        c["elCondition"] = {"condition": " && ".join(clauses)}
    for k in ("auth_type", "idp"):
        if k in when:
            raise ValueError(f"premise clause {k!r} cannot be turned into a rule condition automatically")
    return c


def _possession(**kw: Any) -> dict[str, Any]:
    p = {
        "deviceBound": "OPTIONAL",
        "hardwareProtection": "OPTIONAL",
        "phishingResistant": "OPTIONAL",
        "userPresence": "REQUIRED",
        "userVerification": "OPTIONAL",
        "required": True,
    }
    p.update(kw)
    return p


def verification_method_for(expect: dict[str, Any], previous: dict[str, Any] | None = None) -> dict[str, Any]:
    """The weakest Okta ``verificationMethod`` satisfying a strength/password expectation."""
    reauth = (previous or {}).get("reauthenticateIn", "PT2H")
    vm: dict[str, Any] = {
        "type": "ASSURANCE",
        "factorMode": "2FA",
        "reauthenticateIn": reauth,
        "constraints": [],
    }
    min_s = Strength[str(expect["min_strength"])] if "min_strength" in expect else None
    constraint: dict[str, Any] = {}
    if min_s is None or min_s <= Strength.ONE_FA_POSSESSION:
        # "not a password alone": one possession factor is enough
        if min_s is not None:
            vm["factorMode"] = "1FA"
            constraint["possession"] = _possession()
    elif min_s == Strength.ONE_FA_PHISHING_RESISTANT:
        vm["factorMode"] = "1FA"
        constraint["possession"] = _possession(phishingResistant="REQUIRED")
    elif min_s == Strength.TWO_FA:
        pass  # any two factor types
    elif min_s == Strength.TWO_FA_PHISHING_RESISTANT:
        constraint["possession"] = _possession(phishingResistant="REQUIRED")
    elif min_s == Strength.TWO_FA_PHISHING_RESISTANT_HARDWARE:
        constraint["possession"] = _possession(phishingResistant="REQUIRED", hardwareProtection="REQUIRED")
    if expect.get("passwordless") is False or expect.get("password_required"):
        constraint["knowledge"] = {"types": ["PASSWORD"], "methods": ["PASSWORD"], "required": True}
        if vm["factorMode"] == "1FA" and "possession" in constraint:
            vm["factorMode"] = "2FA"
    if constraint:
        vm["constraints"] = [constraint]
    return vm


def _rule_name(sentence: str, prefix: str) -> str:
    short = " ".join(sentence.strip().rstrip(".").split())
    return f"{prefix}: {short}"[:100]


def synthesize_rule(assertion: Assertion, tenant: Tenant, sentence: str) -> tuple[dict[str, Any], str]:
    """A new top-priority rule enforcing a DENY or ALLOW invariant. Returns (rule body, rationale)."""
    conds = conditions_from_when(assertion.when, tenant)
    e = assertion.expect
    if e.get("access") == "DENY":
        actions = {"appSignOn": {"access": "DENY"}}
        rationale = (
            "a DENY rule at the top of the policy whose conditions are exactly the invariant's premise"
        )
        name = _rule_name(sentence, "Deny")
    elif e.get("access") == "ALLOW":
        actions = {
            "appSignOn": {
                "access": "ALLOW",
                "verificationMethod": verification_method_for({"min_strength": "TWO_FA"}),
            }
        }
        rationale = "an ALLOW rule (2FA) at the top of the policy for the premise; review: it pre-empts every rule below it for these users"
        name = _rule_name(sentence, "Allow")
    else:
        raise ValueError("only DENY/ALLOW invariants are fixed by adding a rule")
    rule = {
        "name": name,
        "priority": 1,
        "status": "ACTIVE",
        "system": False,
        "type": "ACCESS_POLICY",
        "conditions": conds or None,
        "actions": actions,
    }
    return rule, rationale


def strengthen_rule(raw: dict[str, Any], expect: dict[str, Any]) -> dict[str, Any]:
    """Copy of an existing ALLOW rule whose verification method meets the expectation."""
    new = copy.deepcopy(raw)
    aso = new.setdefault("actions", {}).setdefault("appSignOn", {})
    if aso.get("access", "ALLOW") == "DENY":
        raise ValueError("rule is a DENY rule; nothing to strengthen")
    aso["access"] = "ALLOW"
    aso["verificationMethod"] = verification_method_for(expect, aso.get("verificationMethod"))
    return new


# ------------------------------------------------------------------------------------------ patching a snapshot


def _policy_dict(snapshot: Snapshot, policy_id: str) -> dict[str, Any]:
    for p in snapshot.policies:
        if p.get("id") == policy_id:
            return p
    raise KeyError(policy_id)


def apply_ops_to_snapshot(snapshot: Snapshot, ops: list[RuleOp]) -> Snapshot:
    """A deep copy of the snapshot with the operations applied (new rules go to the top of their policy)."""
    snap = Snapshot.from_dict(copy.deepcopy(snapshot.to_dict()))
    for n, op in enumerate(ops):
        pol = _policy_dict(snap, op.policy_id)
        rules: list[dict[str, Any]] = pol.setdefault("_rules", [])
        if op.op == "create":
            body = copy.deepcopy(op.rule)
            body.setdefault("id", f"proposed_{n}")
            user_rules = [r for r in rules if not r.get("system")]
            top = min((int(r.get("priority", 1)) for r in user_rules), default=1)
            for r in user_rules:
                r["priority"] = int(r.get("priority", 1)) + 1
            body["priority"] = top
            body.setdefault("status", "ACTIVE")
            body.setdefault("system", False)
            body.setdefault("type", pol.get("type", "ACCESS_POLICY"))
            rules.insert(0, body)
        elif op.op == "update":
            for i, r in enumerate(rules):
                if r.get("id") == op.rule_id:
                    body = copy.deepcopy(op.rule)
                    body["id"] = op.rule_id
                    body.setdefault("priority", r.get("priority"))
                    rules[i] = body
                    break
            else:
                raise KeyError(f"rule {op.rule_id} not in policy {op.policy_id}")
        else:
            raise ValueError(f"unknown op {op.op!r}")
    snap.manifest.warnings = list(snap.manifest.warnings) + [
        "patched in memory by okta-policy-analyzer propose"
    ]
    return snap


# ------------------------------------------------------------------------------------------ planning


def _findings_key(f: dict[str, Any]) -> tuple:
    return (f.get("kind"), f.get("policy"), f.get("rule"), f.get("title"))


def plan_fix(  # noqa: C901 - one decision tree
    snapshot: Snapshot,
    sentence: str,
    options: AnalysisOptions | None = None,
    *,
    rule_name: str | None = None,
) -> FixPlan:
    options = options or AnalysisOptions(full_cubes=False)
    an = Analyzer.from_snapshot(snapshot, options)
    tenant = an.t
    parsed = parse_invariant(sentence, tenant)
    if not parsed.ok:
        return FixPlan(sentence, "", "UNPARSED", None, [], None, problems=parsed.problems)
    assertion = parsed.assertion
    assert assertion is not None
    (res0,) = check_invariants(an, [sentence])
    plan = FixPlan(
        sentence,
        parsed.reading,
        res0.verdict,
        None,
        [],
        _assertion_dict(assertion),
        before_detail=_violations(res0),
    )
    plan.caveats += [f"interpretation: {n}" for n in parsed.notes]
    if res0.verdict != "VIOLATED":
        return plan

    e = assertion.expect
    ops: list[RuleOp] = []
    try:
        if "rules_any" in e or "rules_none" in e:
            plan.problems.append(
                "the invariant is about which existing rule decides; reorder or narrow the rules named in the counterexample by hand"
            )
            return plan
        if e.get("access") in ("DENY", "ALLOW"):
            rule, why = synthesize_rule(assertion, tenant, sentence)
            if rule_name:
                rule["name"] = rule_name
            for r in res0.results:
                if r.holds or r.vacuous or r.error:
                    continue
                ops.append(RuleOp("create", r.policy.id, r.policy.name, copy.deepcopy(rule), rationale=why))
            if e.get("access") == "ALLOW":
                plan.caveats.append(
                    "an ALLOW rule at the top pre-empts stronger requirements below it for the same users; check the impact lines"
                )
        else:
            # strength / password invariants: raise the violating rules until the invariant is proved
            snap_i = snapshot
            seen: set[tuple[str, str]] = set()
            for _round in range(MAX_STRENGTHEN_ROUNDS):
                an_i = Analyzer.from_snapshot(snap_i, options)
                (res_i,) = check_invariants(an_i, [sentence])
                if res_i.verdict != "VIOLATED":
                    break
                progressed = False
                for r in res_i.results:
                    if r.holds or r.vacuous or r.error or not r.violating_rule:
                        continue
                    pol = next(p for p in an_i.t.access_policies if p.id == r.policy.id)
                    rule = next(
                        (x for x in pol.rules if x.name == r.violating_rule or x.id == r.violating_rule), None
                    )
                    if rule is None or (pol.id, rule.id) in seen:
                        continue
                    seen.add((pol.id, rule.id))
                    if rule.system:
                        plan.caveats.append(
                            f"the catch-all rule of {pol.name!r} is violating; Okta lets you edit its verification method but not its conditions"
                        )
                    new_body = strengthen_rule(rule.raw, e)
                    ops.append(
                        RuleOp(
                            "update",
                            pol.id,
                            pol.name,
                            new_body,
                            rule_id=rule.id,
                            previous=copy.deepcopy(rule.raw),
                            rationale=f"rule {rule.name!r} decides the counterexample with {r.violating_outcome}; raise its verification method to the required minimum",
                        )
                    )
                    progressed = True
                if not progressed:
                    break
                snap_i = apply_ops_to_snapshot(snapshot, ops)
    except (ValueError, KeyError) as ex:
        plan.problems.append(str(ex))
        return plan
    if not ops:
        plan.problems.append("no rule change could be derived from the counterexample")
        return plan
    plan.ops = ops

    # --- verify in the model ---------------------------------------------------------------------
    patched = apply_ops_to_snapshot(snapshot, ops)
    an1 = Analyzer.from_snapshot(patched, options)
    (res1,) = check_invariants(an1, [sentence])
    plan.after = res1.verdict
    if res1.verdict == "VIOLATED":
        plan.before_detail += ["after: " + x for x in _violations(res1)]
    touched = {o.policy_id for o in ops}
    d = diff_tenants(tenant, an1.t, options)
    plan.diff = [
        a.to_dict()
        for a in d.apps
        if next((p.id for p in an1.t.access_policies if p.name == a.new_policy), None) in touched
        and a.verdict != "EQUIVALENT"
    ]
    if any(a["verdict"] in ("MORE_PERMISSIVE", "INCOMPARABLE") for a in plan.diff):
        plan.caveats.append(
            "the change makes some app MORE permissive for someone; see the impact lines before applying"
        )
    before_f = {_findings_key(f.to_dict()) for f in an.run().findings}
    after_f = an1.run().findings
    touched_names = {o.policy_name for o in ops}
    plan.new_findings = [
        f.to_dict()
        for f in after_f
        if _findings_key(f.to_dict()) not in before_f
        and f.severity in ("HIGH", "MEDIUM")
        and (f.policy in touched_names or f.policy is None)
    ]
    return plan


def _violations(res: InvariantResult) -> list[str]:
    out = []
    for r in res.results:
        if r.error:
            out.append(f"error ({r.policy.name}): {r.error}")
        elif not r.holds and not r.vacuous:
            out.append(f"{r.policy.name}: violated by rule {r.violating_rule!r} → {r.violating_outcome}")
            if r.counterexample:
                out.append(f"  counterexample: {r.counterexample}")
    return out


def _assertion_dict(a: Assertion) -> dict[str, Any]:
    from .invariants import _assertion_dict as f

    return f(a)


# ------------------------------------------------------------------------------------------ applying


@dataclass
class AppliedOp:
    op: str
    policy_id: str
    rule_id: str
    previous: dict[str, Any] | None = None  # update: body before; create: None
    response: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ApplyRecord:
    org_url: str
    sentence: str
    applied: list[AppliedOp]

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_url": self.org_url,
            "sentence": self.sentence,
            "applied": [a.to_dict() for a in self.applied],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ApplyRecord:
        return cls(
            d["org_url"],
            d.get("sentence", ""),
            [
                AppliedOp(a["op"], a["policy_id"], a["rule_id"], a.get("previous"), a.get("response"))
                for a in d["applied"]
            ],
        )


_API_RULE_KEYS = ("name", "priority", "status", "type", "conditions", "actions")


def api_body(rule: dict[str, Any]) -> dict[str, Any]:
    """The subset of a rule body Okta accepts on create/update (drops ids, links, system flags)."""
    body = {k: copy.deepcopy(rule[k]) for k in _API_RULE_KEYS if k in rule}
    body.setdefault("type", "ACCESS_POLICY")
    if body.get("conditions") is None:
        body.pop("conditions", None)
    return body


def apply_plan(client: Any, plan: FixPlan, *, activate: bool = True) -> ApplyRecord:
    """Execute the plan's operations against the org. Stops at the first error, returning what was done."""
    applied: list[AppliedOp] = []
    for op in plan.ops:
        body = api_body(op.rule)
        if not activate:
            body["status"] = "INACTIVE"
        if op.op == "create":
            resp = client.post(f"/api/v1/policies/{op.policy_id}/rules", json=body)
            rid = str(resp.get("id")) if isinstance(resp, dict) else ""
            applied.append(
                AppliedOp("create", op.policy_id, rid, None, resp if isinstance(resp, dict) else None)
            )
            if not activate and rid:
                client.post(f"/api/v1/policies/{op.policy_id}/rules/{rid}/lifecycle/deactivate", json=None)
        elif op.op == "update":
            assert op.rule_id
            resp = client.put(f"/api/v1/policies/{op.policy_id}/rules/{op.rule_id}", json=body)
            applied.append(
                AppliedOp(
                    "update",
                    op.policy_id,
                    op.rule_id,
                    api_body(op.previous or {}),
                    resp if isinstance(resp, dict) else None,
                )
            )
        else:
            raise ValueError(f"unknown op {op.op!r}")
    return ApplyRecord(getattr(client, "org_url", ""), plan.sentence, applied)


def rollback(client: Any, record: ApplyRecord) -> list[str]:
    """Undo an ApplyRecord: delete created rules, restore updated rules' previous bodies. Returns log lines."""
    log: list[str] = []
    for a in reversed(record.applied):
        if a.op == "create":
            client.delete(f"/api/v1/policies/{a.policy_id}/rules/{a.rule_id}")
            log.append(f"deleted rule {a.rule_id} from policy {a.policy_id}")
        elif a.op == "update" and a.previous:
            client.put(f"/api/v1/policies/{a.policy_id}/rules/{a.rule_id}", json=api_body(a.previous))
            log.append(f"restored rule {a.rule_id} in policy {a.policy_id}")
    return log


def load_snapshot_dict(d: dict[str, Any]) -> Tenant:
    return load_tenant(Snapshot.from_dict(d))


__all__ = [
    "AppliedOp",
    "ApplyRecord",
    "FixPlan",
    "PolicyType",
    "RuleOp",
    "api_body",
    "apply_ops_to_snapshot",
    "apply_plan",
    "conditions_from_when",
    "plan_fix",
    "rollback",
    "strengthen_rule",
    "synthesize_rule",
    "verification_method_for",
]
