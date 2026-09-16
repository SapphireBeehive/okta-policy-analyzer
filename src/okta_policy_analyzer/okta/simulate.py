"""Differential validation against Okta's own evaluator: ``POST /api/v1/policies/simulate``.

The simulation API (the engine behind the Admin Console's *Access Testing Tool*) tells us which policy and
rule Okta would apply for a principal (a set of group ids, or a real user) in a given context. We sample
worlds from the SMT model, translate each into a simulation request, and compare Okta's winning rule with the
rule our encoder predicts. Any disagreement is a bug in our semantics (or an under-specified context) and is
reported with the exact request so it can become a regression fixture.

Known limits (Okta docs): dynamic zones and custom expressions are not simulated; only one device assurance
id per request; the simulated groups must be assigned to the app (otherwise Okta answers 400).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import z3

from ..analysis import Analyzer
from ..interpreter import Interpreter, World
from ..model import App, Policy, Rule
from ..smt.sampling import sample_models, world_from_model
from .client import OktaAPIError, OktaClient

SIMULATE_PATH = "/api/v1/policies/simulate"


def simulation_request(
    app: App, world: World, *, policy_types: list[str] | None = None, user_id: str | None = None
) -> dict[str, Any]:
    ctx: dict[str, Any] = {}
    if user_id:
        ctx["user"] = {"id": user_id}
    else:
        ctx["groups"] = {"ids": sorted(world.groups)}
    if world.zones:
        ctx["zones"] = {"ids": sorted(world.zones)}
    dev: dict[str, Any] = {}
    if world.registered or world.managed:
        dev["registered"] = True
    if world.managed:
        dev["managed"] = True
    if world.platform and world.platform.value != "OTHER":
        dev["platform"] = world.platform.value
    if world.assurances:
        dev["assuranceId"] = sorted(world.assurances)[0]  # the API accepts a single id
    if dev:
        ctx["device"] = dev
    ctx["risk"] = {"level": world.risk.value}
    body: dict[str, Any] = {"appInstance": app.id, "policyContext": ctx}
    if policy_types:
        body["policyTypes"] = policy_types
    return body


@dataclass
class SimulationVerdict:
    policy_type: str
    policy_id: str | None
    rule_id: str | None
    raw: dict[str, Any] = field(default_factory=dict)


def parse_simulation_response(payload: Any) -> list[SimulationVerdict]:
    evaluations = payload.get("evaluation", payload) if isinstance(payload, dict) else payload
    out: list[SimulationVerdict] = []
    for ev in evaluations or []:
        ptype = ev.get("policyType")
        if isinstance(ptype, list):
            ptype = ptype[0] if ptype else None
        pols = ((ev.get("result") or {}).get("policies")) or []
        pol = next((p for p in pols if p.get("status") in (None, "MATCH")), pols[0] if pols else None)
        rule = None
        if pol:
            rules = pol.get("rules") or []
            rule = next((r for r in rules if r.get("status") in (None, "MATCH")), rules[0] if rules else None)
        out.append(
            SimulationVerdict(
                str(ptype), pol.get("id") if pol else None, rule.get("id") if rule else None, ev
            )
        )
    return out


def simulate(client: OktaClient, body: dict[str, Any]) -> list[SimulationVerdict]:
    """POST one simulation. Sends a single object (Okta's guide); falls back to an array on 400."""
    try:
        payload = client.post(f"{SIMULATE_PATH}?expand=EVALUATED&expand=RULE", body)
    except OktaAPIError as e:
        if e.status == 400 and "not allowed" in str(e.body):
            raise NotAssigned(str(e)) from e
        if e.status == 400:
            payload = client.post(f"{SIMULATE_PATH}?expand=EVALUATED&expand=RULE", [body])
        else:
            raise
    return parse_simulation_response(payload)


class NotAssigned(RuntimeError):
    """The simulated principal is not assigned to the app; Okta refuses to evaluate policies."""


@dataclass
class Mismatch:
    app: str
    world: str
    request: dict[str, Any]
    expected_policy: str | None
    expected_rule: str | None
    okta_policy: str | None
    okta_rule: str | None
    policy_type: str


@dataclass
class ValidationReport:
    app: str
    samples: int
    compared: int
    skipped_not_assigned: int
    skipped_unsupported: int
    mismatches: list[Mismatch]

    @property
    def inconclusive(self) -> bool:
        return self.compared == 0

    @property
    def ok(self) -> bool:
        return not self.mismatches and not self.inconclusive


def validate_app(
    analyzer: Analyzer,
    client: OktaClient,
    app: App,
    *,
    samples: int = 25,
    seed: int = 0,
    include_session: bool = True,
) -> ValidationReport:
    """Sample worlds, ask Okta, compare winners for the app's authentication policy (and the session policies)."""
    t = analyzer.t
    policy = t.access_policy_for_app(app.id)
    if policy is None:
        raise ValueError(f"app {app.label!r} has no authentication policy")
    it = Interpreter(t)
    u = analyzer.u
    # only worlds Okta can simulate: no opaque atoms true, no dynamic zones, at most one assurance policy
    dynamic = [z.id for z in t.zones.values() if z.type != "IP"]
    constraints: list[z3.BoolRef] = [z3.Not(v) for v in u.opaque_vars.values()]
    constraints += [z3.Not(u.zone[z]) for z in dynamic if z in u.zone]
    if len(u.assurance) > 1:
        constraints.append(z3.AtMost(*u.assurance.values(), 1))
    models = sample_models(u, analyzer.axioms, samples, seed=seed, extra=constraints)
    mismatches: list[Mismatch] = []
    compared = skipped_na = skipped_unsupported = 0
    for m in models:
        world = world_from_model(u, m)
        if world.user_id:  # simulate group-mode principals only
            world.user_id = None
        expected: dict[str, tuple[Policy, Rule] | None] = {
            "ACCESS_POLICY": (policy, it.first_matching_rule(policy, world) or None)
        }  # type: ignore[dict-item]
        if include_session:
            expected["OKTA_SIGN_ON"] = it.select(t.session_policies, world)
        body = simulation_request(app, world, policy_types=list(expected))
        try:
            verdicts = simulate(client, body)
        except NotAssigned:
            skipped_na += 1
            continue
        for v in verdicts:
            exp = expected.get(v.policy_type)
            if exp is None and v.policy_type not in expected:
                continue
            exp_pol, exp_rule = (exp[0].id, exp[1].id) if exp and exp[1] is not None else (None, None)
            if v.rule_id is None and v.policy_id is None:
                skipped_unsupported += 1  # UNDEFINED: Okta could not evaluate with the given context
                continue
            compared += 1
            if (v.policy_id, v.rule_id) != (exp_pol, exp_rule):
                mismatches.append(
                    Mismatch(
                        app.label, str(world), body, exp_pol, exp_rule, v.policy_id, v.rule_id, v.policy_type
                    )
                )
    return ValidationReport(app.label, len(models), compared, skipped_na, skipped_unsupported, mismatches)
