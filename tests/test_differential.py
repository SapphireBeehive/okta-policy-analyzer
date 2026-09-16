"""Differential testing: the SMT encoding must agree with the reference interpreter on random worlds."""

from __future__ import annotations

import z3

from okta_policy_analyzer.interpreter import Interpreter
from okta_policy_analyzer.model import Tenant
from okta_policy_analyzer.smt import PolicyEncoder, Universe
from okta_policy_analyzer.smt.sampling import sample_models, world_from_model


def _truth(model: z3.ModelRef, f: z3.BoolRef) -> bool:
    return z3.is_true(model.eval(f, model_completion=True))


def test_access_policies_agree_with_interpreter(acme: Tenant) -> None:
    u = Universe(acme)
    enc = PolicyEncoder(u)
    encoded = [enc.access_policy(p) for p in acme.access_policies]
    axioms = u.axioms()
    it = Interpreter(acme)
    models = sample_models(u, axioms, 250, seed=1)
    checked = 0
    for m in models:
        w = world_from_model(u, m)
        for ep in encoded:
            fired = [i for i, eff in enumerate(ep.effective) if _truth(m, eff)]
            assert len(fired) <= 1, "first-match encoding must select at most one rule"
            expected = it.first_matching_rule(ep.policy, w)
            got = ep.rules[fired[0]] if fired else None
            assert got is expected, (
                f"{ep.policy.name}: encoder={got and got.name} interpreter={expected and expected.name} world={w}"
            )
            # every rule's match formula agrees too
            for i, r in enumerate(ep.rules):
                assert _truth(m, ep.match[i]) == it.rule_matches(r, w), f"match mismatch for {r.name}: {w}"
            checked += 1
    assert checked > 0


def test_prioritised_families_agree_with_interpreter(acme: Tenant) -> None:
    u = Universe(acme)
    enc = PolicyEncoder(u)
    families = {
        "session": (enc.session_policies, acme.session_policies),
        "enrollment": (enc.enrollment_policies, acme.enrollment_policies),
    }
    axioms = u.axioms()
    it = Interpreter(acme)
    for m in sample_models(u, axioms, 200, seed=2):
        w = world_from_model(u, m)
        for name, (encoded, policies) in families.items():
            decided = [(ep, i) for ep in encoded for i, _ in enumerate(ep.rules) if _truth(m, ep.decides(i))]
            assert len(decided) <= 1, f"{name}: more than one deciding rule"
            expected = it.select(policies, w)
            if expected is None:
                assert not decided
            else:
                assert decided, (
                    f"{name}: interpreter chose {expected[0].name}/{expected[1].name}, encoder nothing: {w}"
                )
                ep, i = decided[0]
                assert ep.policy is expected[0] and ep.rules[i] is expected[1], (
                    f"{name}: encoder={ep.policy.name}/{ep.rules[i].name} interpreter={expected[0].name}/{expected[1].name}"
                )


def test_group_rule_axioms_hold_in_interpreter(acme: Tenant) -> None:
    """In every sampled world, the interpreter's group rules agree with the model's memberships."""
    from okta_policy_analyzer.interpreter import active_group_rule_closure

    u = Universe(acme)
    axioms = u.axioms()
    for m in sample_models(u, axioms, 150, seed=3):
        w = world_from_model(u, m)
        if any(v == "<other>" for v in w.attrs.values()):
            continue  # concrete evaluation of "some other value" is not defined
        added = active_group_rule_closure(acme, w)
        assert added <= w.groups, f"group rule targets {added - w.groups} missing from world {w}"
