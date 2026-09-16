"""Regression tests for defects found in the adversarial review."""

from __future__ import annotations

import copy

import z3

from okta_policy_analyzer.analysis import Analyzer
from okta_policy_analyzer.assertions import Assertion, AssertionChecker
from okta_policy_analyzer.assurance import Catalogue, Strength, classify_rule, paths_for
from okta_policy_analyzer.loader import load_tenant
from okta_policy_analyzer.model import (
    Chain,
    ChainItem,
    ChainStep,
    Requirement,
    Tenant,
    VerificationMethod,
    VerificationType,
)
from okta_policy_analyzer.okta.snapshot import Snapshot

from .fixtures import acme as fx


def _snap_with(mutate) -> Snapshot:
    snap = Snapshot.from_dict(copy.deepcopy(fx.build_acme().to_dict()))
    mutate(snap)
    return snap


def test_behaviors_condition_is_loaded_and_gates_the_rule() -> None:
    def mutate(snap: Snapshot) -> None:
        for p in snap.policies:
            if p["id"] == fx.GSP_DEFAULT:
                p["_rules"].insert(
                    0,
                    {
                        "id": "gr_newdev",
                        "name": "New device -> DENY",
                        "priority": 0,
                        "status": "ACTIVE",
                        "type": "SIGN_ON",
                        "conditions": {"risk": {"behaviors": ["beh_newdevice"]}},
                        "actions": {"signon": {"access": "DENY"}},
                    },
                )

    t = load_tenant(_snap_with(mutate))
    gsp = t.policy(fx.GSP_DEFAULT)
    assert gsp is not None and gsp.rules[0].conditions.behaviors == ["beh_newdevice"]
    res = Analyzer(t).run()
    default = next(p for p in res.session if p.policy.id == fx.GSP_DEFAULT)
    # the default rule below the behaviour-gated DENY must still be reachable (behaviour is a free atom)
    assert all(r.reachable for r in default.rules)
    assert not [f for f in res.findings if f.kind == "dead-rule" and f.rule == "Default Rule"]


def test_network_without_connection_keeps_zones_and_classic_values_warn() -> None:
    snap = Snapshot.from_dict(
        {
            "manifest": {"org_url": "https://x.okta.com"},
            "groups": [{"id": "00g_all", "type": "BUILT_IN", "profile": {"name": "Everyone"}}],
            "zones": [{"id": "nzo1", "name": "Z", "type": "IP", "status": "ACTIVE", "usage": "POLICY"}],
            "policies": [
                {
                    "id": "p",
                    "type": "ACCESS_POLICY",
                    "name": "P",
                    "_rules": [
                        {
                            "id": "r1",
                            "name": "zone",
                            "priority": 0,
                            "conditions": {"network": {"include": ["nzo1"]}},
                            "actions": {"appSignOn": {"access": "DENY"}},
                        },
                        {
                            "id": "r2",
                            "name": "classic",
                            "priority": 1,
                            "conditions": {"network": {"connection": "ON_NETWORK"}},
                            "actions": {"appSignOn": {"access": "DENY"}},
                        },
                        {
                            "id": "r99",
                            "name": "Catch-all",
                            "priority": 99,
                            "system": True,
                            "actions": {
                                "appSignOn": {
                                    "access": "ALLOW",
                                    "verificationMethod": {"type": "ASSURANCE", "factorMode": "2FA"},
                                }
                            },
                        },
                    ],
                }
            ],
        }
    )
    t = load_tenant(snap)
    r1, r2, _ = t.access_policies[0].rules
    assert r1.conditions.network is not None and r1.conditions.network.include == ["nzo1"]
    assert "network" in r2.conditions.unsupported and any("ON_NETWORK" in w for w in t.warnings)


def test_chain_counts_distinct_factor_types_and_honours_item_flags(acme: Tenant) -> None:
    cat = Catalogue.for_tenant(acme)
    # password -> security question is ONE factor type
    vm = VerificationMethod(
        type=VerificationType.AUTH_METHOD_CHAIN,
        chains=[
            Chain(
                steps=[
                    ChainStep(items=[ChainItem("okta_password", "password")]),
                    ChainStep(items=[ChainItem("security_question", "security_question")]),
                ]
            )
        ],
    )
    paths = paths_for(vm, cat)
    assert paths and all(p.strength == Strength.ONE_FA_KNOWLEDGE for p in paths)
    # password -> FastPass with phishingResistant REQUIRED on the item -> 2FA phishing-resistant
    vm2 = VerificationMethod(
        type=VerificationType.AUTH_METHOD_CHAIN,
        chains=[
            Chain(
                steps=[
                    ChainStep(items=[ChainItem("okta_password", "password")]),
                    ChainStep(
                        items=[
                            ChainItem("okta_verify", "signed_nonce", phishing_resistant=Requirement.REQUIRED)
                        ]
                    ),
                ]
            )
        ],
    )
    paths2 = paths_for(vm2, cat)
    assert paths2 and all(p.strength == Strength.TWO_FA_PHISHING_RESISTANT for p in paths2)


def test_fastpass_is_phishing_resistant_only_when_required(acme: Tenant) -> None:
    cat = Catalogue.for_tenant(acme)
    rules = {r.id: r for p in acme.access_policies for r in p.rules}
    # "Admins phishing-resistant" requires PR -> FastPass counts; the managed-device rule too
    assert classify_rule(rules["rul_admin_pr"], cat).weakest == Strength.TWO_FA_PHISHING_RESISTANT
    # a 1FA possession-only rule without the PR requirement: FastPass alone is not a PR guarantee
    from okta_policy_analyzer.model import Constraint, ConstraintSet, FactorMode

    vm = VerificationMethod(
        factor_mode=FactorMode.ONE_FA,
        constraints=[
            ConstraintSet(
                possession=Constraint(
                    kind="POSSESSION", authentication_methods=[("okta_verify", "signed_nonce")]
                )
            )
        ],
    )
    (p,) = paths_for(vm, cat)
    assert not p.phishing_resistant and p.strength == Strength.ONE_FA_POSSESSION


def test_attribute_variables_are_bounded(acme: Tenant) -> None:
    an = Analyzer(acme)
    ep = an.enc.access_policy(acme.policy("rst_std"))  # type: ignore[arg-type]
    # the catch-all's WHO includes "department != Sales" style negations: must be a finite, complete enumeration
    i = ep.rule_index("rul_std_default")
    dnf = an.who(ep.effective[i])
    assert dnf.complete and not dnf.coarse
    assert not any("<any other value>" in line for line in an.lines(dnf)) or len(dnf.cubes) < 10
    u = an.u
    for path, v in u.attr_vars.items():
        s = z3.Solver()
        s.add(*an.axioms, v > len(u.attr_literals[path]))
        assert s.check() == z3.unsat


def test_assertion_premise_literals_get_axioms(acme: Tenant) -> None:
    """A premise that interns a new literal must not produce impossible counterexamples."""
    an = Analyzer(acme)
    before = an.u.revision
    checker = AssertionChecker(an)
    (r,) = checker.check(
        Assertion(
            name="x",
            apps=["Salesforce"],
            when={"attributes": {"department": "Marketing"}},
            expect={"min_strength": "TWO_FA"},
        )
    )
    assert an.u.revision > before  # a new literal was interned by the premise
    # the analyzer must have refreshed its axioms: the new literal's bound is present
    v = an.u.attr_vars["user.department"]
    s = z3.Solver()
    s.add(*an.axioms, v > len(an.u.attr_literals["user.department"]))
    assert s.check() == z3.unsat
    # and the counterexample (if any) must be consistent: department is Marketing in it
    if not r.holds and r.counterexample:
        assert "Marketing" in r.counterexample


def test_no_path_rule_is_not_the_weakest_way_in() -> None:
    def mutate(snap: Snapshot) -> None:
        # disable FIDO2 and Okta Verify: phishing-resistant rules become unsatisfiable (NO_PATH)
        for a in snap.authenticators:
            if a["key"] in ("webauthn", "okta_verify"):
                a["status"] = "INACTIVE"

    res = Analyzer(load_tenant(_snap_with(mutate))).run()
    admin = next(a for a in res.access if a.policy.id == fx.P_ADMIN)
    assert admin.weakest == Strength.ONE_FA_KNOWLEDGE  # the break-glass password path, not the NO_PATH rule
    assert any(f.kind == "unsatisfiable-rule" and f.rule == "Admins phishing-resistant" for f in res.findings)
    assert res.weakest_overall is not None


def test_redundant_deny_at_end_is_reported() -> None:
    snap = Snapshot.from_dict(
        {
            "manifest": {"org_url": "https://x.okta.com"},
            "groups": [
                {"id": "00g_all", "type": "BUILT_IN", "profile": {"name": "Everyone"}},
                {"id": "00g_a", "profile": {"name": "A"}},
            ],
            "policies": [
                {
                    "id": "p",
                    "type": "ACCESS_POLICY",
                    "name": "P",
                    "_rules": [
                        {
                            "id": "r1",
                            "name": "deny A",
                            "priority": 0,
                            "conditions": {"people": {"groups": {"include": ["00g_a"]}}},
                            "actions": {"appSignOn": {"access": "DENY"}},
                        },
                        {
                            "id": "r99",
                            "name": "Catch-all",
                            "priority": 99,
                            "system": True,
                            "actions": {"appSignOn": {"access": "DENY"}},
                        },
                    ],
                }
            ],
        }
    )
    res = Analyzer(load_tenant(snap)).run()
    assert any(f.kind == "redundant-rule" and f.rule == "deny A" for f in res.findings)


def test_bypass_uses_semantic_population_for_expression_defined_rules() -> None:
    """A carve-out written with an expression must not be reported as a bypass."""
    snap = Snapshot.from_dict(
        {
            "manifest": {"org_url": "https://x.okta.com"},
            "groups": [{"id": "00g_all", "type": "BUILT_IN", "profile": {"name": "Everyone"}}],
            "zones": [
                {"id": "nzo_corp", "name": "Corp", "type": "IP", "status": "ACTIVE", "usage": "POLICY"}
            ],
            "policies": [
                {
                    "id": "p",
                    "type": "ACCESS_POLICY",
                    "name": "P",
                    "_rules": [
                        {
                            "id": "r1",
                            "name": "contractors from corp",
                            "priority": 0,
                            "conditions": {
                                "elCondition": {"condition": "user.department == 'Contractor'"},
                                "network": {"connection": "ZONE", "include": ["nzo_corp"]},
                            },
                            "actions": {
                                "appSignOn": {
                                    "access": "ALLOW",
                                    "verificationMethod": {"type": "ASSURANCE", "factorMode": "2FA"},
                                }
                            },
                        },
                        {
                            "id": "r2",
                            "name": "contractors elsewhere denied",
                            "priority": 1,
                            "conditions": {"elCondition": {"condition": "user.department == 'Contractor'"}},
                            "actions": {"appSignOn": {"access": "DENY"}},
                        },
                        {
                            "id": "r99",
                            "name": "Catch-all",
                            "priority": 99,
                            "system": True,
                            "actions": {
                                "appSignOn": {
                                    "access": "ALLOW",
                                    "verificationMethod": {"type": "ASSURANCE", "factorMode": "2FA"},
                                }
                            },
                        },
                    ],
                }
            ],
        }
    )
    res = Analyzer(load_tenant(snap)).run()
    assert not [f for f in res.findings if f.kind == "deny-bypassed"]
