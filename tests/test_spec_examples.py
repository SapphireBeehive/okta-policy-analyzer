"""The loader and analyzer must accept the payload shapes in Okta's own OpenAPI examples."""

from __future__ import annotations

import json
from pathlib import Path

from okta_policy_analyzer.analysis import Analyzer
from okta_policy_analyzer.loader import load_tenant
from okta_policy_analyzer.model import Access, AccessAction, PolicyType, SignOnAction
from okta_policy_analyzer.okta.snapshot import Snapshot
from okta_policy_analyzer.smt.dnf import var_names

EX = Path(__file__).parent / "fixtures" / "spec_examples"


def _ex(name: str):
    return json.loads((EX / f"{name}.json").read_text())


def _as_list(x):
    return x if isinstance(x, list) else [x]


def build_spec_snapshot() -> Snapshot:
    access = _as_list(_ex("list-access-policy-response"))[0]
    access["id"] = "rst_spec"
    access["_rules"] = [
        {**_ex("create-auth-policy-rule-condition-response"), "id": "rul_cond"},
        {**_ex("update-auth-policy-rule-condition-response"), "id": "rul_upd", "priority": 1},
        {**_ex("oamp-id-proofing-policy-rule-response"), "id": "rul_idp", "priority": 2},
        *[{**r, "id": "rul_catch"} for r in _as_list(_ex("list-all-access-policy-rule-response"))],
    ]
    gsp = _as_list(_ex("list-okta-sign-on-policy-response"))[0]
    gsp["id"] = "gsp_spec"
    gsp["conditions"] = {"people": {"groups": {"include": ["00g_everyone"]}}}
    gsp["_rules"] = [
        {
            **_ex("deny-rule-response"),
            "id": "gr_deny",
            "conditions": {
                **_ex("deny-rule-response")["conditions"],
                "network": {"connection": "ZONE", "include": ["nzo9o4rctwQCJNE6y1d7"]},
            },
        },
        {**_ex("radius-rule-response"), "id": "gr_radius", "priority": 1},
        {**_ex("skip-factor-challenge-on-prem-rule-response"), "id": "gr_onprem", "priority": 2},
        {**_ex("sign-on-policy-rule-response"), "id": "gr_signon", "priority": 3},
        *[
            {**r, "id": "gr_default", "priority": 99, "system": True}
            for r in _as_list(_ex("list-all-sign-on-policy-rule-response"))
        ],
    ]
    mfa = _ex("mfa-enroll-policy-response")
    mfa["id"] = "mfa_spec"
    mfa["conditions"] = {"people": {"groups": {"include": ["00g_everyone"]}}}
    mfa["_rules"] = [
        {**r, "id": f"mr_{i}"}
        for i, r in enumerate(_as_list(_ex("list-all-mfa-enroll-policy-rule-response")))
    ]
    pwd = _ex("password-policy-response")
    pwd["id"] = "pwd_spec"
    pwd["_rules"] = []
    groups = [
        {"id": "00g_everyone", "type": "BUILT_IN", "profile": {"name": "Everyone"}},
        {"id": "00g9i12jictsYdZdi1d7", "type": "OKTA_GROUP", "profile": {"name": "Spec group"}},
        {"id": "groupId", "type": "OKTA_GROUP", "profile": {"name": "Placeholder group"}},
    ]
    zones = [
        {
            "id": "nzo9o4rctwQCJNE6y1d7",
            "name": "Spec zone",
            "type": "IP",
            "status": "ACTIVE",
            "usage": "POLICY",
        }
    ]
    user_types = [
        {"id": "otyezu4m0xN6w5JEa1d7", "name": "contractor", "displayName": "Contractor", "default": False}
    ]
    apps = [
        {
            "id": "0oa_spec",
            "label": "Spec App",
            "status": "ACTIVE",
            "_links": {"accessPolicy": {"href": "https://x.okta.com/api/v1/policies/rst_spec"}},
        }
    ]
    return Snapshot.from_dict(
        {
            "manifest": {"org_url": "https://x.okta.com", "pipeline": "idx"},
            "policies": [access, gsp, mfa, pwd],
            "apps": apps,
            "groups": groups,
            "zones": zones,
            "user_types": user_types,
            "authenticators": [],
        }
    )


def test_spec_examples_load_and_analyse() -> None:
    t = load_tenant(build_spec_snapshot())
    assert [p.type for p in t.access_policies] == [PolicyType.ACCESS_POLICY]
    pol = t.access_policies[0]
    rules = {r.id: r for r in pol.rules}
    cond = rules["rul_cond"]
    # object-shaped constraints and lower-case type names are normalised
    assert isinstance(cond.action, AccessAction) and cond.action.verification is not None
    cs = cond.action.verification.constraints
    assert (
        len(cs) == 1
        and cs[0].knowledge is not None
        and cs[0].knowledge.types == ["PASSWORD"]
        and cs[0].knowledge.reauthenticate_in == "PT2H"
    )
    assert cond.conditions.people is not None and cond.conditions.people.users_exclude == [
        "00u7yq5goxNFTiMjW1d7"
    ]
    assert cond.conditions.network is not None and cond.conditions.network.exclude == ["nzo9o4rctwQCJNE6y1d7"]
    assert cond.conditions.platform is not None and len(cond.conditions.platform.include) == 3
    assert cond.conditions.risk_level is None  # ANY
    assert cond.conditions.user_type is not None and cond.conditions.user_type.exclude == [
        "otyezu4m0xN6w5JEa1d7"
    ]
    assert cond.conditions.el is not None and cond.conditions.el.ast is not None
    # `conditions: null` catch-all
    assert rules["rul_catch"].system and rules["rul_catch"].conditions.people is None
    assert pol.rules[-1].id == "rul_catch"
    # ID_PROOFING is modelled (as 2FA) with a warning
    assert isinstance(rules["rul_idp"].action, AccessAction)
    assert any("ID_PROOFING" in w for w in t.warnings)

    gsp = t.session_policies[0]
    by = {r.id: r for r in gsp.rules}
    assert isinstance(by["gr_deny"].action, SignOnAction) and by["gr_deny"].action.access == Access.DENY
    assert by["gr_radius"].conditions.auth_type == "RADIUS"
    assert by["gr_onprem"].conditions.network is not None and by["gr_onprem"].conditions.network.include == [
        "00u7yq5goxNFTiMjW1d7"
    ]
    assert gsp.rules[-1].id == "gr_default"

    mfa = t.enrollment_policies[0]
    assert {s.key: s.enroll_self.value for s in mfa.authenticator_settings} == {
        "okta_email": "NOT_ALLOWED",
        "okta_verify": "OPTIONAL",
        "okta_password": "REQUIRED",
    }
    assert t.password_policies and t.password_policies[0].id == "pwd_spec"

    an = Analyzer(t)
    # the expression `security.risk.level == 'HIGH'` ties to the shared risk variable
    ep = an.enc.access_policy(pol)
    assert "risk" in var_names(ep.match[ep.rule_index("rul_cond")])
    res = an.run()
    assert res.stats["rules"] >= 4
    assert any(a.policy.id == "rst_spec" for a in res.access)
    assert res.session and res.enrollment
    assert res.to_json()
