from __future__ import annotations

import json
from pathlib import Path

from okta_policy_analyzer.loader import load_tenant
from okta_policy_analyzer.model import (
    Access,
    AccessAction,
    DevicePlatform,
    EnrollStatus,
    FactorMode,
    PolicyType,
    PrimaryFactor,
    Requirement,
    RiskLevel,
    SignOnAction,
    Status,
    Tenant,
)
from okta_policy_analyzer.okta.snapshot import Snapshot

from .fixtures import acme as fx

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "acme"


def test_checked_in_fixture_matches_builder(acme_snapshot: Snapshot) -> None:
    """The JSON snapshot in tests/fixtures/acme must be regenerated when the builder changes."""
    on_disk = Snapshot.load(FIXTURE_DIR)
    assert on_disk.to_dict() == acme_snapshot.to_dict(), (
        "run: python tests/fixtures/acme.py tests/fixtures/acme"
    )


def test_inventory(acme: Tenant) -> None:
    assert acme.org_url == fx.ORG
    assert acme.everyone_group_id == fx.G_EVERYONE
    assert acme.groups[fx.G_ADMINS].name == "Okta Administrators"
    assert acme.groups[fx.G_EVERYONE].is_everyone
    assert acme.zones[fx.Z_BLOCKED].usage == "BLOCKLIST" and acme.zones[fx.Z_BLOCKED].system
    assert acme.zones[fx.Z_HIGHRISK].type == "DYNAMIC" and "KP" in acme.zones[fx.Z_HIGHRISK].summary
    assert acme.device_assurances[fx.DA_MAC].platform == DevicePlatform.MACOS
    assert acme.authenticators["phone_number"].active_methods() == ["sms"]
    assert acme.authenticators["google_otp"].status == Status.INACTIVE
    assert acme.user_types[fx.UT_DEFAULT].default is True
    assert acme.apps[fx.APP_SFDC].access_policy_id == fx.P_STD
    assert acme.apps[fx.APP_ORPHAN].access_policy_id is None
    assert len(acme.users) == 6


def test_group_rules(acme: Tenant) -> None:
    by_id = {g.id: g for g in acme.group_rules}
    assert by_id["grr_finance"].expr_ast is not None and by_id["grr_finance"].target_group_ids == [
        fx.G_FINANCE
    ]
    assert by_id["grr_us"].exclude_user_ids == [fx.U_BREAKGLASS]
    assert by_id["grr_inactive"].status == Status.INACTIVE


def test_policies_sorted_and_mapped(acme: Tenant) -> None:
    assert [p.id for p in acme.access_policies] == [fx.P_ADMIN, fx.P_DASH, fx.P_STD, fx.P_PAYROLL, fx.P_WEAK]
    assert [p.id for p in acme.session_policies] == [fx.GSP_ADMINS, fx.GSP_CONTRACTORS, fx.GSP_DEFAULT]
    assert acme.session_policies[-1].system and acme.session_policies[-1].group_include == [fx.G_EVERYONE]
    assert [p.id for p in acme.enrollment_policies] == [fx.MFA_FINANCE, fx.MFA_DEFAULT]
    std = acme.policy(fx.P_STD)
    assert std is not None and std.type == PolicyType.ACCESS_POLICY
    assert std.app_ids == [fx.APP_GITHUB, fx.APP_SFDC]
    assert acme.access_policy_for_app(fx.APP_GITHUB) is std


def test_rule_order_and_catch_all_last(acme: Tenant) -> None:
    std = acme.policy(fx.P_STD)
    assert std is not None
    names = [r.name for r in std.rules]
    assert names[0] == "Service accounts denied" and names[-1] == "Catch-all Rule"
    assert std.rules[-1].system
    assert [r.name for r in std.active_rules()] == [n for n in names if n != "Old rule (inactive)"]


def test_conditions_and_actions(acme: Tenant) -> None:
    std = acme.policy(fx.P_STD)
    assert std is not None
    rules = {r.id: r for r in std.rules}
    managed = rules["rul_std_managed"]
    assert managed.conditions.device is not None
    assert managed.conditions.device.managed is True and managed.conditions.device.registered is True
    assert managed.conditions.device.assurance_include == [fx.DA_MAC, fx.DA_WIN]
    assert isinstance(managed.action, AccessAction) and managed.action.access == Access.ALLOW
    vm = managed.action.verification
    assert vm is not None and vm.factor_mode == FactorMode.TWO_FA and vm.reauthenticate_in == "PT43800H"
    poss = vm.constraints[0].possession
    assert poss is not None
    assert poss.phishing_resistant == Requirement.REQUIRED
    assert poss.device_bound == Requirement.REQUIRED
    assert poss.user_presence == Requirement.REQUIRED
    assert poss.hardware_protection == Requirement.OPTIONAL

    ctr = rules["rul_std_contractor_corp"]
    assert ctr.conditions.network is not None and ctr.conditions.network.include == [fx.Z_CORP, fx.Z_VPN]
    assert ctr.conditions.people is not None and ctr.conditions.people.groups_include == [fx.G_CONTRACTORS]

    assert rules["rul_std_high_risk"].conditions.risk_level == RiskLevel.HIGH
    assert isinstance(rules["rul_std_high_risk"].action, AccessAction)
    assert rules["rul_std_high_risk"].action.access == Access.DENY
    assert rules["rul_std_high_risk"].action.verification is None

    el = rules["rul_std_sales_mobile"].conditions.el
    assert el is not None and el.ast is not None and el.parse_error is None

    fin = rules["rul_std_finance_hw"].conditions.people
    assert fin is not None and fin.groups_exclude == [fx.G_DELETED]

    one_fa = rules["rul_std_default"]
    assert isinstance(one_fa.action, AccessAction) and one_fa.action.verification is not None
    assert one_fa.action.verification.factor_mode == FactorMode.TWO_FA

    # network ANYWHERE and people with only empty lists normalise to None
    admin = acme.policy(fx.P_ADMIN)
    assert admin is not None
    pr = {r.id: r for r in admin.rules}["rul_admin_pr"]
    assert pr.conditions.network is None
    gsp_admin_rule = acme.policy(fx.GSP_ADMINS).rules[0]  # type: ignore[union-attr]
    assert gsp_admin_rule.conditions.people is None and gsp_admin_rule.conditions.auth_type is None


def test_signon_actions(acme: Tenant) -> None:
    admins = acme.policy(fx.GSP_ADMINS)
    assert admins is not None
    a = admins.rules[0].action
    assert isinstance(a, SignOnAction)
    assert a.require_factor and a.factor_prompt_mode is not None and a.factor_prompt_mode.value == "ALWAYS"
    assert a.max_session_idle_minutes == 60 and a.max_session_lifetime_minutes == 480
    ctr = acme.policy(fx.GSP_CONTRACTORS)
    assert ctr is not None
    deny, mfa = ctr.rules
    assert isinstance(deny.action, SignOnAction) and deny.action.access == Access.DENY
    assert deny.conditions.network is not None and deny.conditions.network.include == [fx.Z_HIGHRISK]
    assert isinstance(mfa.action, SignOnAction) and mfa.action.factor_lifetime == 720
    default = acme.policy(fx.GSP_DEFAULT)
    assert default is not None
    d = default.rules[0].action
    assert (
        isinstance(d, SignOnAction)
        and d.primary_factor == PrimaryFactor.PASSWORD_IDP_ANY_FACTOR
        and not d.require_factor
    )


def test_enrollment_settings(acme: Tenant) -> None:
    fin = acme.policy(fx.MFA_FINANCE)
    assert fin is not None
    settings = {s.key: s.enroll_self for s in fin.authenticator_settings}
    assert settings["webauthn"] == EnrollStatus.NOT_ALLOWED
    assert settings["okta_verify"] == EnrollStatus.NOT_ALLOWED
    assert settings["phone_number"] == EnrollStatus.REQUIRED


def test_warnings_for_dangling_references(acme: Tenant) -> None:
    assert any(fx.G_DELETED in w and "does not exist" in w for w in acme.warnings)


def test_loader_tolerates_unknown_shapes() -> None:
    snap = Snapshot.from_dict(
        {
            "manifest": {"org_url": "https://x.okta.com"},
            "policies": [
                {
                    "id": "p1",
                    "type": "ACCESS_POLICY",
                    "name": "P",
                    "priority": 1,
                    "_rules": [
                        {
                            "id": "r1",
                            "name": "weird",
                            "priority": 0,
                            "status": "ACTIVE",
                            "conditions": {
                                "people": {"groups": {"include": ["g"]}},
                                "mystery": {"x": 1},
                                "riskScore": {"level": "BANANA"},
                            },
                            "actions": {"appSignOn": {"access": "ALLOW"}},
                        },
                        {
                            "id": "r2",
                            "name": "el",
                            "priority": 1,
                            "conditions": {"elCondition": {"condition": "user.x == "}},
                            "actions": {"appSignOn": {"access": "DENY"}},
                        },
                    ],
                },
                {
                    "id": "p2",
                    "type": "SOMETHING_NEW",
                    "name": "N",
                    "_rules": [{"id": "r", "name": "r", "actions": {"foo": 1}}],
                },
            ],
            "groups": [],
        }
    )
    t = load_tenant(snap)
    r1, r2 = t.access_policies[0].rules
    assert r1.conditions.unsupported == {"mystery": {"x": 1}}
    assert r1.conditions.risk_level is None
    assert isinstance(r1.action, AccessAction) and r1.action.verification is not None
    assert r1.action.verification.factor_mode == FactorMode.ONE_FA
    assert r2.conditions.el is not None and r2.conditions.el.ast is None and r2.conditions.el.parse_error
    assert t.other_policies[0].type == PolicyType.OTHER
    assert any("unsupported condition 'mystery'" in w for w in t.warnings)
    assert any("Everyone" in w for w in t.warnings)
    assert json.dumps(t.warnings)  # serialisable


def test_account_management_policy_is_separated_and_priority_ties_warn() -> None:
    snap = Snapshot.from_dict(
        {
            "manifest": {"org_url": "https://x.okta.com", "pipeline": "idx"},
            "groups": [{"id": "00g_all", "type": "BUILT_IN", "profile": {"name": "Everyone"}}],
            "policies": [
                {
                    "id": "rst_acct",
                    "type": "ACCESS_POLICY",
                    "name": "Okta Account Management Policy",
                    "priority": 1,
                    "_resourceType": "END_USER_ACCOUNT_MANAGEMENT",
                    "_rules": [
                        {
                            "id": "r0",
                            "name": "Catch-all",
                            "priority": 99,
                            "system": True,
                            "actions": {"appSignOn": {"access": "ALLOW"}},
                        }
                    ],
                },
                {
                    "id": "rst_app",
                    "type": "ACCESS_POLICY",
                    "name": "App",
                    "priority": 2,
                    "_rules": [
                        {
                            "id": "rb",
                            "name": "B",
                            "priority": 0,
                            "created": "2024-02-01T00:00:00Z",
                            "actions": {"appSignOn": {"access": "DENY"}},
                        },
                        {
                            "id": "ra",
                            "name": "A",
                            "priority": 0,
                            "created": "2024-01-01T00:00:00Z",
                            "actions": {"appSignOn": {"access": "ALLOW"}},
                        },
                        {
                            "id": "r99",
                            "name": "Catch-all",
                            "priority": 99,
                            "system": True,
                            "actions": {"appSignOn": {"access": "DENY"}},
                        },
                    ],
                },
            ],
        }
    )
    t = load_tenant(snap)
    assert [p.id for p in t.access_policies] == ["rst_app"]
    assert [p.id for p in t.account_management_policies] == ["rst_acct"]
    assert t.account_management_policies[0].is_account_management
    assert [r.id for r in t.access_policies[0].rules] == ["ra", "rb", "r99"]  # tie broken by creation time
    assert any("share priority 0" in w for w in t.warnings)
    assert any("account management policy" in w for w in t.warnings)
