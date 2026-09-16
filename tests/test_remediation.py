"""Propose → verify-in-model → apply → rollback for plain-English invariants."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from okta_policy_analyzer.analysis import Analyzer
from okta_policy_analyzer.assertions import Assertion
from okta_policy_analyzer.cli import main
from okta_policy_analyzer.invariants import check_invariants
from okta_policy_analyzer.okta.client import OktaClient
from okta_policy_analyzer.remediation import (
    ApplyRecord,
    FixPlan,
    api_body,
    apply_ops_to_snapshot,
    apply_plan,
    conditions_from_when,
    plan_fix,
    rollback,
    verification_method_for,
)

from .fixtures import acme as fx

FIXTURE = str(Path(__file__).parent / "fixtures" / "acme")


# ------------------------------------------------------------------------------------------ synthesis


def test_conditions_from_when(acme) -> None:
    c = conditions_from_when(
        {
            "groups_any": ["Contractors"],
            "zones_none": ["Corporate Network", "VPN"],
            "managed": False,
            "platforms_any": ["MACOS", "IOS"],
            "risk": "HIGH",
            "attributes": {"user.department": "Finance"},
        },
        acme,
    )
    assert c["people"] == {"groups": {"include": [fx.G_CONTRACTORS]}}
    assert c["network"] == {"connection": "ZONE", "exclude": [fx.Z_CORP, fx.Z_VPN]}
    assert c["device"] == {"managed": False}
    assert c["platform"]["include"] == [
        {"type": "DESKTOP", "os": {"type": "OSX"}},
        {"type": "MOBILE", "os": {"type": "IOS"}},
    ]
    assert c["riskScore"] == {"level": "HIGH"}
    assert c["elCondition"] == {"condition": 'user.profile.department == "Finance"'}
    # exclusion-only premise includes Everyone so the rule applies to the rest
    c = conditions_from_when({"groups_none": ["Finance"]}, acme)
    assert c["people"]["groups"] == {"include": [fx.G_EVERYONE], "exclude": [fx.G_FINANCE]}
    # managed implies registered
    assert conditions_from_when({"managed": True}, acme)["device"] == {"managed": True, "registered": True}
    with pytest.raises(ValueError):
        conditions_from_when({"zones_any": ["VPN"], "zones_none": ["Corporate Network"]}, acme)
    with pytest.raises(ValueError):
        conditions_from_when({"groups_any": ["Nope"]}, acme)


def test_verification_method_for() -> None:
    vm = verification_method_for({"min_strength": "TWO_FA"})
    assert vm["factorMode"] == "2FA" and vm["constraints"] == []
    vm = verification_method_for({"min_strength": "TWO_FA_PHISHING_RESISTANT"}, {"reauthenticateIn": "PT8H"})
    assert vm["reauthenticateIn"] == "PT8H"
    assert vm["constraints"][0]["possession"]["phishingResistant"] == "REQUIRED"
    vm = verification_method_for({"min_strength": "TWO_FA_PHISHING_RESISTANT_HARDWARE"})
    assert vm["constraints"][0]["possession"]["hardwareProtection"] == "REQUIRED"
    vm = verification_method_for({"min_strength": "ONE_FA_POSSESSION"})
    assert vm["factorMode"] == "1FA" and "possession" in vm["constraints"][0]
    vm = verification_method_for({"passwordless": False})
    assert vm["constraints"][0]["knowledge"]["types"] == ["PASSWORD"]


# ------------------------------------------------------------------------------------------ planning


@pytest.fixture(scope="module")
def snapshot():
    return fx.build_acme()


def test_plan_deny_rule_is_proved_and_shows_impact(snapshot) -> None:
    plan = plan_fix(snapshot, "Contractors can only reach Salesforce from the Corporate Network or VPN")
    assert plan.status == "FIX_PROVED" and plan.before == "VIOLATED" and plan.after == "PROVED"
    (op,) = plan.ops
    assert op.op == "create" and op.policy_id == fx.P_STD
    assert op.rule["actions"] == {"appSignOn": {"access": "DENY"}}
    assert op.rule["conditions"]["people"]["groups"]["include"] == [fx.G_CONTRACTORS]
    assert op.rule["conditions"]["network"] == {"connection": "ZONE", "exclude": [fx.Z_CORP, fx.Z_VPN]}
    # formal impact: contractors lose access on both apps of the policy, nobody gains anything
    apps = {d["app"]: d for d in plan.diff}
    assert set(apps) == {"Salesforce", "GitHub"}
    assert all(d["verdict"] == "LESS_PERMISSIVE" for d in apps.values())
    assert any("Contractors" in w for w in apps["Salesforce"]["lost_access"])
    assert not any("MORE permissive" in c for c in plan.caveats)
    # the old DENY rule becomes dead, and the plan says so
    assert any("can never apply" in f["title"] for f in plan.new_findings)
    text = plan.to_text()
    assert "CREATE rule" in text and "after the change the invariant is: PROVED" in text
    # JSON round trip
    plan2 = FixPlan.from_dict(json.loads(plan.to_json()))
    assert plan2.status == "FIX_PROVED" and plan2.ops[0].rule == op.rule


def test_plan_strengthens_violating_rule(snapshot) -> None:
    plan = plan_fix(snapshot, "Executives must use phishing-resistant MFA for Payroll (Workday)")
    assert plan.status == "FIX_PROVED"
    (op,) = plan.ops
    assert op.op == "update" and op.rule_id == "rul_pay_exec" and op.previous is not None
    vm = op.rule["actions"]["appSignOn"]["verificationMethod"]
    assert vm["constraints"][0]["possession"]["phishingResistant"] == "REQUIRED"
    assert op.previous["actions"]["appSignOn"]["verificationMethod"]["constraints"] == []
    (d,) = plan.diff
    assert d["verdict"] == "LESS_PERMISSIVE" and d["stronger"] and not d["lost_access"]


def test_plan_iterates_over_several_policies(snapshot) -> None:
    plan = plan_fix(snapshot, "Nobody can access any app with only a password")
    assert plan.status == "FIX_PROVED"
    assert {o.op for o in plan.ops} == {"update"}
    assert {o.rule_id for o in plan.ops} >= {
        "rul_admin_breakglass",
        "rul_std_sales_mobile",
        "rul_weak_default",
    }
    assert any("catch-all" in c for c in plan.caveats)


def test_plan_allow_rule_is_flagged(snapshot) -> None:
    plan = plan_fix(snapshot, "Everyone must be able to access Legacy Intranet")
    assert plan.status == "FIX_PROVED"
    assert plan.ops[0].rule["actions"]["appSignOn"]["access"] == "ALLOW"
    assert any("MORE permissive" in c for c in plan.caveats)
    assert any(d["new_access"] for d in plan.diff)


def test_plan_statuses(snapshot) -> None:
    assert (
        plan_fix(
            snapshot, "Okta Administrators must use phishing-resistant MFA for the Okta Admin Console"
        ).status
        == "ALREADY_HOLDS"
    )
    p = plan_fix(snapshot, "Rule 'Break-glass account' must never apply for Okta Admin Console")
    assert p.status == "UNFIXABLE" and not p.ops
    assert plan_fix(snapshot, "Marketing must use MFA for Salesforce").status == "UNPARSED"


def test_patched_snapshot_keeps_rule_order(snapshot) -> None:
    plan = plan_fix(snapshot, "Only Finance can access Payroll (Workday)")
    patched = apply_ops_to_snapshot(snapshot, plan.ops)
    pol = next(p for p in patched.policies if p["id"] == fx.P_PAYROLL)
    prios = [r["priority"] for r in pol["_rules"] if not r.get("system")]
    assert pol["_rules"][0]["name"].startswith("Deny:") and len(set(prios)) == len(prios)
    assert prios[0] == min(prios)
    # the original snapshot is untouched
    orig = next(p for p in snapshot.policies if p["id"] == fx.P_PAYROLL)
    assert not orig["_rules"][0]["name"].startswith("Deny:")
    (res,) = check_invariants(Analyzer.from_snapshot(patched), ["Only Finance can access Payroll (Workday)"])
    assert res.verdict == "PROVED"


# ------------------------------------------------------------------------------------------ apply / rollback


class _FakeOkta:
    """Records rule writes the way Okta would answer them."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict | None]] = []
        self.rules: dict[str, dict] = {}
        self.n = 0

    def handler(self, req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content) if req.content else None
        self.calls.append((req.method, req.url.path, body))
        parts = req.url.path.split("/")
        if req.method == "POST" and parts[-1] == "rules":
            self.n += 1
            rid = f"rul_new_{self.n}"
            self.rules[rid] = dict(body, id=rid)
            return httpx.Response(200, json=self.rules[rid])
        if req.method == "POST" and parts[-1] == "deactivate":
            return httpx.Response(204)
        if req.method == "PUT":
            rid = parts[-1]
            self.rules[rid] = dict(body, id=rid)
            return httpx.Response(200, json=self.rules[rid])
        if req.method == "DELETE":
            self.rules.pop(parts[-1], None)
            return httpx.Response(204)
        return httpx.Response(404, json={"errorSummary": "no"})


def test_apply_and_rollback(snapshot) -> None:
    fake = _FakeOkta()
    client = OktaClient("https://acme.okta.com", api_token="t", transport=httpx.MockTransport(fake.handler))
    plan = plan_fix(snapshot, "Contractors can only reach Salesforce from the Corporate Network or VPN")
    plan2 = plan_fix(snapshot, "Executives must use phishing-resistant MFA for Payroll (Workday)")
    plan.ops += plan2.ops
    record = apply_plan(client, plan)
    methods = [(m, p) for m, p, _ in fake.calls]
    assert methods == [
        ("POST", f"/api/v1/policies/{fx.P_STD}/rules"),
        ("PUT", f"/api/v1/policies/{fx.P_PAYROLL}/rules/rul_pay_exec"),
    ]
    post_body = fake.calls[0][2]
    assert set(post_body) <= {"name", "priority", "status", "type", "conditions", "actions"}
    assert "id" not in post_body and post_body["type"] == "ACCESS_POLICY"
    assert [a.op for a in record.applied] == ["create", "update"]
    assert record.applied[0].rule_id == "rul_new_1"
    assert record.applied[1].previous == api_body(plan2.ops[0].previous)
    # record round-trips and rollback undoes in reverse order
    record2 = ApplyRecord.from_dict(json.loads(record.to_json()))
    fake.calls.clear()
    log = rollback(client, record2)
    assert [(m, p) for m, p, _ in fake.calls] == [
        ("PUT", f"/api/v1/policies/{fx.P_PAYROLL}/rules/rul_pay_exec"),
        ("DELETE", f"/api/v1/policies/{fx.P_STD}/rules/rul_new_1"),
    ]
    assert fake.calls[0][2]["actions"]["appSignOn"]["verificationMethod"]["constraints"] == []
    assert "rul_new_1" not in fake.rules and len(log) == 2


def test_apply_inactive_deactivates_created_rule(snapshot) -> None:
    fake = _FakeOkta()
    client = OktaClient("https://acme.okta.com", api_token="t", transport=httpx.MockTransport(fake.handler))
    plan = plan_fix(snapshot, "Only Finance can access Payroll (Workday)")
    apply_plan(client, plan, activate=False)
    assert [(m, p.rsplit("/", 1)[-1]) for m, p, _ in fake.calls] == [
        ("POST", "rules"),
        ("POST", "deactivate"),
    ]
    assert fake.calls[0][2]["status"] == "INACTIVE"


# ------------------------------------------------------------------------------------------ CLI


def test_cli_propose_apply_rollback(tmp_path, capsys, monkeypatch) -> None:
    plan_path = tmp_path / "plan.json"
    patched = tmp_path / "patched"
    rc = main(
        [
            "propose",
            FIXTURE,
            "Only Finance can access Payroll (Workday)",
            "--plan-out",
            str(plan_path),
            "--patched-snapshot",
            str(patched),
            "--rule-name",
            "CorpSec: payroll is Finance only",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "FIX_PROVED" in out and "CorpSec: payroll is Finance only" in out
    assert (patched / "policies.json").exists()
    plan = json.loads(plan_path.read_text())
    assert (
        plan["status"] == "FIX_PROVED"
        and plan["ops"][0]["rule"]["name"] == "CorpSec: payroll is Finance only"
    )
    # the patched snapshot proves the invariant with the ordinary check command
    assert main(["check", str(patched), "Only Finance can access Payroll (Workday)"]) == 0

    # apply: dry-run never needs credentials; without --yes it refuses
    assert main(["apply", str(plan_path), "--dry-run"]) == 0
    assert "dry run: nothing sent" in capsys.readouterr().out
    monkeypatch.delenv("OKTA_API_TOKEN", raising=False)
    monkeypatch.delenv("OKTA_ACCESS_TOKEN", raising=False)
    assert main(["apply", str(plan_path), "--org", "https://acme.okta.com"]) == 2
    # a plan that is not FIX_PROVED is refused without --force
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(dict(plan, after="VIOLATED")))
    assert main(["apply", str(bad), "--dry-run"]) == 2
    # unparseable / unfixable exit codes
    assert main(["propose", FIXTURE, "Marketing must use MFA for Salesforce"]) == 2
    assert (
        main(["propose", FIXTURE, "Rule 'Break-glass account' must never apply for Okta Admin Console"]) == 1
    )
    # rollback dry-run from a record
    rec = tmp_path / "rec.json"
    rec.write_text(
        json.dumps(
            {
                "org_url": "https://acme.okta.com",
                "sentence": "x",
                "applied": [{"op": "create", "policy_id": fx.P_PAYROLL, "rule_id": "rul_new_1"}],
            }
        )
    )
    assert main(["rollback", str(rec), "--dry-run"]) == 0
    assert "DELETE" in capsys.readouterr().out
    assert main(["rollback", str(rec)]) == 2


def test_assertion_import_kept() -> None:  # the plan's assertion dict re-loads as an Assertion
    a = Assertion.from_dict(
        {
            "name": "x",
            "apps": ["Payroll (Workday)"],
            "when": {"groups_none": ["Finance"]},
            "expect": {"access": "DENY"},
        }
    )
    assert a.when == {"groups_none": ["Finance"]}
