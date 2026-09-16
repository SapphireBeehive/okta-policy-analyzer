from __future__ import annotations

import json

import pytest

from okta_policy_analyzer.analysis import AnalysisResult, Analyzer
from okta_policy_analyzer.assurance import Strength
from okta_policy_analyzer.model import Tenant


@pytest.fixture(scope="module")
def result(acme: Tenant) -> AnalysisResult:
    return Analyzer(acme).run()


def _kinds(result: AnalysisResult) -> dict[str, list]:
    out: dict[str, list] = {}
    for f in result.findings:
        out.setdefault(f.kind, []).append(f)
    return out


def test_expected_findings_present(result: AnalysisResult) -> None:
    k = _kinds(result)
    bypass = {f.rule: f for f in k["deny-bypassed"]}
    assert set(bypass) == {"Contractors elsewhere denied", "High risk denied"}
    # the intentional carve-out (contractors from corp/VPN) is not blamed for the contractor deny
    assert bypass["Contractors elsewhere denied"].data["bypassing_rules"] == ["Managed device passwordless"]
    assert set(bypass["High risk denied"].data["bypassing_rules"]) == {
        "Managed device passwordless",
        "Contractors from corp/VPN",
    }
    assert any("Contractors" in w for w in bypass["Contractors elsewhere denied"].who)

    shadowed = {f.rule for f in k["shadowed-rule"]}
    assert shadowed == {"Admins from corp (2FA)", "Catch-all Rule"}
    dash_dead = next(f for f in k["shadowed-rule"] if f.policy == "Okta Dashboard policy")
    assert dash_dead.severity == "INFO" and dash_dead.data["shadowed_by"] == ["Everyone 2FA"]
    admin_dead = next(f for f in k["shadowed-rule"] if f.rule == "Admins from corp (2FA)")
    assert admin_dead.data["shadowed_by"] == ["Admins phishing-resistant"]

    assert {f.rule for f in k["redundant-rule"]} == {"Everyone 2FA"}

    weak = k["weak-catch-all"]
    assert [f.policy for f in weak] == ["Legacy intranet policy"]

    gaps = {f.rule for f in k["unenrollable-requirement"]}
    assert {
        "Finance hardware-protected",
        "Finance phishing-resistant",
        "Admins phishing-resistant",
        "Managed device passwordless",
    } <= gaps
    fin = next(f for f in k["unenrollable-requirement"] if f.rule == "Finance hardware-protected")
    assert all("Finance" in w for w in fin.who)

    assert {f.rule for f in k["single-factor-rule"]} == {
        "Break-glass account",
        "Sales on mobile (custom expression)",
    }
    assert any(f.apps == ["Orphan App"] for f in k["app-without-policy"])
    assert {f.rule for f in k["dangling-group"]} == {"Executives", "Finance hardware-protected"}
    assert k["no-phishing-resistant-enrollment"][0].policy == "Finance enrollment"
    assert k["session-deny"][0].rule == "Deny from high-risk countries"
    assert (
        not k.get("policy-fall-through") and not k.get("shadowed-policy") and not k.get("no-session-policy")
    )
    assert result.findings == sorted(
        result.findings, key=lambda f: ["HIGH", "MEDIUM", "LOW", "INFO"].index(f.severity)
    )


def test_outcome_tables(result: AnalysisResult) -> None:
    by_id = {a.policy.id: a for a in result.access}
    admin = by_id["rst_admin"]
    assert admin.weakest == Strength.ONE_FA_KNOWLEDGE  # the break-glass user
    rows = {o.strength: o for o in admin.outcomes}
    assert rows[Strength.ONE_FA_KNOWLEDGE].who == ["is user breakglass@acme.com"]
    assert rows[Strength.TWO_FA_PHISHING_RESISTANT].who == [
        "member of Okta Administrators ∧ not member of Contractors"
    ]
    assert "member of Contractors" in rows[Strength.DENY].who

    std = by_id["rst_std"]
    assert std.app_labels == ["GitHub", "Salesforce"]
    rules = {r.rule.id: r for r in std.rules}
    managed = rules["rul_std_managed"]
    assert managed.who == ["not member of Service Accounts"]
    assert any("device managed" in w and "macOS secure" in w for w in managed.when)
    assert managed.strength == Strength.TWO_FA_PHISHING_RESISTANT
    assert not rules["rul_std_svc_deny"].shadowed_by and rules["rul_std_svc_deny"].reachable
    assert "Old rule (inactive)" in [r.name for r in std.inactive_rules]
    assert std.combined_weakest == Strength.ONE_FA_KNOWLEDGE

    dash = by_id["rst_dashboard"]
    assert dash.weakest == Strength.TWO_FA and dash.outcomes[0].who == ["everyone, in every context"]
    assert not dash.rules[1].reachable and dash.rules[1].shadowed_by[0].name == "Everyone 2FA"

    weak = by_id["rst_weak"]
    assert weak.weakest == Strength.ONE_FA_KNOWLEDGE and weak.combined_weakest == Strength.ONE_FA_KNOWLEDGE


def test_session_and_enrollment_families(result: AnalysisResult) -> None:
    names = [p.policy.name for p in result.session]
    assert names == ["Admins session policy", "Contractors session policy", "Default Policy"]
    assert all(p.decides for p in result.session)
    default = result.session[-1]
    assert default.rules[0].who == ["not member of Okta Administrators ∧ not member of Contractors"]
    admins = result.session[0]
    assert admins.rules[0].who == ["member of Okta Administrators"]
    assert "MFA=required (always)" in admins.rules[0].summary
    enroll = {p.policy.name: p for p in result.enrollment}
    assert enroll["Finance enrollment"].decides and enroll["Default Policy"].decides


def test_combined_rows_and_json(result: AnalysisResult) -> None:
    std = next(a for a in result.access if a.policy.id == "rst_std")
    # a contractor on VPN: contractor session policy (MFA) + 2FA app rule -> 2FA
    rows = [
        c
        for c in std.combined
        if c.session_policy.id == "gsp_contractors" and c.app_rule.id == "rul_std_contractor_corp"
    ]
    by_session_rule = {c.session_rule.name: c.strength for c in rows}
    # zones may overlap: a contractor on VPN who is also inside the high-risk dynamic zone is denied at sign-in
    assert by_session_rule == {
        "MFA per session": Strength.TWO_FA,
        "Deny from high-risk countries": Strength.DENY,
    }
    # sales 1FA rule under the default (passwordless-capable, no MFA) session policy stays 1FA
    row = next(
        c
        for c in std.combined
        if c.session_policy.id == "gsp_default" and c.app_rule.id == "rul_std_sales_mobile"
    )
    assert row.strength == Strength.ONE_FA_KNOWLEDGE
    # ... but a contractor cannot reach the sales rule at all (excluded by earlier rules)
    assert not any(
        c.session_policy.id == "gsp_contractors" and c.app_rule.id == "rul_std_sales_mobile"
        for c in std.combined
    )
    d = json.loads(result.to_json())
    assert d["stats"]["authentication_policies"] == 5
    assert d["authentication_policies"][0]["rules"][0]["name"]
    assert any(a.startswith("a managed device") for a in d["assumptions"])
