from __future__ import annotations

from pathlib import Path

from okta_policy_analyzer.analysis import Analyzer
from okta_policy_analyzer.assertions import AssertionChecker, load_assertions
from okta_policy_analyzer.model import Tenant

ASSERTIONS = Path(__file__).parent / "fixtures" / "acme_assertions.yaml"


def test_assertions_on_fixture(acme: Tenant) -> None:
    an = Analyzer(acme)
    checker = AssertionChecker(an)
    results = checker.check_all(load_assertions(str(ASSERTIONS)))
    by_name: dict[str, list] = {}
    for r in results:
        by_name.setdefault(r.assertion.name, []).append(r)

    # violated: managed-device bypass
    (ctr,) = [r for r in by_name["contractors-denied-off-network"] if r.policy.id == "rst_std"]
    assert not ctr.holds and ctr.violating_rule == "Managed device passwordless"
    assert ctr.counterexample and "Contractors" in ctr.counterexample and "managed" in ctr.counterexample
    assert any("Contractors" in w for w in ctr.who)

    # holds: admins always PR (contractor admins are denied, which is fine)
    (adm,) = by_name["admins-phishing-resistant"]
    assert adm.holds and not adm.vacuous

    (svc,) = by_name["service-accounts-never-interactive"]
    assert svc.holds

    (pay,) = by_name["payroll-needs-two-factors"]
    assert pay.holds

    weak = {r.policy.id: r for r in by_name["no-password-only-anywhere"]}
    assert not weak["rst_weak"].holds and weak["rst_weak"].violating_rule == "Catch-all Rule"
    assert not weak["rst_admin"].holds and weak["rst_admin"].violating_rule == "Break-glass account"
    assert (
        not weak["rst_std"].holds and weak["rst_std"].violating_rule == "Sales on mobile (custom expression)"
    )
    assert weak["rst_dashboard"].holds and weak["rst_payroll"].holds

    (risk,) = by_name["high-risk-always-denied"]
    assert not risk.holds and risk.violating_rule in (
        "Managed device passwordless",
        "Contractors from corp/VPN",
    )

    (managed,) = by_name["managed-device-rule-is-what-fires"]
    assert managed.holds

    (dash,) = by_name["dashboard-with-session-policy"]
    assert dash.holds

    (vac,) = by_name["vacuous-premise"]
    assert vac.holds and vac.vacuous


def test_unknown_names_are_reported(acme: Tenant) -> None:
    from okta_policy_analyzer.assertions import Assertion

    checker = AssertionChecker(Analyzer(acme))
    (r,) = checker.check(Assertion(name="x", apps=["Nope"], expect={"access": "DENY"}))
    assert not r.holds and r.error and "unknown app" in r.error
    (r,) = checker.check(
        Assertion(name="y", apps=["Salesforce"], when={"groups_any": ["Ghosts"]}, expect={"access": "DENY"})
    )
    assert r.error and "unknown group" in r.error
