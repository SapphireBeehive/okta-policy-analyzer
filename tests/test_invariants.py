"""Plain-English invariants: parsing, formal readings and verdicts on the ACME fixture."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from okta_policy_analyzer.analysis import Analyzer
from okta_policy_analyzer.cli import main
from okta_policy_analyzer.invariants import check_invariants, explain_result, parse_invariant, reading

FIXTURE = str(Path(__file__).parent / "fixtures" / "acme")


@pytest.fixture(scope="module")
def analyzer(acme_snapshot) -> Analyzer:
    return Analyzer.from_snapshot(acme_snapshot)


def _one(analyzer: Analyzer, sentence: str):
    (res,) = check_invariants(analyzer, [sentence])
    return res


# ------------------------------------------------------------------------------------------ parsing


@pytest.mark.parametrize(
    "sentence, apps, when, expect",
    [
        (
            "Okta Administrators must use phishing-resistant MFA for the Okta Admin Console.",
            ["Okta Admin Console"],
            {"groups_any": ["Okta Administrators"]},
            {"min_strength": "TWO_FA_PHISHING_RESISTANT"},
        ),
        (
            "Contractors can only reach Salesforce from the Corporate Network or VPN.",
            ["Salesforce"],
            {"groups_any": ["Contractors"], "zones_none": ["Corporate Network", "VPN"]},
            {"access": "DENY"},
        ),
        (
            "Users outside the VPN on an unmanaged device must be denied access to Payroll (Workday).",
            ["Payroll (Workday)"],
            {"zones_none": ["VPN"], "managed": False},
            {"access": "DENY"},
        ),
        (
            "Only Finance can access Payroll (Workday).",
            ["Payroll (Workday)"],
            {"groups_none": ["Finance"]},
            {"access": "DENY"},
        ),
        (
            "Contractors cannot access GitHub.",
            ["GitHub"],
            {"groups_any": ["Contractors"]},
            {"access": "DENY"},
        ),
        (
            "Executives cannot access Payroll (Workday) without phishing-resistant MFA.",
            ["Payroll (Workday)"],
            {"groups_any": ["Executives"]},
            {"min_strength": "TWO_FA_PHISHING_RESISTANT"},
        ),
        (
            "Nobody can sign in to Legacy Intranet without a password.",
            ["Legacy Intranet"],
            {},
            {"passwordless": False},
        ),
        (
            "Nobody can access the Okta Admin Console with only a password.",
            ["Okta Admin Console"],
            {},
            {"min_strength": "ONE_FA_POSSESSION"},
        ),
        (
            "Executives must use hardware-protected MFA for Payroll (Workday) from the internet.",
            ["Payroll (Workday)"],
            {
                "groups_any": ["Executives"],
                "zones_none": ["Corporate Network", "VPN", "LegacyIpZone", "High-risk countries"],
            },
            {"min_strength": "TWO_FA_PHISHING_RESISTANT_HARDWARE"},
        ),
        (
            "Finance must use MFA for Payroll (Workday) unless they are on the Corporate Network.",
            ["Payroll (Workday)"],
            {"groups_any": ["Finance"], "zones_none": ["Corporate Network"]},
            {"min_strength": "TWO_FA"},
        ),
        (
            "Sales can access Salesforce unless they are on the VPN.",
            ["Salesforce"],
            {"groups_any": ["Sales"], "zones_any": ["VPN"]},
            {"access": "DENY"},
        ),
        (
            "High-risk sign-ins to Salesforce must be denied.",
            ["Salesforce"],
            {"risk": "HIGH"},
            {"access": "DENY"},
        ),
        (
            "Users on iOS must use MFA for GitHub.",
            ["GitHub"],
            {"platforms_any": ["IOS"]},
            {"min_strength": "TWO_FA"},
        ),
        (
            "Users whose department is 'Finance' must use MFA for Payroll (Workday).",
            ["Payroll (Workday)"],
            {"attributes": {"user.department": "Finance"}},
            {"min_strength": "TWO_FA"},
        ),
        (
            "Users who are not in US Employees must be denied access to Payroll (Workday).",
            ["Payroll (Workday)"],
            {"groups_none": ["US Employees"]},
            {"access": "DENY"},
        ),
        (
            "Everyone must be able to access Okta Dashboard.",
            ["Okta Dashboard"],
            {},
            {"access": "ALLOW"},
        ),
        (
            "Contractors must be handled by rule 'Contractors elsewhere denied' for GitHub.",
            ["GitHub"],
            {"groups_any": ["Contractors"]},
            {"rules_any": ["Contractors elsewhere denied"]},
        ),
        (
            "Rule 'Break-glass account' must never apply for Okta Admin Console.",
            ["Okta Admin Console"],
            {},
            {"rules_none": ["Break-glass account"]},
        ),
        (
            "Contractors on the Corporate Network must be handled by rule Contractors from corp/VPN for GitHub.",
            ["GitHub"],
            {"groups_any": ["Contractors"], "zones_any": ["Corporate Network"]},
            {"rules_any": ["Contractors from corp/VPN"]},
        ),
    ],
)
def test_parse(acme, sentence, apps, when, expect) -> None:
    parsed = parse_invariant(sentence, acme)
    assert parsed.ok, parsed.problems
    a = parsed.assertion
    assert a.apps == apps
    assert a.when == when
    assert a.expect == expect
    assert parsed.reading and parsed.reading.startswith("For every user")


def test_parse_all_apps_and_session(acme) -> None:
    p = parse_invariant("Nobody can access any app with only a password", acme)
    assert p.ok and p.assertion.all_apps and not p.assertion.apps
    assert any("read literally" in n for n in p.notes)
    p = parse_invariant("Engineering must use MFA for Salesforce even after the global session policy", acme)
    assert p.ok and p.assertion.with_session_policy
    assert "global session policy" in p.reading


def test_parse_policy_name(acme) -> None:
    p = parse_invariant("Everyone must use MFA for apps governed by Standard apps policy", acme)
    assert p.ok and p.assertion.policy == "Standard apps policy" and not p.assertion.apps


@pytest.mark.parametrize(
    "sentence, fragment",
    [
        ("Marketing must use MFA for Salesforce.", "'Marketing' is not a group"),
        ("Contractor users must use MFA for Salesforce.", "did you mean 'Contractors'"),
        ("Okta Administrators must use MFA for Slack.", "no app or policy recognised"),
        ("Okta Administrators must use MFA for Sales force.", "did you mean 'Salesforce'"),
        ("Anyone can access Salesforce.", "no requirement recognised"),
        ("Contractors must be handled by rule 'Contractors deny' for GitHub.", "did you mean"),
    ],
)
def test_unparseable_sentences_explain_why(acme, sentence, fragment) -> None:
    p = parse_invariant(sentence, acme)
    assert not p.ok
    assert any(fragment in msg for msg in p.problems), p.problems


def test_reading_is_deterministic_and_formal(acme) -> None:
    p = parse_invariant("Contractors can only reach Salesforce from the Corporate Network or VPN", acme)
    assert p.reading == reading(p.assertion, acme)
    assert "outside Corporate Network and VPN" in p.reading
    assert "the deciding rule is DENY" in p.reading


# ------------------------------------------------------------------------------------------ verdicts


@pytest.mark.parametrize(
    "sentence, verdict",
    [
        ("Okta Administrators must use phishing-resistant MFA for the Okta Admin Console.", "PROVED"),
        ("Nobody can sign in to Legacy Intranet without a password.", "PROVED"),
        ("Finance must use MFA for Payroll (Workday) on Windows.", "PROVED"),
        ("Finance must use MFA for Payroll (Workday) unless they are on the Corporate Network.", "PROVED"),
        ("Everyone must be able to access Okta Dashboard.", "PROVED"),
        ("Users whose department is 'Finance' must use MFA for Payroll (Workday).", "PROVED"),
        ("Contractors can only reach Salesforce from the Corporate Network or VPN.", "VIOLATED"),
        ("Nobody can access any app with only a password.", "VIOLATED"),
        ("Only Finance can access Payroll (Workday).", "VIOLATED"),
        ("Contractors cannot access GitHub.", "VIOLATED"),
        ("Rule 'Break-glass account' must never apply for Okta Admin Console.", "VIOLATED"),
        ("Marketing must use MFA for Salesforce.", "UNPARSED"),
    ],
)
def test_verdicts(analyzer, sentence, verdict) -> None:
    res = _one(analyzer, sentence)
    assert res.verdict == verdict, "\n".join(explain_result(res, analyzer.t))


def test_violation_names_rule_and_counterexample(analyzer) -> None:
    res = _one(analyzer, "Contractors cannot access GitHub.")
    assert res.verdict == "VIOLATED"
    bad = [r for r in res.results if not r.holds]
    assert bad and bad[0].violating_rule == "Managed device passwordless"
    text = "\n".join(explain_result(res, analyzer.t))
    assert "counterexample:" in text and "member of Contractors" in text
    d = res.to_dict()
    assert d["verdict"] == "VIOLATED" and d["assertion"]["expect"] == {"access": "DENY"}
    assert d["assumptions"] == []  # only PROVED results carry the assumption list


def test_proof_lists_assumptions(analyzer) -> None:
    res = _one(analyzer, "Okta Administrators must use phishing-resistant MFA for the Okta Admin Console.")
    assert res.verdict == "PROVED"
    assert any("managed device is always a registered device" in a for a in res.assumptions)
    text = "\n".join(explain_result(res, analyzer.t))
    assert "proof relies on these modelling assumptions" in text


def test_vacuous_premise(analyzer) -> None:
    # a managed device is always registered, so this premise matches no world: the tool must say so rather
    # than claim a proof
    sentence = "Users on a managed unregistered device must be denied access to Salesforce"
    p = parse_invariant(sentence, analyzer.t)
    assert p.ok and p.assertion.when == {"managed": True, "registered": False}
    (r,) = check_invariants(analyzer, [sentence])
    assert r.verdict == "VACUOUS"
    assert "vacuous" in "\n".join(explain_result(r, analyzer.t))


# ------------------------------------------------------------------------------------------ CLI


def test_cli_check(tmp_path, capsys) -> None:
    rc = main(
        [
            "check",
            FIXTURE,
            "Okta Administrators must use phishing-resistant MFA for the Okta Admin Console",
            "Nobody can sign in to Legacy Intranet without a password",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert out.count("PROVED:") == 2 and "summary: 2 proved" in out

    inv = tmp_path / "inv.txt"
    inv.write_text(
        "# corp-sec invariants\nContractors cannot access GitHub.\n\n"
        "Okta Administrators must use phishing-resistant MFA for the Okta Admin Console.\n"
    )
    yaml_out = tmp_path / "inv.yaml"
    out_json = tmp_path / "inv.json"
    rc = main(
        [
            "check",
            FIXTURE,
            "--file",
            str(inv),
            "--yaml-out",
            str(yaml_out),
            "--format",
            "json",
            "-o",
            str(out_json),
        ]
    )
    assert rc == 1
    d = json.loads(out_json.read_text())
    assert [x["verdict"] for x in d] == ["VIOLATED", "PROVED"]
    assert "reading" in d[0] and d[0]["results"][0]["violating_rule"] == "Managed device passwordless"
    # exported YAML round-trips through `verify --assertions`
    res_json = tmp_path / "verify.json"
    rc = main(
        [
            "verify",
            FIXTURE,
            "--assertions",
            str(yaml_out),
            "--no-cubes",
            "--format",
            "json",
            "-o",
            str(res_json),
        ]
    )
    assert rc == 1
    v = json.loads(res_json.read_text())
    assert [a["holds"] for a in v["assertions"]] == [False, True]

    # unparseable sentence → exit 2 with an explanation
    rc = main(["check", FIXTURE, "Marketing must use MFA for Salesforce"])
    assert rc == 2
    assert "cannot read this sentence" in capsys.readouterr().out
    # no sentences at all → usage error
    assert main(["check", FIXTURE]) == 2
