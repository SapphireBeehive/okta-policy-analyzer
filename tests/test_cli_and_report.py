from __future__ import annotations

import json
from pathlib import Path

from okta_policy_analyzer.cli import main

FIXTURE = str(Path(__file__).parent / "fixtures" / "acme")
ASSERTIONS = str(Path(__file__).parent / "fixtures" / "acme_assertions.yaml")


def test_analyze_json(tmp_path, capsys) -> None:
    out = tmp_path / "r.json"
    rc = main(
        ["analyze", FIXTURE, "--format", "json", "-o", str(out), "--assertions", ASSERTIONS, "--no-cubes"]
    )
    assert rc == 0
    d = json.loads(out.read_text())
    assert d["stats"]["authentication_policies"] == 5
    kinds = {f["kind"] for f in d["findings"]}
    assert {"deny-bypassed", "shadowed-rule", "weak-catch-all", "unenrollable-requirement"} <= kinds
    assert any(not a["holds"] for a in d["assertions"])
    # fail-on-violation exit code
    rc = main(
        [
            "analyze",
            FIXTURE,
            "--format",
            "json",
            "-o",
            str(out),
            "--assertions",
            ASSERTIONS,
            "--no-cubes",
            "--fail-on-violation",
        ]
    )
    assert rc == 1
    rc = main(
        ["verify", FIXTURE, "--assertions", ASSERTIONS, "--no-cubes", "--format", "json", "-o", str(out)]
    )
    assert rc == 1


def test_analyze_markdown_and_text(tmp_path) -> None:
    md = tmp_path / "r.md"
    assert main(["analyze", FIXTURE, "--format", "markdown", "-o", str(md), "--no-cubes"]) == 0
    text = md.read_text()
    assert "# Okta authentication policy analysis" in text
    assert "Contractors elsewhere denied" in text and "Weakest way in" in text
    txt = tmp_path / "r.txt"
    assert main(["-v", "analyze", FIXTURE, "-o", str(txt), "--no-cubes"]) == 0
    assert "okta-policy-analyzer" in txt.read_text()


def test_explain(capsys) -> None:
    rc = main(
        [
            "explain",
            FIXTURE,
            "--user",
            "bob@contractor.example",
            "--managed",
            "--platform",
            "MACOS",
            "--assurance",
            "macOS secure",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Contractors session policy" in out
    assert "Salesforce: [Standard apps policy] rule 'Managed device passwordless'" in out
    assert "Okta Admin Console: [Okta Admin Console policy] rule 'Deny contractors' → DENY" in out
    rc = main(
        [
            "explain",
            FIXTURE,
            "--group",
            "Finance",
            "--attr",
            "department=Finance",
            "--zone",
            "VPN",
            "--app",
            "Payroll (Workday)",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Finance phishing-resistant" in out


def test_who(capsys) -> None:
    rc = main(["who", FIXTURE, "--app", "Salesforce", "--max-strength", "ONE_FA_KNOWLEDGE", "--no-cubes"])
    assert rc == 0
    out = capsys.readouterr().out
    assert (
        "Sales on mobile" in out and "Service accounts denied" not in out
    )  # DENY rows hidden with --max-strength
    rc = main(
        [
            "who",
            FIXTURE,
            "--app",
            "Salesforce",
            "--max-strength",
            "ONE_FA_KNOWLEDGE",
            "--include-deny",
            "--no-cubes",
        ]
    )
    assert rc == 0 and "Service accounts denied" in capsys.readouterr().out
    assert "who:" in out and "when:" in out


def test_export_tla(tmp_path, capsys) -> None:
    rc = main(
        [
            "export-tla",
            FIXTURE,
            "-o",
            str(tmp_path),
            "--policy",
            "Okta Admin Console policy",
            "--assertions",
            ASSERTIONS,
            "--no-cubes",
        ]
    )
    assert rc == 0
    tla = tmp_path / "Policy_Okta_Admin_Console_policy.tla"
    cfg = tmp_path / "Policy_Okta_Admin_Console_policy.cfg"
    assert tla.exists() and cfg.exists()
    text = tla.read_text()
    assert "Match_0 ==" in text and "Decision ==" in text and "Strength ==" in text
    assert "Assert_admins_phishing_resistant" in cfg.read_text()


def test_version(capsys) -> None:
    try:
        main(["--version"])
    except SystemExit as e:
        assert e.code == 0
    assert capsys.readouterr().out.strip()


def test_all_subcommands_registered() -> None:
    from okta_policy_analyzer.cli import build_parser

    parser = build_parser()
    sub = next(a for a in parser._actions if a.dest == "command")
    assert set(sub.choices) == {
        "fetch",
        "analyze",
        "verify",
        "explain",
        "who",
        "export-tla",
        "diff",
        "simulate-validate",
    }
    ns = parser.parse_args(["simulate-validate", "snap", "--app", "X", "--samples", "3"])
    assert ns.samples == 3 and ns.func.__name__ == "cmd_simulate_validate"
    ns = parser.parse_args(["diff", "a", "b", "--fail-on-more-permissive"])
    assert ns.func.__name__ == "cmd_diff"
    ns = parser.parse_args(["analyze", "snap", "-j", "4", "--no-cubes", "--combined-who"])
    assert ns.jobs == 4 and ns.combined_who


def test_sarif_output(tmp_path) -> None:
    out = tmp_path / "r.sarif"
    assert main(["analyze", FIXTURE, "--format", "sarif", "-o", str(out), "--no-cubes"]) == 0
    sarif = json.loads(out.read_text())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "okta-policy-analyzer"
    assert any(r["ruleId"] == "deny-bypassed" and r["level"] == "error" for r in run["results"])
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {r["ruleId"] for r in run["results"]}
