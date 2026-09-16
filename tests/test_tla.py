"""TLA+ export: module structure, and (when TLC is available) agreement with the z3 analyses."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from okta_policy_analyzer.analysis import Analyzer
from okta_policy_analyzer.assertions import AssertionChecker, load_assertions
from okta_policy_analyzer.model import Tenant
from okta_policy_analyzer.tla import TLAExporter, run_tlc_each, tla_ident

ASSERTIONS = Path(__file__).parent / "fixtures" / "acme_assertions.yaml"
JAR = os.environ.get("TLA2TOOLS_JAR") or next(
    (
        p
        for p in [
            "/tmp/claude-0/-home-user-okta-policy-analyzer/b342d3b6-c38f-5f66-ac4e-22ade4fb97ed/scratchpad/ref/tla2tools.jar",
            "tla2tools.jar",
            str(Path.home() / "tla2tools.jar"),
        ]
        if Path(p).exists()
    ),
    None,
)


def _relevant(tenant: Tenant, assertions, pol):
    out = []
    for a in assertions:
        if a.all_apps or a.policy in (pol.id, pol.name):
            out.append(a)
            continue
        for label in a.apps:
            app = next((x for x in tenant.apps.values() if x.label == label), None)
            if app and tenant.access_policy_for_app(app.id) is pol:
                out.append(a)
                break
    return out


def test_export_structure(acme: Tenant, tmp_path) -> None:
    an = Analyzer(acme)
    ex = TLAExporter(an)
    pol = acme.policy("rst_std")
    assert pol is not None
    e = ex.export_policy(pol, load_assertions(str(ASSERTIONS)))
    tla, cfg = e.write(tmp_path)
    text = tla.read_text()
    assert text.startswith(f"---------------------------- MODULE {e.module_name}")
    # slicing: only groups the policy, its group rules and the session policies mention (Engineering is unreferenced)
    groups_line = next(line for line in text.splitlines() if line.startswith("Groups =="))
    assert '"00g_eng"' not in groups_line and '"00g_exec"' not in groups_line
    assert (
        '"00g_contractors"' in groups_line and '"00g_admins"' in groups_line
    )  # admins via the session policy
    assert '"nzo_corp"' in text
    # the deleted group is substituted as a constant, not enumerated
    assert '"00g_deleted"' not in groups_line and "00g_deleted]=False" in text
    assert "Opaques == {\"opaque:String.stringContains(request.userAgent, 'Mobile')\"}" in text
    assert "Match_0 ==" in text and 'ELSE "NO_MATCH"' in text and "SessionDecision ==" in text
    assert "Assert_contractors_denied_off_network" in cfg.read_text()
    assert e.estimated_states < 5_000_000
    assert tla_ident("Weird name/with (chars)") == "Weird_name_with__chars_"


@pytest.mark.skipif(JAR is None or shutil.which("java") is None, reason="tla2tools.jar / java not available")
def test_tlc_agrees_with_z3_on_small_policies(acme: Tenant, tmp_path) -> None:
    an = Analyzer(acme)
    ex = TLAExporter(an)
    assertions = load_assertions(str(ASSERTIONS))
    z3res = {(r.assertion.name, r.policy.id): r.holds for r in AssertionChecker(an).check_all(assertions)}
    for pid in ("rst_admin", "rst_weak", "rst_payroll", "rst_dashboard"):
        pol = acme.policy(pid)
        assert pol is not None
        rel = _relevant(acme, assertions, pol)
        e = ex.export_policy(pol, rel)
        tla, _ = e.write(tmp_path)
        results = run_tlc_each(
            tla, JAR, list(e.invariants) + list(e.reachability_probes), timeout=600, parallel=2
        )
        assert not [k for k, r in results.items() if r.error], {
            k: r.error for k, r in results.items() if r.error
        }
        ep = an.enc.access_policy(pol)
        z3_reach = {r.name: an.sat(eff) for r, eff in zip(ep.rules, ep.effective, strict=True)}
        tlc_reach = {name: probe in results[probe].violated for probe, name in e.reachability_probes.items()}
        assert z3_reach == tlc_reach, pid
        for a in rel:
            inv = f"Assert_{tla_ident(a.name)}"
            if inv in e.invariants:
                assert (inv not in results[inv].violated) == z3res[(a.name, pol.id)], (pid, a.name)
        assert results["SomeRuleDecides"].violated == []
