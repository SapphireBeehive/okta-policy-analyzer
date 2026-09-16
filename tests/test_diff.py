from __future__ import annotations

import copy
import json
from pathlib import Path

from okta_policy_analyzer.cli import main
from okta_policy_analyzer.diff import diff_tenants
from okta_policy_analyzer.loader import load_tenant
from okta_policy_analyzer.okta.snapshot import Snapshot

from .fixtures import acme as fx


def _modified(snap: Snapshot) -> Snapshot:
    new = Snapshot.from_dict(copy.deepcopy(snap.to_dict()))
    for p in new.policies:
        if p["id"] == fx.P_STD:
            for r in p["_rules"]:
                if r["id"] == "rul_std_contractor_deny":
                    r["priority"] = 0  # fix the bypass: DENY contractors before the managed-device rule
                elif r["priority"] < 3:
                    r["priority"] += 1
        if p["id"] == fx.P_PAYROLL:
            for r in p["_rules"]:
                if r["id"] == "rul_pay_default":  # weaken payroll: catch-all DENY -> 2FA
                    r["actions"] = {
                        "appSignOn": {
                            "access": "ALLOW",
                            "verificationMethod": {
                                "type": "ASSURANCE",
                                "factorMode": "2FA",
                                "constraints": [],
                            },
                        }
                    }
    return new


def test_diff_verdicts(acme_snapshot: Snapshot) -> None:
    new = _modified(acme_snapshot)
    res = diff_tenants(load_tenant(acme_snapshot), load_tenant(new))
    by = {a.app: a for a in res.apps}
    assert by["Okta Dashboard"].verdict == "EQUIVALENT" and by["Legacy Intranet"].verdict == "EQUIVALENT"
    std = by["Salesforce"]
    assert std.verdict == "LESS_PERMISSIVE"
    assert any("Contractors" in w for w in std.lost_access) and not std.new_access
    assert any(c.kind == "reordered" for c in std.rule_changes)
    pay = by["Payroll (Workday)"]
    assert pay.verdict == "MORE_PERMISSIVE" and pay.new_access and pay.witness_new_access
    assert any(c.kind == "edited" and c.rule == "Catch-all Rule" for c in pay.rule_changes)
    assert res.more_permissive == [pay]
    assert any(a.startswith("diff:") for a in res.assumptions)
    # identical snapshots are equivalent everywhere
    same = diff_tenants(load_tenant(acme_snapshot), load_tenant(acme_snapshot))
    assert all(a.verdict == "EQUIVALENT" and not a.rule_changes for a in same.apps)


def test_diff_cli(acme_snapshot: Snapshot, tmp_path, capsys) -> None:
    old_dir = Path(__file__).parent / "fixtures" / "acme"
    new_path = tmp_path / "new.json"
    _modified(acme_snapshot).save_file(new_path)
    rc = main(["diff", str(old_dir), str(new_path), "--fail-on-more-permissive"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "Payroll (Workday): MORE_PERMISSIVE" in out and "+ new access:" in out
    out_json = tmp_path / "d.json"
    assert main(["diff", str(old_dir), str(new_path), "--format", "json", "-o", str(out_json)]) == 0
    d = json.loads(out_json.read_text())
    assert {a["verdict"] for a in d["apps"]} >= {"EQUIVALENT", "MORE_PERMISSIVE", "LESS_PERMISSIVE"}
