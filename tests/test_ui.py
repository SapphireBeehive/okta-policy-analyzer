"""Web UI: JSON API over the analyzer, invariants file round trip, static export."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from okta_policy_analyzer.cli import main
from okta_policy_analyzer.ui import UIState, describe_conditions, make_server

from .fixtures import acme as fx

FIXTURE = str(Path(__file__).parent / "fixtures" / "acme")


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    inv = tmp_path_factory.mktemp("ui") / "invariants.txt"
    inv.write_text(
        "# demo\nOnly Finance can access Payroll (Workday)\n\n"
        "Okta Administrators must use phishing-resistant MFA for the Okta Admin Console\n"
    )
    state = UIState.load(FIXTURE, str(inv))
    srv = make_server(state, port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv, state, inv
    srv.shutdown()
    srv.server_close()


def _call(srv, path, method="GET", body=None):
    port = srv.server_address[1]
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        method=method,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_describe_conditions(acme) -> None:
    pol = next(p for p in acme.access_policies if p.id == fx.P_STD)
    texts = {r.name: describe_conditions(r.conditions, acme) for r in pol.rules}
    assert "groups: Contractors" in texts["Contractors from corp/VPN"]
    assert any(c.startswith("from zones: ") and "VPN" in c for c in texts["Contractors from corp/VPN"])
    assert texts[next(n for n in texts if n.startswith("Catch-all"))] == []


def test_state_policies_principals_findings(server) -> None:
    srv, state, _ = server
    s, st = _call(srv, "/api/state")
    assert s == 200 and st["live"] and not st["allow_apply"] and st["counts"]["groups"] == 9
    s, p = _call(srv, "/api/policies")
    assert s == 200 and {x["name"] for x in p["access"]} >= {"Standard apps policy", "Payroll policy"}
    std = next(x for x in p["access"] if x["name"] == "Standard apps policy")
    rule = next(r for r in std["rules"] if r["name"] == "Managed device passwordless")
    assert rule["strength"] == "TWO_FA_PHISHING_RESISTANT" and "device managed" in rule["conditions"]
    assert rule["raw"]["actions"]["appSignOn"]["access"] == "ALLOW"
    assert any(r.get("reachable") is False for x in p["access"] for r in x["rules"])  # shadowing surfaced
    assert std["outcomes"] and std["weakest"] == "ONE_FA_KNOWLEDGE"
    assert p["session"] and p["enrollment"]
    s, pr = _call(srv, "/api/principals")
    contractors = next(g for g in pr["groups"] if g["name"] == "Contractors")
    assert any(r["rule"] == "Contractors from corp/VPN" for r in contractors["referenced_by"])
    assert any(
        v["policy"] == "Okta Admin Console policy" and v["weakest"] == "DENY" for v in contractors["view"]
    )
    assert any(g["type"] == "MISSING" for g in pr["groups"])  # dangling group reference is visible
    assert any(z["usage"] == "BLOCKLIST" for z in pr["zones"])
    assert any(a["policy"] is None for a in pr["apps"])
    s, f = _call(srv, "/api/findings")
    assert s == 200 and any(x["kind"] == "deny-bypassed" for x in f)


def test_invariants_check_save_remove(server) -> None:
    srv, state, inv = server
    s, lst = _call(srv, "/api/invariants")
    assert [x["verdict"] for x in lst] == ["VIOLATED", "PROVED"] and all(x["saved"] for x in lst)
    assert lst[0]["results"][0]["violating_rule"] == "Executives" and "Reading" not in lst[0]["reading"]
    s, c = _call(srv, "/api/invariants/check", "POST", {"sentence": "Contractors cannot access GitHub"})
    assert s == 200 and c["verdict"] == "VIOLATED" and c["results"][0]["counterexample"]
    assert "Contractors cannot access GitHub" not in inv.read_text()
    s, c = _call(srv, "/api/invariants", "POST", {"sentence": "  Contractors   cannot access GitHub "})
    assert s == 200 and c["saved"] and "Contractors cannot access GitHub" in inv.read_text()
    s, _ = _call(srv, "/api/invariants", "DELETE", {"sentence": "Contractors cannot access GitHub"})
    assert s == 200 and "Contractors cannot access GitHub" not in inv.read_text()
    assert "Only Finance can access Payroll (Workday)" in inv.read_text()  # others preserved
    s, e = _call(srv, "/api/invariants/check", "POST", {"sentence": "   "})
    assert s == 400 and "empty" in e["error"]
    s, u = _call(srv, "/api/invariants/check", "POST", {"sentence": "Marketing must use MFA for Salesforce"})
    assert s == 200 and u["verdict"] == "UNPARSED" and u["problems"]


def test_propose_and_apply_guard(server) -> None:
    srv, state, _ = server
    s, plan = _call(
        srv,
        "/api/propose",
        "POST",
        {"sentence": "Only Finance can access Payroll (Workday)", "rule_name": "X"},
    )
    assert s == 200 and plan["status"] == "FIX_PROVED" and plan["ops"][0]["rule"]["name"] == "X"
    assert plan["diff"] and "CREATE rule" in plan["text"]
    s, e = _call(srv, "/api/apply", "POST", {"plan": plan, "confirm": "APPLY"})
    assert s == 403 and "allow-apply" in e["error"]
    s, e = _call(srv, "/api/apply", "POST", {"plan": plan})
    assert s == 400
    s, e = _call(srv, "/api/nope")
    assert s == 404


def test_index_and_export(server, tmp_path) -> None:
    srv, state, _ = server
    port = srv.server_address[1]
    html = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read().decode()
    assert "<title>Okta Policy Workbench" in html and "<!--DATA-->" in html
    exported = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/export").read().decode()
    assert "window.__DATA__" in exported and "<!--DATA-->" not in exported
    data = json.loads(exported.split("window.__DATA__ = ", 1)[1].split(";</script>", 1)[0])
    assert data["state"]["live"] is False and len(data["invariants"]) == 2 and data["policies"]["access"]
    assert "</script>" not in json.dumps(data)  # embedded JSON cannot break out of its script tag
    # CLI export path
    out = tmp_path / "page.html"
    assert main(["serve", FIXTURE, "--export", str(out)]) == 0
    assert "Okta Policy Workbench" in out.read_text()
