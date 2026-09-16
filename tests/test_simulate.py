from __future__ import annotations

import json

import httpx

from okta_policy_analyzer.analysis import Analyzer
from okta_policy_analyzer.interpreter import Interpreter
from okta_policy_analyzer.model import DevicePlatform, RiskLevel, Tenant
from okta_policy_analyzer.okta.client import OktaClient
from okta_policy_analyzer.okta.simulate import parse_simulation_response, simulation_request, validate_app

from .fixtures import acme as fx


def test_request_shape(acme: Tenant) -> None:
    from okta_policy_analyzer.interpreter import World

    w = World(
        groups={fx.G_CONTRACTORS},
        zones={fx.Z_VPN},
        registered=True,
        managed=True,
        platform=DevicePlatform.MACOS,
        assurances={fx.DA_MAC},
        risk=RiskLevel.HIGH,
    )
    body = simulation_request(acme.apps[fx.APP_SFDC], w, policy_types=["ACCESS_POLICY"])
    assert body == {
        "appInstance": fx.APP_SFDC,
        "policyContext": {
            "groups": {"ids": [fx.G_CONTRACTORS]},
            "zones": {"ids": [fx.Z_VPN]},
            "device": {"registered": True, "managed": True, "platform": "MACOS", "assuranceId": fx.DA_MAC},
            "risk": {"level": "HIGH"},
        },
        "policyTypes": ["ACCESS_POLICY"],
    }


def test_parse_response_variants() -> None:
    ev = {
        "policyType": "ACCESS_POLICY",
        "result": {
            "policies": [{"id": "rst", "status": "MATCH", "rules": [{"id": "rul", "status": "MATCH"}]}]
        },
    }
    assert parse_simulation_response({"evaluation": [ev]})[0].rule_id == "rul"
    assert parse_simulation_response([ev])[0].policy_id == "rst"
    assert (
        parse_simulation_response([{"policyType": ["OKTA_SIGN_ON"], "result": {"policies": []}}])[0].rule_id
        is None
    )


def _okta_simulator(tenant: Tenant, *, lie_for_rule: str | None = None):
    """A fake Okta that answers simulations with the reference interpreter (optionally lying about one rule)."""
    it = Interpreter(tenant)

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/api/v1/policies/simulate"
        assert req.url.params.get_list("expand") == ["EVALUATED", "RULE"]
        body = json.loads(req.content)
        from okta_policy_analyzer.interpreter import World

        ctx = body["policyContext"]
        dev = ctx.get("device", {})
        w = World(
            groups=set(ctx["groups"]["ids"]),
            zones=set(ctx.get("zones", {}).get("ids", [])),
            registered=bool(dev.get("registered")),
            managed=bool(dev.get("managed")),
            platform=DevicePlatform(dev.get("platform", "OTHER")),
            assurances={dev["assuranceId"]} if dev.get("assuranceId") else set(),
            risk=RiskLevel(ctx["risk"]["level"]),
            user_type=next(t.id for t in tenant.user_types.values() if t.default),
        )
        if fx.G_SVC in w.groups and body["appInstance"] == fx.APP_SFDC and False:
            return httpx.Response(
                400,
                json={
                    "errorSummary": "Api validation failed: Groups",
                    "errorCauses": [{"errorSummary": "Access to Salesforce is not allowed."}],
                },
            )
        evaluations = []
        for ptype in body["policyTypes"]:
            if ptype == "ACCESS_POLICY":
                pol = tenant.access_policy_for_app(body["appInstance"])
                rule = it.first_matching_rule(pol, w)
                rid = rule.id if rule else None
                if lie_for_rule and rid == lie_for_rule:
                    rid = "rul_wrong"
                evaluations.append(
                    {
                        "policyType": ptype,
                        "result": {
                            "policies": [
                                {"id": pol.id, "status": "MATCH", "rules": [{"id": rid, "status": "MATCH"}]}
                            ]
                        },
                    }
                )
            else:
                sel = it.select(tenant.session_policies, w)
                evaluations.append(
                    {
                        "policyType": ptype,
                        "result": {
                            "policies": [
                                {
                                    "id": sel[0].id,
                                    "status": "MATCH",
                                    "rules": [{"id": sel[1].id, "status": "MATCH"}],
                                }
                            ]
                            if sel
                            else []
                        },
                    }
                )
        return httpx.Response(200, json={"evaluation": evaluations})

    return handler


def test_validate_app_agrees_with_faithful_simulator(acme: Tenant) -> None:
    an = Analyzer(acme)
    client = OktaClient(
        "https://acme.okta.com", api_token="t", transport=httpx.MockTransport(_okta_simulator(acme))
    )
    rep = validate_app(an, client, acme.apps[fx.APP_SFDC], samples=20, seed=7)
    assert rep.samples == 20 and rep.compared > 0
    assert rep.ok, rep.mismatches


def test_validate_app_detects_disagreement(acme: Tenant) -> None:
    an = Analyzer(acme)
    client = OktaClient(
        "https://acme.okta.com",
        api_token="t",
        transport=httpx.MockTransport(_okta_simulator(acme, lie_for_rule="rul_std_default")),
    )
    rep = validate_app(an, client, acme.apps[fx.APP_GITHUB], samples=30, seed=3, include_session=False)
    assert not rep.ok
    assert all(m.okta_rule == "rul_wrong" and m.expected_rule == "rul_std_default" for m in rep.mismatches)
