from __future__ import annotations

import json

import httpx
import pytest

from okta_policy_analyzer.okta import OktaAPIError, OktaClient, Snapshot, fetch_snapshot
from okta_policy_analyzer.okta.client import parse_next_link

ORG = "https://example.okta.com"


def _client(handler, **kw) -> OktaClient:
    sleeps: list[float] = []
    c = OktaClient(ORG, api_token="t", transport=httpx.MockTransport(handler), sleep=sleeps.append, **kw)
    c._sleeps = sleeps  # type: ignore[attr-defined]
    return c


def test_parse_next_link() -> None:
    hdr = '<https://example.okta.com/api/v1/groups?limit=2>; rel="self", <https://example.okta.com/api/v1/groups?after=abc&limit=2>; rel="next"'
    assert parse_next_link(hdr) == "https://example.okta.com/api/v1/groups?after=abc&limit=2"
    assert parse_next_link('<https://x/y>; rel="self"') is None
    assert parse_next_link(None) is None


def test_auth_header_variants() -> None:
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.headers["Authorization"])
        return httpx.Response(200, json={})

    _client(handler).get("/api/v1/org")
    OktaClient(ORG, bearer_token="b", transport=httpx.MockTransport(handler)).get("/api/v1/org")
    assert seen == ["SSWS t", "Bearer b"]
    with pytest.raises(ValueError):
        OktaClient(ORG)
    with pytest.raises(ValueError):
        OktaClient("http://insecure.okta.com", api_token="t")


def test_pagination_follows_next_links() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        after = req.url.params.get("after")
        assert req.url.params.get("limit") == "2"
        if after is None:
            return httpx.Response(
                200,
                json=[{"id": "a"}, {"id": "b"}],
                headers={"Link": f'<{ORG}/api/v1/groups?limit=2&after=b>; rel="next"'},
            )
        assert after == "b"
        return httpx.Response(200, json=[{"id": "c"}])

    items = _client(handler, page_limit=2).list_all("/api/v1/groups")
    assert [i["id"] for i in items] == ["a", "b", "c"]


def test_rate_limit_429_retries_until_reset() -> None:
    calls = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(
                429,
                json={"errorSummary": "rate limited"},
                headers={"X-Rate-Limit-Reset": "1000", "Date": "Thu, 01 Jan 1970 00:16:30 GMT"},
            )
        return httpx.Response(200, json={"ok": True})

    c = _client(handler)
    assert c.get("/api/v1/org") == {"ok": True}
    assert calls["n"] == 2
    # reset at t=1000, Date says t=990 -> sleep ~11s
    assert c._sleeps == [11.0]  # type: ignore[attr-defined]


def test_non_retryable_error_raises() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"errorCode": "E0000006", "errorSummary": "forbidden"})

    with pytest.raises(OktaAPIError) as ei:
        _client(handler).get("/api/v1/policies")
    assert ei.value.status == 403
    assert "forbidden" in str(ei.value)


def test_server_error_retries_then_gives_up() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"errorSummary": "down"})

    with pytest.raises(OktaAPIError):
        _client(handler, max_retries=2).get("/api/v1/org")


def _fake_org_handler(req: httpx.Request) -> httpx.Response:
    p = req.url.path
    q = req.url.params
    if p == "/api/v1/policies":
        t = q.get("type")
        if t == "ACCESS_POLICY":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": "rst1",
                        "type": "ACCESS_POLICY",
                        "name": "App policy",
                        "_embedded": {"rules": [{"id": "rul1", "priority": 0}]},
                    }
                ],
            )
        if t == "OKTA_SIGN_ON":
            return httpx.Response(200, json=[{"id": "gsp1", "type": "OKTA_SIGN_ON", "name": "Default"}])
        if t == "MFA_ENROLL":
            return httpx.Response(403, json={"errorSummary": "no"})
        return httpx.Response(200, json=[])
    if p == "/api/v1/policies/gsp1/rules":
        return httpx.Response(200, json=[{"id": "rulg", "priority": 0}])
    if p == "/api/v1/apps":
        return httpx.Response(
            200,
            json=[
                {
                    "id": "app1",
                    "label": "App",
                    "_links": {"accessPolicy": {"href": f"{ORG}/api/v1/policies/rst1"}},
                }
            ],
        )
    if p == "/api/v1/groups":
        return httpx.Response(200, json=[{"id": "g1", "profile": {"name": "Everyone"}}])
    if p == "/api/v1/authenticators":
        return httpx.Response(200, json=[{"id": "aut1", "key": "okta_password"}])
    if p == "/api/v1/authenticators/aut1/methods":
        return httpx.Response(200, json=[{"type": "password", "status": "ACTIVE"}])
    if p == "/api/v1/device-assurances":
        return httpx.Response(404, json={"errorSummary": "feature not enabled"})
    return httpx.Response(200, json=[])


def test_fetch_snapshot_and_roundtrip(tmp_path) -> None:
    c = _client(_fake_org_handler)
    snap = fetch_snapshot(c, tool_version="test")
    assert [p["id"] for p in snap.policies] == ["rst1", "gsp1"]
    assert snap.policies[0]["_rules"] == [{"id": "rul1", "priority": 0}]  # from expand=rules
    assert "_embedded" not in snap.policies[0]
    assert snap.policies[1]["_rules"] == [{"id": "rulg", "priority": 0}]  # fetched separately
    assert snap.policy_mappings == {"rst1": ["app1"]}
    assert snap.authenticators[0]["_methods"] == [{"type": "password", "status": "ACTIVE"}]
    assert any("MFA_ENROLL" in w for w in snap.manifest.warnings)
    assert any("device assurance" in w for w in snap.manifest.warnings)
    assert snap.manifest.counts["policies"] == 2

    d = tmp_path / "snap"
    snap.save_dir(d)
    assert json.loads((d / "manifest.json").read_text())["org_url"] == ORG
    again = Snapshot.load(d)
    assert again.to_dict() == snap.to_dict()

    f = tmp_path / "snap.json"
    snap.save_file(f)
    assert Snapshot.load(f).to_dict() == snap.to_dict()
