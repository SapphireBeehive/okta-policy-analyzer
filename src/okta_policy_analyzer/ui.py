"""Local web UI: author invariants, browse policies and principals, see the cases that violate rules.

``okta-policy-analyzer serve SNAPSHOT`` starts a small dependency-free HTTP server (stdlib) that exposes the
analyzer as a JSON API and serves ``ui/index.html``. ``serve --export page.html`` writes a self-contained,
read-only page with the same data embedded (for sharing a review).

API (all JSON):

  GET  /api/state             org, snapshot, counts, assumptions, capabilities (apply allowed?)
  GET  /api/policies          authentication policies with per-rule conditions, strength, who/when, outcomes;
                              global session and enrollment policies
  GET  /api/principals        groups (with the rules that reference them and the group view), users, zones,
                              device assurance policies, user types, apps, authenticators
  GET  /api/findings          analysis findings (the cases that violate the org's own policy intent)
  GET  /api/invariants        saved invariants with their verdicts, readings and counterexamples
  POST /api/invariants/check  {sentence}            check without saving
  POST /api/invariants        {sentence}            save (to the invariants file) and check
  DELETE /api/invariants      {sentence}            remove
  POST /api/propose           {sentence, rule_name?} plan a fix, proved in the model
  POST /api/apply             {plan, inactive?}      apply a plan (only with --allow-apply and credentials)
  POST /api/refresh           {}                     fetch a fresh snapshot (credentials required) and reload

Writes to the org happen only through ``/api/apply``, which is disabled unless the server was started with
``--allow-apply``; the page additionally asks for a typed confirmation.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import __version__
from .analysis import AnalysisOptions, AnalysisResult, Analyzer
from .assurance import classify_rule
from .invariants import check_invariants, explain_result
from .model import PeopleCondition, Rule, RuleConditions, Tenant
from .okta.snapshot import Snapshot
from .remediation import FixPlan, apply_plan, plan_fix

log = logging.getLogger(__name__)


# ------------------------------------------------------------------------------------------ descriptions


def describe_conditions(rc: RuleConditions | None, t: Tenant) -> list[str]:  # noqa: C901 - one clause per condition
    """Human-readable clauses for a rule's conditions (empty list = matches everyone in every context)."""
    if rc is None:
        return []
    out: list[str] = []
    p: PeopleCondition | None = rc.people
    if p and not p.is_trivial():
        everyone = {g.id for g in t.groups.values() if g.is_everyone}
        if p.groups_include and set(p.groups_include) - everyone:
            out.append("groups: " + ", ".join(t.group_name(g) for g in p.groups_include))
        if p.users_include:
            out.append("users: " + ", ".join(_login(t, u) for u in p.users_include))
        if p.groups_exclude:
            out.append("not in groups: " + ", ".join(t.group_name(g) for g in p.groups_exclude))
        if p.users_exclude:
            out.append("not users: " + ", ".join(_login(t, u) for u in p.users_exclude))
    n = rc.network
    if n and n.connection == "ZONE":
        if n.include:
            out.append("from zones: " + ", ".join(t.zone_name(z) for z in n.include))
        if n.exclude:
            out.append("not from zones: " + ", ".join(t.zone_name(z) for z in n.exclude))
    d = rc.device
    if d:
        if d.managed is not None:
            out.append("device managed" if d.managed else "device not managed")
        if d.registered is not None:
            out.append("device registered" if d.registered else "device not registered")
        if d.assurance_include:
            names = [
                t.device_assurances[a].name if a in t.device_assurances else a for a in d.assurance_include
            ]
            out.append("device assurance: " + ", ".join(names))
        if d.platform_types:
            out.append("device platform: " + ", ".join(x.value for x in d.platform_types))
    pl = rc.platform
    if pl and (pl.include or pl.exclude):

        def spec(s: Any) -> str:
            base = s.os_type or s.type
            if s.os_expression:
                base += f" ({s.os_expression})"
            if s.os_version:
                base += f" version {s.os_version}"
            return base

        if pl.include:
            out.append("platform: " + ", ".join(spec(s) for s in pl.include))
        if pl.exclude:
            out.append("platform not: " + ", ".join(spec(s) for s in pl.exclude))
    if rc.risk_level is not None:
        out.append(f"risk {rc.risk_level.value}")
    ut = rc.user_type
    if ut and (ut.include or ut.exclude):
        if ut.include:
            out.append("user type: " + ", ".join(_ut_name(t, x) for x in ut.include))
        if ut.exclude:
            out.append("user type not: " + ", ".join(_ut_name(t, x) for x in ut.exclude))
    if rc.el:
        out.append("expression: " + rc.el.text)
    if rc.auth_type:
        out.append(f"authentication type {rc.auth_type}")
    if rc.idp and rc.idp.provider != "ANY":
        if rc.idp.provider == "OKTA":
            out.append("identity provider: Okta")
        else:
            out.append("identity provider: " + ", ".join(t.idps.get(i, i) for i in rc.idp.idp_ids))
    if rc.behaviors:
        out.append("behaviors: " + ", ".join(rc.behaviors))
    for k in rc.unsupported:
        out.append(f"unmodelled condition: {k}")
    return out


def _login(t: Tenant, uid: str) -> str:
    return next((u.login for u in t.users if u.id == uid), uid)


def _ut_name(t: Tenant, x: str) -> str:
    return t.user_types[x].name if x in t.user_types else x


def _action_summary(rule: Rule, catalogue: Any) -> dict[str, Any]:
    ra = classify_rule(rule, catalogue)
    return {
        "access": ra.access.value,
        "strength": ra.weakest.name,
        "strength_label": ra.label,
        "paths": [p.describe() for p in ra.paths],
        "passwordless_possible": ra.passwordless_possible,
    }


# ------------------------------------------------------------------------------------------ state


@dataclass
class UIState:
    snapshot_path: str
    snapshot: Snapshot
    analyzer: Analyzer
    result: AnalysisResult
    invariants_file: Path | None
    allow_apply: bool = False
    options: AnalysisOptions = field(default_factory=lambda: AnalysisOptions(full_cubes=False))
    _inv_cache: dict[str, dict[str, Any]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # ------------------------------------------------------------------ construction
    @classmethod
    def load(
        cls,
        snapshot_path: str,
        invariants_file: str | None = None,
        *,
        allow_apply: bool = False,
        options: AnalysisOptions | None = None,
    ) -> UIState:
        options = options or AnalysisOptions(full_cubes=False)
        snap = Snapshot.load(snapshot_path)
        an = Analyzer.from_snapshot(snap, options)
        result = an.run()
        return cls(
            snapshot_path=str(snapshot_path),
            snapshot=snap,
            analyzer=an,
            result=result,
            invariants_file=Path(invariants_file) if invariants_file else None,
            allow_apply=allow_apply,
            options=options,
        )

    def reload(self, snapshot_path: str | None = None) -> None:
        with self._lock:
            path = snapshot_path or self.snapshot_path
            self.snapshot = Snapshot.load(path)
            self.analyzer = Analyzer.from_snapshot(self.snapshot, self.options)
            self.result = self.analyzer.run()
            self.snapshot_path = str(path)
            self._inv_cache.clear()

    @property
    def t(self) -> Tenant:
        return self.analyzer.t

    # ------------------------------------------------------------------ views
    def state(self) -> dict[str, Any]:
        m = self.snapshot.manifest
        return {
            "version": __version__,
            "org_url": m.org_url,
            "fetched_at": m.fetched_at,
            "snapshot": self.snapshot_path,
            "counts": m.counts,
            "warnings": list(m.warnings) + list(self.t.warnings),
            "assumptions": self.result.assumptions,
            "stats": self.result.stats,
            "invariants_file": str(self.invariants_file) if self.invariants_file else None,
            "allow_apply": self.allow_apply,
            "credentials": bool(os.environ.get("OKTA_API_TOKEN") or os.environ.get("OKTA_ACCESS_TOKEN")),
            "live": True,
        }

    def policies(self) -> dict[str, Any]:
        t = self.t
        by_id = {a.policy.id: a for a in self.result.access}
        access = []
        for pol in t.access_policies:
            a = by_id.get(pol.id)
            ra_by_id = {r.rule.id: r for r in a.rules} if a else {}
            rules = []
            for r in pol.rules:
                ra = ra_by_id.get(r.id)
                entry: dict[str, Any] = {
                    "id": r.id,
                    "name": r.name,
                    "priority": r.priority,
                    "status": r.status.value,
                    "system": r.system,
                    "conditions": describe_conditions(r.conditions, t),
                    "raw": r.raw,
                }
                entry.update(_action_summary(r, self.analyzer.catalogue))
                if ra:
                    entry.update(
                        {
                            "reachable": ra.reachable,
                            "shadowed_by": [x.name for x in ra.shadowed_by],
                            "redundant": ra.redundant,
                            "who": ra.who,
                            "when": ra.when,
                            "enrollment_gap_who": ra.enrollment_gap_who,
                        }
                    )
                rules.append(entry)
            access.append(
                {
                    "id": pol.id,
                    "name": pol.name,
                    "status": pol.status.value,
                    "priority": pol.priority,
                    "resource_type": pol.resource_type,
                    "apps": [t.app_label(x) for x in pol.app_ids],
                    "rules": rules,
                    "outcomes": [o.to_dict() for o in a.outcomes] if a else [],
                    "weakest": a.weakest.name if a else None,
                    "weakest_label": a.weakest.label if a else None,
                    "weakest_witness": a.weakest_witness if a else None,
                    "combined_weakest": (a.combined_weakest.name if a and a.combined_weakest else None),
                    "findings": [f.to_dict() for f in self.result.findings if f.policy == pol.name],
                }
            )
        return {
            "access": access,
            "session": [p.to_dict() for p in self.result.session],
            "enrollment": [p.to_dict() for p in self.result.enrollment],
            "apps_without_policy": self.result.apps_without_policy,
        }

    def principals(self) -> dict[str, Any]:  # noqa: C901
        t = self.t
        refs: dict[str, list[dict[str, str]]] = {}
        zone_refs: dict[str, list[dict[str, str]]] = {}
        da_refs: dict[str, list[dict[str, str]]] = {}
        user_refs: dict[str, list[dict[str, str]]] = {}
        for pol in t.access_policies + t.session_policies + t.enrollment_policies:
            for g in pol.group_include:
                refs.setdefault(g, []).append(
                    {"policy": pol.name, "rule": "(policy scope)", "how": "include"}
                )
            for r in pol.rules:
                c = r.conditions
                if c.people:
                    for g in c.people.groups_include:
                        refs.setdefault(g, []).append({"policy": pol.name, "rule": r.name, "how": "include"})
                    for g in c.people.groups_exclude:
                        refs.setdefault(g, []).append({"policy": pol.name, "rule": r.name, "how": "exclude"})
                    for u in c.people.users_include:
                        user_refs.setdefault(u, []).append(
                            {"policy": pol.name, "rule": r.name, "how": "include"}
                        )
                    for u in c.people.users_exclude:
                        user_refs.setdefault(u, []).append(
                            {"policy": pol.name, "rule": r.name, "how": "exclude"}
                        )
                if c.network:
                    for z in c.network.include:
                        zone_refs.setdefault(z, []).append(
                            {"policy": pol.name, "rule": r.name, "how": "include"}
                        )
                    for z in c.network.exclude:
                        zone_refs.setdefault(z, []).append(
                            {"policy": pol.name, "rule": r.name, "how": "exclude"}
                        )
                if c.device:
                    for d in c.device.assurance_include:
                        da_refs.setdefault(d, []).append(
                            {"policy": pol.name, "rule": r.name, "how": "include"}
                        )
        rule_managed: dict[str, list[str]] = {}
        for gr in t.group_rules:
            for g in gr.target_group_ids:
                rule_managed.setdefault(g, []).append(gr.name)
        gv: dict[str, list[dict[str, Any]]] = {}
        for cell in self.result.group_view:
            gv.setdefault(cell.group, []).append(cell.to_dict())
        groups = [
            {
                "id": g.id,
                "name": g.name,
                "type": g.type,
                "users_count": g.users_count,
                "description": g.description,
                "everyone": g.is_everyone,
                "managed_by_rules": rule_managed.get(g.id, []),
                "referenced_by": refs.get(g.id, []),
                "view": gv.get(g.name, []),
            }
            for g in sorted(t.groups.values(), key=lambda x: (not x.is_everyone, x.name.lower()))
        ]
        missing = [
            {
                "id": gid,
                "name": gid,
                "type": "MISSING",
                "referenced_by": r,
                "view": [],
                "managed_by_rules": [],
            }
            for gid, r in refs.items()
            if gid not in t.groups
        ]
        return {
            "groups": groups + missing,
            "group_rules": [
                {
                    "id": gr.id,
                    "name": gr.name,
                    "status": gr.status.value,
                    "expression": gr.expression,
                    "targets": [t.group_name(g) for g in gr.target_group_ids],
                    "parse_error": gr.parse_error,
                }
                for gr in t.group_rules
            ],
            "users": [
                {
                    "id": u.id,
                    "login": u.login,
                    "status": u.status,
                    "user_type": _ut_name(t, u.user_type_id) if u.user_type_id else None,
                    "groups": [t.group_name(g) for g in u.group_ids],
                    "referenced_by": user_refs.get(u.id, []),
                }
                for u in t.users
            ],
            "user_refs_unknown": [
                {"id": uid, "referenced_by": r}
                for uid, r in user_refs.items()
                if not any(u.id == uid for u in t.users)
            ],
            "zones": [
                {
                    "id": z.id,
                    "name": z.name,
                    "type": z.type,
                    "status": z.status.value,
                    "usage": z.usage,
                    "system": z.system,
                    "summary": z.summary,
                    "referenced_by": zone_refs.get(z.id, []),
                }
                for z in t.zones.values()
            ],
            "device_assurances": [
                {
                    "id": d.id,
                    "name": d.name,
                    "platform": d.platform.value,
                    "referenced_by": da_refs.get(d.id, []),
                }
                for d in t.device_assurances.values()
            ],
            "user_types": [
                {"id": x.id, "name": x.name, "display_name": x.display_name, "default": x.default}
                for x in t.user_types.values()
            ],
            "apps": [
                {
                    "id": a.id,
                    "label": a.label,
                    "status": a.status.value,
                    "sign_on_mode": a.sign_on_mode,
                    "policy": next((p.name for p in t.access_policies if p.id == a.access_policy_id), None),
                }
                for a in sorted(t.apps.values(), key=lambda x: x.label.lower())
            ],
            "authenticators": [
                {
                    "key": a.key,
                    "name": a.name,
                    "type": a.type,
                    "status": a.status.value,
                    "methods": [{"type": m.type, "status": m.status.value} for m in a.methods],
                }
                for a in t.authenticators.values()
            ],
        }

    def findings(self) -> list[dict[str, Any]]:
        return [f.to_dict() for f in self.result.findings]

    # ------------------------------------------------------------------ invariants
    def saved_sentences(self) -> list[str]:
        if not self.invariants_file or not self.invariants_file.exists():
            return []
        out = []
        for raw in self.invariants_file.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                out.append(line)
        return out

    def _write_sentences(self, sentences: list[str]) -> None:
        if not self.invariants_file:
            raise ValueError("no invariants file: start the server with --invariants FILE to save")
        header = "# Okta authentication-policy invariants (one per line; checked by okta-policy-analyzer)\n"
        self.invariants_file.write_text(header + "".join(s + "\n" for s in sentences), encoding="utf-8")

    def check(self, sentence: str) -> dict[str, Any]:
        sentence = " ".join(sentence.split())
        if not sentence:
            raise ValueError("empty invariant")
        with self._lock:
            if sentence in self._inv_cache:
                return self._inv_cache[sentence]
            (res,) = check_invariants(self.analyzer, [sentence])
            d = res.to_dict()
            d["text"] = "\n".join(explain_result(res, self.t))
            d["checked_at"] = datetime.now(UTC).isoformat(timespec="seconds")
            self._inv_cache[sentence] = d
            return d

    def invariants(self) -> list[dict[str, Any]]:
        return [dict(self.check(s), saved=True) for s in self.saved_sentences()]

    def save(self, sentence: str) -> dict[str, Any]:
        sentence = " ".join(sentence.split())
        sentences = self.saved_sentences()
        if sentence not in sentences:
            sentences.append(sentence)
            self._write_sentences(sentences)
        return dict(self.check(sentence), saved=True)

    def remove(self, sentence: str) -> None:
        sentence = " ".join(sentence.split())
        sentences = [s for s in self.saved_sentences() if s != sentence]
        self._write_sentences(sentences)

    # ------------------------------------------------------------------ remediation
    def propose(self, sentence: str, rule_name: str | None = None) -> dict[str, Any]:
        with self._lock:
            plan = plan_fix(self.snapshot, sentence, self.options, rule_name=rule_name or None)
        d = plan.to_dict()
        d["text"] = plan.to_text()
        return d

    def apply(self, plan_dict: dict[str, Any], *, inactive: bool = False) -> dict[str, Any]:
        if not self.allow_apply:
            raise PermissionError("applying changes is disabled; start the server with --allow-apply")
        plan = FixPlan.from_dict(plan_dict)
        if plan.status != "FIX_PROVED":
            raise ValueError(f"plan status is {plan.status}, not FIX_PROVED")
        client = self._client()
        try:
            record = apply_plan(client, plan, activate=not inactive)
        finally:
            client.close()
        out = Path(
            self.snapshot_path.rstrip("/\\") + f".applied-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        )
        out.write_text(record.to_json(), encoding="utf-8")
        d = record.to_dict()
        d["record_file"] = str(out)
        return d

    def refresh(self) -> dict[str, Any]:
        from .okta.snapshot import fetch_snapshot

        client = self._client()
        try:
            snap = fetch_snapshot(
                client, with_users=self.snapshot.manifest.with_users, tool_version=__version__
            )
        finally:
            client.close()
        base = Path(self.snapshot_path)
        out = base.parent / f"{base.name.split('.')[0]}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        snap.save_dir(out)
        self.reload(str(out))
        return self.state()

    def _client(self) -> Any:
        from .okta.client import OktaClient

        org = os.environ.get("OKTA_ORG_URL") or self.snapshot.manifest.org_url
        token = os.environ.get("OKTA_API_TOKEN")
        bearer = os.environ.get("OKTA_ACCESS_TOKEN")
        if not org or not (token or bearer):
            raise PermissionError(
                "no credentials: set OKTA_ORG_URL and OKTA_API_TOKEN (or OKTA_ACCESS_TOKEN)"
            )
        return OktaClient(org, api_token=token or None, bearer_token=bearer or None)

    # ------------------------------------------------------------------ static export
    def export_html(self) -> str:
        data = {
            "state": dict(self.state(), live=False, allow_apply=False, credentials=False),
            "policies": self.policies(),
            "principals": self.principals(),
            "findings": self.findings(),
            "invariants": self.invariants(),
        }
        blob = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
        page = index_html()
        return page.replace("<!--DATA-->", f"<script>window.__DATA__ = {blob};</script>")


def index_html() -> str:
    return resources.files("okta_policy_analyzer").joinpath("ui/index.html").read_text(encoding="utf-8")


# ------------------------------------------------------------------------------------------ http


class Handler(BaseHTTPRequestHandler):
    state: UIState  # set by make_server

    def log_message(self, fmt: str, *args: Any) -> None:  # quieter default logging
        log.info("%s " + fmt, self.address_string(), *args)

    # ---- helpers
    def _json(self, obj: Any, status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict[str, Any]:
        n = int(self.headers.get("Content-Length") or 0)
        if n == 0:
            return {}
        try:
            data = json.loads(self.rfile.read(n).decode("utf-8"))
        except json.JSONDecodeError as e:
            raise ValueError(f"invalid JSON body: {e}") from e
        return data if isinstance(data, dict) else {}

    def _route(self, method: str) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        st = self.state
        try:
            if method == "GET":
                if path == "/":
                    return self._html(index_html())
                if path == "/api/state":
                    return self._json(st.state())
                if path == "/api/policies":
                    return self._json(st.policies())
                if path == "/api/principals":
                    return self._json(st.principals())
                if path == "/api/findings":
                    return self._json(st.findings())
                if path == "/api/invariants":
                    return self._json(st.invariants())
                if path == "/api/export":
                    return self._html(st.export_html())
            elif method == "POST":
                body = self._body()
                if path == "/api/invariants/check":
                    return self._json(st.check(str(body.get("sentence", ""))))
                if path == "/api/invariants":
                    return self._json(st.save(str(body.get("sentence", ""))))
                if path == "/api/propose":
                    return self._json(st.propose(str(body.get("sentence", "")), body.get("rule_name")))
                if path == "/api/apply":
                    if not isinstance(body.get("plan"), dict):
                        raise ValueError("body.plan must be a plan object from /api/propose")
                    if body.get("confirm") != "APPLY":
                        raise ValueError("confirmation missing: send confirm: 'APPLY'")
                    return self._json(st.apply(body["plan"], inactive=bool(body.get("inactive"))))
                if path == "/api/refresh":
                    return self._json(st.refresh())
            elif method == "DELETE":
                body = self._body()
                if path == "/api/invariants":
                    st.remove(str(body.get("sentence", "")))
                    return self._json({"ok": True})
            return self._json({"error": f"no such endpoint: {method} {path}"}, HTTPStatus.NOT_FOUND)
        except PermissionError as e:
            return self._json({"error": str(e)}, HTTPStatus.FORBIDDEN)
        except (ValueError, KeyError) as e:
            return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)
        except Exception as e:  # noqa: BLE001 - surface to the page rather than dropping the connection
            log.exception("request failed")
            return self._json({"error": f"{type(e).__name__}: {e}"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_GET(self) -> None:  # noqa: N802
        self._route("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._route("POST")

    def do_DELETE(self) -> None:  # noqa: N802
        self._route("DELETE")


def make_server(state: UIState, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"state": state})
    srv = ThreadingHTTPServer((host, port), handler)
    srv.daemon_threads = True
    return srv


def serve(state: UIState, host: str = "127.0.0.1", port: int = 8765) -> None:
    srv = make_server(state, host, port)
    print(f"okta-policy-analyzer UI at http://{host}:{srv.server_address[1]}/  (Ctrl-C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
