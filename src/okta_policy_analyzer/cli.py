"""Command-line interface.

okta-policy-analyzer fetch   --org https://acme.okta.com [--with-users] -o snapshot/
okta-policy-analyzer analyze snapshot/ [--assertions rules.yaml] [--format text|markdown|json] [-o report.md]
okta-policy-analyzer verify  snapshot/ --assertions rules.yaml        (exit 1 when an assertion is violated)
okta-policy-analyzer explain snapshot/ --user alice@acme.com [--zone VPN --managed --platform MACOS ...]
okta-policy-analyzer who     snapshot/ --app Salesforce [--min-strength TWO_FA]
okta-policy-analyzer export-tla snapshot/ -o tla/ [--policy NAME] [--assertions rules.yaml] [--run-tlc JAR]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from . import __version__

log = logging.getLogger("okta_policy_analyzer")


def _load_tenant(path: str):
    from .loader import load_tenant
    from .okta.snapshot import Snapshot

    return load_tenant(Snapshot.load(path))


def _analyzer(args: argparse.Namespace):
    from .analysis import Analyzer
    from .okta.snapshot import Snapshot

    return Analyzer.from_snapshot(Snapshot.load(args.snapshot), _options(args))


def _options(args: argparse.Namespace):
    import yaml

    from .analysis import AnalysisOptions
    from .smt.universe import UniverseOptions

    overrides = None
    if getattr(args, "authenticator_overrides", None):
        with open(args.authenticator_overrides, encoding="utf-8") as fh:
            overrides = yaml.safe_load(fh)
    return AnalysisOptions(
        universe=UniverseOptions(
            strict_group_rules=bool(getattr(args, "strict_group_rules", False)),
            assurance_requires_registered=not getattr(args, "assurance_without_registration", False),
            blocklist_zones_unreachable=not getattr(args, "evaluate_blocklisted", False),
        ),
        authenticator_overrides=overrides,
        full_cubes=not getattr(args, "no_cubes", False),
        dnf_limit=getattr(args, "dnf_limit", 48),
        combined_who=bool(getattr(args, "combined_who", False)),
    )


# ------------------------------------------------------------------------------------------ commands


def cmd_fetch(args: argparse.Namespace) -> int:
    from .okta.client import OktaClient
    from .okta.snapshot import fetch_snapshot

    if not args.org:
        print("error: pass --org https://your-org.okta.com or set $OKTA_ORG_URL", file=sys.stderr)
        return 2
    token = os.environ.get(args.token_env) if args.token_env else None
    bearer = os.environ.get(args.bearer_env) if args.bearer_env else None
    if not token and not bearer:
        print(
            f"error: set the API token in ${args.token_env} (SSWS) or ${args.bearer_env} (OAuth bearer)",
            file=sys.stderr,
        )
        return 2
    with OktaClient(args.org, api_token=token, bearer_token=bearer) as client:
        snap = fetch_snapshot(
            client,
            with_users=args.with_users,
            progress=lambda m: print(m, file=sys.stderr),
            tool_version=__version__,
        )
    out = Path(args.output)
    if out.suffix == ".json":
        snap.save_file(out)
    else:
        snap.save_dir(out)
    print(
        f"snapshot written to {out}: " + ", ".join(f"{k}={v}" for k, v in snap.manifest.counts.items() if v)
    )
    for w in snap.manifest.warnings:
        print(f"warning: {w}", file=sys.stderr)
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    from .assertions import AssertionChecker, load_assertions
    from .report import findings_summary, render_console, render_markdown, render_sarif

    analyzer = _analyzer(args)
    result = analyzer.run(jobs=max(1, args.jobs))
    assertions = None
    if args.assertions:
        assertions = AssertionChecker(analyzer).check_all(load_assertions(args.assertions))
    if args.format == "json":
        payload = result.to_dict()
        if assertions is not None:
            payload["assertions"] = [r.to_dict() for r in assertions]
        text = json.dumps(payload, indent=2, ensure_ascii=False)
        _emit(text, args.output)
    elif args.format == "markdown":
        _emit(render_markdown(result, assertions), args.output)
    elif args.format == "sarif":
        _emit(render_sarif(result, snapshot_uri=args.snapshot), args.output)
    else:
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                render_console(result, assertions, file=fh, verbose=args.verbose)
        else:
            render_console(result, assertions, verbose=args.verbose)
    print(f"\n{findings_summary(result.findings)} findings", file=sys.stderr)
    violated = [r for r in (assertions or []) if not r.holds]
    if violated:
        print(f"{len(violated)} assertion(s) violated", file=sys.stderr)
    high = [f for f in result.findings if f.severity == "HIGH"]
    if args.fail_on_high and high:
        return 1
    return 1 if violated and args.fail_on_violation else 0


def cmd_verify(args: argparse.Namespace) -> int:
    args.fail_on_violation = True
    args.fail_on_high = False
    return cmd_analyze(args)


def cmd_check(args: argparse.Namespace) -> int:
    """Plain-English invariants → proof or counterexample. Exit 0 all proved, 1 violated, 2 unparseable."""
    import json

    import yaml

    from .invariants import _assertion_dict, check_invariants, explain_result

    sentences: list[str] = list(args.sentences or [])
    if args.file:
        for raw in Path(args.file).read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                sentences.append(line)
    if not sentences:
        raise ValueError("no invariants given: pass sentences as arguments or --file FILE (one per line)")
    an = _analyzer(args)
    results = check_invariants(an, sentences)
    if args.yaml_out:
        doc = {
            "assertions": [
                _assertion_dict(r.parsed.assertion) for r in results if r.parsed.assertion is not None
            ]
        }
        Path(args.yaml_out).write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
        print(f"assertions written to {args.yaml_out}", file=sys.stderr)
    if args.format == "json":
        _emit(json.dumps([r.to_dict() for r in results], indent=2, default=str), args.output)
    else:
        blocks = ["\n".join(explain_result(r, an.t)) for r in results]
        counts = {
            v: sum(1 for r in results if r.verdict == v)
            for v in ("PROVED", "VIOLATED", "VACUOUS", "UNPARSED", "ERROR")
        }
        summary = "summary: " + ", ".join(f"{n} {v.lower()}" for v, n in counts.items() if n)
        _emit("\n\n".join(blocks) + "\n\n" + summary, args.output)
    verdicts = {r.verdict for r in results}
    if verdicts & {"UNPARSED", "ERROR"}:
        return 2
    return 1 if "VIOLATED" in verdicts else 0


def _client(args: argparse.Namespace, default_org: str | None = None):
    from .okta.client import OktaClient

    org = getattr(args, "org", None) or os.environ.get("OKTA_ORG_URL") or default_org
    if not org:
        raise ValueError("no org URL: pass --org or set $OKTA_ORG_URL")
    token = os.environ.get(args.token_env) if getattr(args, "token_env", None) else None
    bearer = os.environ.get(args.bearer_env) if getattr(args, "bearer_env", None) else None
    if not token and not bearer:
        raise ValueError(
            f"set the API token in ${args.token_env} (SSWS) or ${args.bearer_env} (OAuth bearer)"
        )
    return OktaClient(org, api_token=token, bearer_token=bearer)


def cmd_propose(args: argparse.Namespace) -> int:
    """Invariant → proposed rule change, proved in the model. Exit 0 fix proved, 1 not fixable, 2 unparseable."""
    import json

    from .okta.snapshot import Snapshot
    from .remediation import apply_ops_to_snapshot, plan_fix

    snap = Snapshot.load(args.snapshot)
    plan = plan_fix(snap, args.sentence, _options(args), rule_name=args.rule_name)
    if args.plan_out:
        Path(args.plan_out).write_text(plan.to_json(), encoding="utf-8")
        print(f"plan written to {args.plan_out}", file=sys.stderr)
    if args.patched_snapshot and plan.ops:
        apply_ops_to_snapshot(snap, plan.ops).save_dir(args.patched_snapshot)
        print(f"patched snapshot written to {args.patched_snapshot}", file=sys.stderr)
    if args.format == "json":
        _emit(json.dumps(plan.to_dict(), indent=2, ensure_ascii=False), args.output)
    else:
        _emit(plan.to_text(), args.output)
    if plan.status in ("UNPARSED", "ERROR"):
        return 2
    return 0 if plan.status in ("FIX_PROVED", "ALREADY_HOLDS") else 1


def cmd_apply(args: argparse.Namespace) -> int:
    """Apply a plan written by `propose` to the org. Requires --yes; --dry-run prints the requests."""
    import json

    from .remediation import FixPlan, api_body, apply_plan

    plan = FixPlan.from_dict(json.loads(Path(args.plan).read_text(encoding="utf-8")))
    if not plan.ops:
        print("plan has no operations; nothing to apply")
        return 0
    if plan.status != "FIX_PROVED" and not args.force:
        print(
            f"error: plan status is {plan.status}, not FIX_PROVED; re-run `propose` or pass --force",
            file=sys.stderr,
        )
        return 2
    lines = []
    for op in plan.ops:
        if op.op == "create":
            lines.append(f"POST /api/v1/policies/{op.policy_id}/rules   ({op.policy_name!r})")
        else:
            lines.append(f"PUT  /api/v1/policies/{op.policy_id}/rules/{op.rule_id}   ({op.policy_name!r})")
        body = api_body(op.rule)
        if not args.activate:
            body["status"] = "INACTIVE"
        lines += ["    " + ln for ln in json.dumps(body, indent=2, ensure_ascii=False).splitlines()]
    print("\n".join(lines))
    if args.dry_run:
        print("dry run: nothing sent")
        return 0
    if not args.yes:
        print("error: refusing to change the org without --yes (or use --dry-run)", file=sys.stderr)
        return 2
    with _client(args) as client:
        record = apply_plan(client, plan, activate=args.activate)
    out = Path(args.record_out or (str(args.plan) + ".applied.json"))
    out.write_text(record.to_json(), encoding="utf-8")
    for a in record.applied:
        print(f"{a.op}d rule {a.rule_id} in policy {a.policy_id}")
    print(f"rollback record written to {out}")
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    """Undo an `apply` using its record. Requires --yes."""
    import json

    from .remediation import ApplyRecord, rollback

    record = ApplyRecord.from_dict(json.loads(Path(args.record).read_text(encoding="utf-8")))
    for a in record.applied:
        if a.op == "create":
            print(f"DELETE /api/v1/policies/{a.policy_id}/rules/{a.rule_id}")
        else:
            print(f"PUT    /api/v1/policies/{a.policy_id}/rules/{a.rule_id}  (restore previous body)")
    if args.dry_run:
        print("dry run: nothing sent")
        return 0
    if not args.yes:
        print("error: refusing to change the org without --yes (or use --dry-run)", file=sys.stderr)
        return 2
    with _client(args, default_org=record.org_url) as client:
        for line in rollback(client, record):
            print(line)
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    from .assurance import Catalogue, classify_rule, combined_rule_strength
    from .interpreter import Interpreter, World, world_from_user
    from .model import DevicePlatform, RiskLevel, SignOnAction

    tenant = _load_tenant(args.snapshot)
    it = Interpreter(tenant)
    ctx: dict = {}
    if args.zone:
        ctx["zones"] = {_zone_id(tenant, z) for z in args.zone}
    if args.registered or args.managed:
        ctx["registered"] = True
    if args.managed:
        ctx["managed"] = True
    if args.platform:
        ctx["platform"] = DevicePlatform(args.platform.upper())
    if args.assurance:
        ctx["assurances"] = {_assurance_id(tenant, a) for a in args.assurance}
        ctx.setdefault("registered", True)
        plats = {
            tenant.device_assurances[d].platform for d in ctx["assurances"] if d in tenant.device_assurances
        }
        if len(plats) > 1:
            raise ValueError(
                f"device assurance policies for different platforms given: {sorted(p.value for p in plats)}"
            )
        if plats:
            (plat,) = plats
            if "platform" in ctx and ctx["platform"] != plat:
                raise ValueError(
                    f"device assurance policy is for {plat.value} but --platform {ctx['platform'].value} was given"
                )
            ctx["platform"] = plat
    if args.risk:
        ctx["risk"] = RiskLevel(args.risk.upper())
    if args.user:
        try:
            world = world_from_user(tenant, args.user, **ctx)
        except KeyError:
            if not args.group:
                print(
                    f"error: user {args.user!r} not in snapshot (fetch with --with-users) and no --group given",
                    file=sys.stderr,
                )
                return 2
            world = World(groups={_group_id(tenant, g) for g in args.group}, user_id=args.user, **ctx)
    else:
        world = World(groups={_group_id(tenant, g) for g in (args.group or [])}, **ctx)
    if args.attr:
        for kv in args.attr:
            k, _, v = kv.partition("=")
            world.attrs[k if k.startswith("user.") else f"user.{k}"] = v
    if args.user_type:
        world.user_type = next(
            (t.id for t in tenant.user_types.values() if t.name == args.user_type or t.id == args.user_type),
            args.user_type,
        )
    elif world.user_type is None:
        world.user_type = next((t.id for t in tenant.user_types.values() if t.default), None)
    cat = Catalogue.for_tenant(tenant)
    print(
        f"World: groups={{{', '.join(tenant.group_name(g) for g in sorted(world.groups))}}} zones={{{', '.join(tenant.zone_name(z) for z in sorted(world.zones))}}} "
        f"device={'managed' if world.managed else ('registered' if world.registered else 'unregistered')} {world.platform.value} risk={world.risk.value}"
        + (
            f" assurance={{{', '.join(tenant.device_assurances[d].name if d in tenant.device_assurances else d for d in sorted(world.assurances))}}}"
            if world.assurances
            else ""
        )
    )
    sel = it.select(tenant.session_policies, world)
    session_action = None
    if sel:
        pol, rule = sel
        print(f"\nGlobal session policy: {pol.name} → rule {rule.name!r}")
        if isinstance(rule.action, SignOnAction):
            session_action = rule.action
            a = rule.action
            print(
                f"  access={a.access.value} primary={a.primary_factor.value} requireFactor={a.require_factor} prompt={a.factor_prompt_mode.value if a.factor_prompt_mode else '-'}"
            )
    else:
        print("\nGlobal session policy: no policy decides (denied)")
    enr = it.select(tenant.enrollment_policies, world)
    allowed: set[str] | None = None
    if enr:
        pol, rule = enr
        if pol.authenticator_settings:
            allowed = {s.key for s in pol.authenticator_settings if s.enroll_self.value != "NOT_ALLOWED"}
        print(
            f"Enrollment policy: {pol.name} → can enroll: {', '.join(sorted(allowed)) if allowed else '(unknown)'}"
        )
    print("\nApps:")
    apps = [a for a in tenant.apps.values() if not args.app or a.label == args.app or a.id == args.app]
    for app in sorted(apps, key=lambda a: a.label):
        pol = tenant.access_policy_for_app(app.id)
        if pol is None:
            print(f"  {app.label}: no authentication policy")
            continue
        rule = it.first_matching_rule(pol, world)
        if rule is None:
            print(f"  {app.label}: no rule matched → DENY")
            continue
        ra = classify_rule(rule, cat)
        line = f"  {app.label}: [{pol.name}] rule {rule.name!r} → {ra.label}"
        if session_action is not None and ra.paths:
            line += f"; with session policy: {combined_rule_strength(session_action, ra).label}"
        if allowed is not None and ra.paths and enr is not None:
            enrollable = [p for p in ra.paths if p.authenticator_keys <= allowed]
            if not enrollable:
                needed = sorted({k for p in ra.paths for k in p.authenticator_keys} - allowed)
                line += f" — LOCKED OUT: every accepted path needs one of {needed}, not enrollable under {enr[0].name!r}"
        print(line)
        if args.verbose and ra.paths:
            for p in ra.paths:
                print(f"      - {p.describe()}")
    return 0


def cmd_who(args: argparse.Namespace) -> int:
    from .analysis import Analyzer
    from .assurance import Strength

    tenant = _load_tenant(args.snapshot)
    an = Analyzer(tenant, _options(args))
    app = next((a for a in tenant.apps.values() if a.label == args.app or a.id == args.app), None)
    pol = (
        tenant.access_policy_for_app(app.id)
        if app
        else (
            tenant.policy(args.app) or next((p for p in tenant.access_policies if p.name == args.app), None)
        )
    )
    if pol is None:
        print(f"error: unknown app or policy {args.app!r}", file=sys.stderr)
        return 2
    ep = an.enc.access_policy(pol)
    import z3

    from .assurance import classify_rule

    rows: list[tuple[Strength, str, list[str], list[str]]] = []
    min_s = Strength[args.min_strength] if args.min_strength else None
    max_s = Strength[args.max_strength] if args.max_strength else None
    for i, rule in enumerate(ep.rules):
        ra = classify_rule(rule, an.catalogue)
        strength = ra.weakest if ra.access.value == "ALLOW" else Strength.DENY
        if min_s is not None and strength < min_s:
            continue
        if max_s is not None and (
            strength > max_s or (strength <= Strength.NO_PATH and not args.include_deny)
        ):
            continue
        if not an.sat(ep.effective[i]):
            continue
        rows.append(
            (strength, rule.name, an.lines(an.who(ep.effective[i])), an.lines(an.when(ep.effective[i])))
        )
    print(f"Policy {pol.name!r} (apps: {', '.join(tenant.app_label(a) for a in pol.app_ids)})")
    for strength, name, who, when in rows:
        print(f"\n{strength.label}  ←  rule {name!r}")
        for w in who:
            print(f"   who:  {w}")
        for w in when:
            print(f"   when: {w}")
    if not rows:
        print("  nobody")
    _ = z3
    return 0


def cmd_export_tla(args: argparse.Namespace) -> int:
    from .analysis import Analyzer
    from .assertions import load_assertions
    from .tla import TLAExporter, run_tlc_each

    tenant = _load_tenant(args.snapshot)
    an = Analyzer(tenant, _options(args))
    ex = TLAExporter(an)
    assertions = load_assertions(args.assertions) if args.assertions else []
    policies = [
        p for p in tenant.access_policies if not args.policy or p.name == args.policy or p.id == args.policy
    ]
    if not policies:
        print(f"error: no policy matches {args.policy!r}", file=sys.stderr)
        return 2
    rc = 0
    for pol in policies:
        relevant = [
            a
            for a in assertions
            if a.all_apps
            or a.policy in (pol.id, pol.name)
            or any(
                tenant.access_policy_for_app(_app_id(tenant, x)) is pol for x in a.apps if _app_id(tenant, x)
            )
        ]
        e = ex.export_policy(pol, relevant)
        tla, cfg = e.write(args.output)
        print(
            f"{pol.name}: wrote {tla.name} and {cfg.name} (~{e.estimated_states:,} worlds, invariants: {', '.join(e.invariants)})"
        )
        if args.run_tlc:
            invs = list(e.invariants) + (list(e.reachability_probes) if args.tlc_probes else [])
            results = run_tlc_each(tla, args.run_tlc, invs, timeout=args.tlc_timeout)
            for inv, res in results.items():
                label = e.reachability_probes.get(inv)
                if res.error:
                    print(f"  TLC {inv}: error {res.error}")
                    rc = 1
                elif label is not None:
                    print(
                        f"  TLC rule {label!r}: {'reachable' if inv in res.violated else 'UNREACHABLE'}"
                        + (
                            f" (witness: {res.witness_for(inv)})"
                            if args.verbose and inv in res.violated
                            else ""
                        )
                    )
                elif inv in res.violated:
                    print(f"  TLC {inv}: VIOLATED ({res.states} states)")
                    w = res.witness_for(inv)
                    if w:
                        print("    " + w.replace("\n", "\n    "))
                    rc = 1
                else:
                    print(f"  TLC {inv}: holds ({res.states} states)")
    return rc


def cmd_simulate_validate(args: argparse.Namespace) -> int:
    """Compare the encoder with Okta's policy simulation API on sampled worlds (needs API access)."""
    from .analysis import Analyzer
    from .okta.client import OktaClient
    from .okta.simulate import validate_app

    tenant = _load_tenant(args.snapshot)
    token = os.environ.get(args.token_env) if args.token_env else None
    bearer = os.environ.get(args.bearer_env) if args.bearer_env else None
    if not token and not bearer:
        print(f"error: set the API token in ${args.token_env} or ${args.bearer_env}", file=sys.stderr)
        return 2
    an = Analyzer(tenant, _options(args))
    apps = [
        a
        for a in tenant.apps.values()
        if (not args.app or a.label == args.app or a.id == args.app) and a.access_policy_id
    ]
    rc = 0
    with OktaClient(args.org or tenant.org_url, api_token=token, bearer_token=bearer) as client:
        for app in sorted(apps, key=lambda a: a.label):
            rep = validate_app(an, client, app, samples=args.samples, seed=args.seed)
            status = (
                "OK"
                if rep.ok
                else (
                    "INCONCLUSIVE (0 verdicts compared)"
                    if rep.inconclusive
                    else f"{len(rep.mismatches)} MISMATCH(ES)"
                )
            )
            if rep.inconclusive:
                rc = max(rc, 3)
            print(
                f"{app.label}: {rep.compared} verdicts compared from {rep.samples} sampled worlds; skipped {rep.skipped_not_assigned} unassigned, {rep.skipped_unsupported} undefined → {status}"
            )
            for m in rep.mismatches:
                rc = 1
                print(
                    f"  {m.policy_type}: expected {m.expected_policy}/{m.expected_rule}, Okta says {m.okta_policy}/{m.okta_rule}"
                )
                print(f"    request: {json.dumps(m.request)}")
    return rc


def cmd_diff(args: argparse.Namespace) -> int:
    """Compare two snapshots: which apps became more or less permissive, for whom."""
    from .diff import diff_tenants

    old = _load_tenant(args.old)
    new = _load_tenant(args.new)
    res = diff_tenants(old, new, _options(args))
    if args.format == "json":
        _emit(res.to_json(), args.output)
    else:
        lines: list[str] = [
            f"Snapshot diff: {res.old_fetched_at or args.old}  →  {res.new_fetched_at or args.new}",
            "",
        ]
        for a in res.apps:
            lines.append(
                f"{a.app}: {a.verdict}  (policy {a.old_policy!r} → {a.new_policy!r}; weakest {a.old_weakest} → {a.new_weakest})"
            )
            for w in a.new_access:
                lines.append(f"    + new access:   {w}")
            for w in a.weaker:
                lines.append(f"    ~ weaker auth:  {w}")
            for w in a.lost_access:
                lines.append(f"    - lost access:  {w}")
            for w in a.stronger:
                lines.append(f"    ^ stronger auth: {w}")
            if a.witness_new_access:
                lines.append(f"    witness (new access): {a.witness_new_access}")
            elif a.witness_weaker:
                lines.append(f"    witness (weaker): {a.witness_weaker}")
            for c in a.rule_changes:
                lines.append(f"    rule {c.kind}: {c.rule}{' — ' + c.detail if c.detail else ''}")
        if res.apps_added:
            lines.append("apps added: " + ", ".join(res.apps_added))
        if res.apps_removed:
            lines.append("apps removed: " + ", ".join(res.apps_removed))
        lines.append("")
        lines.append("assumptions: " + "; ".join(res.assumptions))
        _emit("\n".join(lines), args.output)
    return 1 if (args.fail_on_more_permissive and res.more_permissive) else 0


# ------------------------------------------------------------------------------------------ helpers


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
        print(f"written to {output}", file=sys.stderr)
    else:
        print(text)


def _group_id(tenant, name: str) -> str:
    if name in tenant.groups:
        return name
    for g in tenant.groups.values():
        if g.name == name:
            return g.id
    raise SystemExit(f"error: unknown group {name!r}")


def _zone_id(tenant, name: str) -> str:
    if name in tenant.zones:
        return name
    for z in tenant.zones.values():
        if z.name == name:
            return z.id
    raise SystemExit(f"error: unknown zone {name!r}")


def _assurance_id(tenant, name: str) -> str:
    if name in tenant.device_assurances:
        return name
    for d in tenant.device_assurances.values():
        if d.name == name:
            return d.id
    raise SystemExit(f"error: unknown device assurance policy {name!r}")


def _app_id(tenant, label: str) -> str | None:
    if label in tenant.apps:
        return label
    return next((a.id for a in tenant.apps.values() if a.label == label), None)


# ------------------------------------------------------------------------------------------ parser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="okta-policy-analyzer",
        description="Formal analysis of Okta authentication policies with z3 (and TLA+ export).",
    )
    p.add_argument("-V", "--version", action="version", version=__version__)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    f = sub.add_parser("fetch", help="pull a policy snapshot from an Okta org (read-only)")
    f.add_argument(
        "--org",
        default=os.environ.get("OKTA_ORG_URL"),
        help="https://your-org.okta.com (default $OKTA_ORG_URL)",
    )
    f.add_argument("--token-env", default="OKTA_API_TOKEN", help="env var holding an SSWS API token")
    f.add_argument(
        "--bearer-env", default="OKTA_ACCESS_TOKEN", help="env var holding an OAuth 2.0 access token"
    )
    f.add_argument(
        "--with-users", action="store_true", help="also fetch users and their group memberships (slow)"
    )
    f.add_argument("-o", "--output", default="okta-snapshot", help="output directory (or .json file)")
    f.set_defaults(func=cmd_fetch)

    def analysis_opts(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("snapshot", help="snapshot directory or .json file")
        sp.add_argument("--assertions", help="YAML file with assertions to verify")
        sp.add_argument(
            "--strict-group-rules",
            action="store_true",
            help="assume rule-managed groups have no manual members",
        )
        sp.add_argument(
            "--assurance-without-registration",
            action="store_true",
            help="do not assume device assurance implies a registered device",
        )
        sp.add_argument(
            "--evaluate-blocklisted",
            action="store_true",
            help="do not assume blocklisted IPs are rejected before policy evaluation",
        )
        sp.add_argument("--authenticator-overrides", help="YAML overriding authenticator characteristics")
        sp.add_argument(
            "--no-cubes", action="store_true", help="skip joint who+context cube enumeration (faster)"
        )
        sp.add_argument("--dnf-limit", type=int, default=48, help="max prime implicants per description")
        sp.add_argument(
            "--combined-who",
            action="store_true",
            help="describe WHO for every session-rule × app-rule pair (slow)",
        )
        sp.add_argument(
            "-j", "--jobs", type=int, default=1, help="analyse authentication policies in N worker processes"
        )
        sp.add_argument(
            "-v",
            "--verbose",
            dest="verbose_sub",
            action="store_true",
            help="show INFO findings and rule tables",
        )

    a = sub.add_parser("analyze", help="analyze a snapshot: who can do what, findings, assertions")
    analysis_opts(a)
    a.add_argument("--format", choices=["text", "markdown", "json", "sarif"], default="text")
    a.add_argument("-o", "--output")
    a.add_argument("--fail-on-high", action="store_true", help="exit 1 when HIGH findings exist")
    a.add_argument("--fail-on-violation", action="store_true", help="exit 1 when an assertion is violated")
    a.set_defaults(func=cmd_analyze)

    v = sub.add_parser("verify", help="check assertions (exit 1 on violation)")
    analysis_opts(v)
    v.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    v.add_argument("-o", "--output")
    v.set_defaults(func=cmd_verify)

    c = sub.add_parser(
        "check",
        help="prove or refute plain-English invariants (exit 1 on violation, 2 if a sentence cannot be read)",
    )
    c.add_argument("snapshot", help="snapshot directory or file")
    c.add_argument("sentences", nargs="*", help="invariants in controlled English (see docs/invariants.md)")
    c.add_argument("--file", help="file with one invariant per line (# comments allowed)")
    c.add_argument("--yaml-out", help="also write the formal assertions as YAML for `verify --assertions`")
    c.add_argument("--format", choices=["text", "json"], default="text")
    c.add_argument("-o", "--output")
    c.add_argument("--authenticator-overrides", help="authenticator characteristics overrides (YAML)")
    c.add_argument("-v", "--verbose", dest="verbose_sub", action="store_true")
    c.set_defaults(func=cmd_check)

    pr = sub.add_parser(
        "propose",
        help="turn a violated invariant into a rule change and prove it fixes the invariant (no org access)",
    )
    pr.add_argument("snapshot", help="snapshot directory or file")
    pr.add_argument("sentence", help="invariant in controlled English (see docs/invariants.md)")
    pr.add_argument("--rule-name", help="name for a created rule (default derived from the sentence)")
    pr.add_argument("--plan-out", help="write the plan (Okta API operations + verification) as JSON")
    pr.add_argument("--patched-snapshot", help="write the snapshot with the change applied to this directory")
    pr.add_argument("--format", choices=["text", "json"], default="text")
    pr.add_argument("-o", "--output")
    pr.add_argument("--authenticator-overrides", help="authenticator characteristics overrides (YAML)")
    pr.add_argument("-v", "--verbose", dest="verbose_sub", action="store_true")
    pr.set_defaults(func=cmd_propose, no_cubes=True)

    ap = sub.add_parser("apply", help="apply a plan from `propose` to the org (writes! needs --yes)")
    ap.add_argument("plan", help="plan JSON written by `propose --plan-out`")
    ap.add_argument("--org", help="org URL (default $OKTA_ORG_URL)")
    ap.add_argument("--token-env", default="OKTA_API_TOKEN")
    ap.add_argument("--bearer-env", default="OKTA_ACCESS_TOKEN")
    ap.add_argument("--dry-run", action="store_true", help="print the requests without sending them")
    ap.add_argument("--yes", action="store_true", help="actually send the requests")
    ap.add_argument("--force", action="store_true", help="apply even if the plan is not FIX_PROVED")
    ap.add_argument(
        "--inactive",
        dest="activate",
        action="store_false",
        help="create/update rules as INACTIVE for staged rollout",
    )
    ap.add_argument("--record-out", help="where to write the rollback record (default PLAN.applied.json)")
    ap.set_defaults(func=cmd_apply)

    rb = sub.add_parser("rollback", help="undo an `apply` using its record (writes! needs --yes)")
    rb.add_argument("record", help="rollback record written by `apply`")
    rb.add_argument("--org", help="org URL (default: the record's, or $OKTA_ORG_URL)")
    rb.add_argument("--token-env", default="OKTA_API_TOKEN")
    rb.add_argument("--bearer-env", default="OKTA_ACCESS_TOKEN")
    rb.add_argument("--dry-run", action="store_true")
    rb.add_argument("--yes", action="store_true")
    rb.set_defaults(func=cmd_rollback)

    e = sub.add_parser("explain", help="evaluate one concrete user/context with the reference interpreter")
    e.add_argument("snapshot")
    e.add_argument(
        "--user", help="user login or id (needs --with-users snapshot) or a label for an ad-hoc user"
    )
    e.add_argument("--group", action="append", help="group name/id (repeatable) for an ad-hoc user")
    e.add_argument("--attr", action="append", help="profile attribute, e.g. department=Finance (repeatable)")
    e.add_argument("--user-type", help="user type name or id (default: the org's default type)")
    e.add_argument("--zone", action="append", help="network zone the request is inside (repeatable)")
    e.add_argument("--registered", action="store_true")
    e.add_argument("--managed", action="store_true")
    e.add_argument("--platform", help="ANDROID IOS MACOS WINDOWS CHROMEOS LINUX OTHER")
    e.add_argument("--assurance", action="append", help="device assurance policy satisfied (repeatable)")
    e.add_argument("--risk", help="LOW MEDIUM HIGH")
    e.add_argument("--app", help="only this app")
    e.add_argument("-v", "--verbose", dest="verbose_sub", action="store_true")
    e.set_defaults(func=cmd_explain)

    w = sub.add_parser("who", help="who can obtain which form of authentication for an app")
    analysis_opts(w)
    w.add_argument("--app", required=True, help="app label/id or policy name/id")
    w.add_argument("--min-strength", help="only outcomes at least this strong (Strength name)")
    w.add_argument(
        "--max-strength",
        help="only ALLOW outcomes at most this strong (Strength name); DENY rows are hidden unless --include-deny",
    )
    w.add_argument("--include-deny", action="store_true", help="keep DENY rows when --max-strength is given")
    w.set_defaults(func=cmd_who)

    x = sub.add_parser("export-tla", help="export TLA+ modules (optionally run TLC)")
    analysis_opts(x)
    x.add_argument("-o", "--output", default="tla")
    x.add_argument("--policy", help="only this authentication policy (name or id)")
    x.add_argument("--run-tlc", metavar="TLA2TOOLS_JAR", help="run TLC with this tla2tools.jar")
    x.add_argument("--tlc-timeout", type=int, default=600)
    x.add_argument(
        "--tlc-probes", action="store_true", help="also run one TLC probe per rule to report reachability"
    )
    x.set_defaults(func=cmd_export_tla)
    d = sub.add_parser(
        "diff", help="formally compare two snapshots: who gained/lost access or got weaker auth"
    )
    d.add_argument("old", help="older snapshot directory or .json")
    d.add_argument("new", help="newer snapshot directory or .json")
    d.add_argument("--format", choices=["text", "json"], default="text")
    d.add_argument("-o", "--output")
    d.add_argument(
        "--fail-on-more-permissive", action="store_true", help="exit 1 when any app became more permissive"
    )
    d.add_argument("--strict-group-rules", action="store_true")
    d.add_argument("--authenticator-overrides")
    d.set_defaults(func=cmd_diff)

    sv = sub.add_parser(
        "simulate-validate",
        help="compare the model with Okta's policy simulation API (read-only, needs a token)",
    )
    analysis_opts(sv)
    sv.add_argument("--org", help="org URL (defaults to the snapshot's)")
    sv.add_argument("--token-env", default="OKTA_API_TOKEN")
    sv.add_argument("--bearer-env", default="OKTA_ACCESS_TOKEN")
    sv.add_argument("--app", help="only this app")
    sv.add_argument("--samples", type=int, default=25, help="sampled worlds per app")
    sv.add_argument("--seed", type=int, default=0)
    sv.set_defaults(func=cmd_simulate_validate)

    return p


def main(argv: list[str] | None = None) -> int:
    """Exit codes: 0 ok, 1 findings/violations (when requested), 2 usage or input error, 3 Okta API error."""
    args = build_parser().parse_args(argv)
    verbose = bool(getattr(args, "verbose", False) or getattr(args, "verbose_sub", False))
    args.verbose = verbose
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING, format="%(levelname)s %(message)s"
    )
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
    except Exception as e:  # noqa: BLE001 - turn expected operational failures into clean messages
        import yaml

        from .okta.client import OktaAPIError

        if isinstance(e, OktaAPIError):
            print(f"error: Okta API: {e}", file=sys.stderr)
            return 3
        if isinstance(e, ValueError | FileNotFoundError | OSError | KeyError | yaml.YAMLError):
            print(f"error: {e}", file=sys.stderr)
            return 2
        raise


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
