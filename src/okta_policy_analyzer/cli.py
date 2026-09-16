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
        _emit(render_sarif(result), args.output)
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
    if enr:
        pol, rule = enr
        allowed = [s.key for s in pol.authenticator_settings if s.enroll_self.value != "NOT_ALLOWED"]
        print(f"Enrollment policy: {pol.name} → can enroll: {', '.join(allowed) or '(unknown)'}")
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
        if max_s is not None and strength > max_s:
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
            status = "OK" if rep.ok else f"{len(rep.mismatches)} MISMATCH(ES)"
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
    f.add_argument("--org", required=True, help="https://your-org.okta.com")
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
    e.set_defaults(func=cmd_explain)

    w = sub.add_parser("who", help="who can obtain which form of authentication for an app")
    analysis_opts(w)
    w.add_argument("--app", required=True, help="app label/id or policy name/id")
    w.add_argument("--min-strength", help="only outcomes at least this strong (Strength name)")
    w.add_argument("--max-strength", help="only outcomes at most this strong (Strength name)")
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
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(message)s"
    )
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
