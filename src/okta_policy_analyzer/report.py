"""Render analysis results as Markdown, JSON or a rich terminal report."""

from __future__ import annotations

import sys
from collections.abc import Iterable
from typing import TextIO

from .analysis import AccessPolicyAnalysis, AnalysisResult, Finding
from .assertions import AssertionResult
from .assurance import Strength

SEVERITY_ICON = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "INFO": "🔵"}


def _bullets(lines: Iterable[str], indent: str = "  ") -> str:
    lines = list(lines)
    if not lines:
        return f"{indent}- (nobody)"
    return "\n".join(f"{indent}- {line}" for line in lines)


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|")


# ------------------------------------------------------------------------------------------ markdown


def render_markdown(result: AnalysisResult, assertions: list[AssertionResult] | None = None) -> str:
    out: list[str] = []
    w = out.append
    w("# Okta authentication policy analysis")
    w("")
    w(f"Org: `{result.org_url or 'snapshot'}`  ·  snapshot: {result.fetched_at or 'n/a'}")
    s = result.stats
    w(
        f"{s['authentication_policies']} authentication policies, {s['rules']} active rules, {s['groups']} groups, "
        f"{s['zones']} zones, {s['apps']} apps · {s['who_variables']} WHO + {s['context_variables']} context variables · "
        f"{s['solver_queries']} solver queries in {s['seconds']}s"
    )
    w("")
    wk = result.weakest_overall
    if wk is not None:
        strength, a = wk
        w(
            f"**Weakest way into any app:** {strength.label} — {', '.join(a.app_labels) or a.policy.name}"
            + (f" ({a.weakest_witness})" if a.weakest_witness else "")
        )
        w("")
    from .report import findings_summary as _fs

    w(f"Findings: {_fs(result.findings)}")
    w("")
    # ---- findings
    w("## Findings")
    w("")
    if not result.findings:
        w("No findings.")
    by_sev = result.findings_by_severity()
    for sev in ("HIGH", "MEDIUM", "LOW", "INFO"):
        items = by_sev.get(sev, [])
        if not items:
            continue
        w(f"### {SEVERITY_ICON[sev]} {sev} ({len(items)})")
        w("")
        for f in items:
            w(f"- **{_md_escape(f.title)}**  `{f.kind}`")
            ctx = " · ".join(
                x
                for x in [
                    f"policy: {f.policy}" if f.policy else "",
                    f"rule: {f.rule}" if f.rule else "",
                    f"apps: {', '.join(f.apps)}" if f.apps else "",
                ]
                if x
            )
            if ctx:
                w(f"  {ctx}")
            w(f"  {f.detail}")
            if f.who:
                w("  Who (in some context):")
                w(_bullets(f.who, "    "))
            when = f.data.get("when") if f.data else None
            if when:
                w("  When:")
                w(_bullets(when, "    "))
            if f.witness:
                w(f"  Witness: {f.witness}")
            hint = f.data.get("fix_hint") if f.data else None
            if hint:
                w(f"  Fix hint: the intended rule would apply {hint}.")
            w("")
    # ---- group view
    if result.group_view:
        w("## Group view (weakest / strongest outcome members of each group can obtain)")
        w("")
        policies = []
        for c in result.group_view:
            if c.policy not in policies:
                policies.append(c.policy)
        groups = []
        for c in result.group_view:
            if c.group not in groups:
                groups.append(c.group)
        w("| group | " + " | ".join(_md_escape(p) for p in policies) + " |")
        w("|---|" + "---|" * len(policies))
        cells = {(c.group, c.policy): c for c in result.group_view}
        for g in groups:
            row = []
            for pol in policies:
                c = cells.get((g, pol))
                row.append(
                    "—"
                    if c is None
                    else (
                        f"{c.weakest.label}" + (f" … {c.strongest.label}" if c.strongest != c.weakest else "")
                    )
                )
            w(f"| {_md_escape(g)} | " + " | ".join(_md_escape(x) for x in row) + " |")
        w("")
    # ---- assertions
    if assertions is not None:
        w("## Assertions")
        w("")
        w("| assertion | policy | result | violating rule | outcome |")
        w("|---|---|---|---|---|")
        for r in assertions:
            status = (
                "ERROR" if r.error else ("VACUOUS" if r.vacuous else ("holds" if r.holds else "**VIOLATED**"))
            )
            w(
                f"| {r.assertion.name} | {r.policy.name} | {status} | {r.violating_rule or ''} | {_md_escape(r.violating_outcome or r.error or '')} |"
            )
        w("")
        for r in assertions:
            if not r.holds and not r.error:
                w(f"### ✗ {r.assertion.name} ({r.policy.name})")
                if r.assertion.description:
                    w(r.assertion.description)
                w("")
                w(f"Counterexample: {r.counterexample}")
                w("")
                w("Who violates (in some context):")
                w(_bullets(r.who))
                w("")
    # ---- per policy
    w("## Who can do what, per authentication policy")
    w("")
    for a in result.access:
        out.extend(_policy_markdown(a))
    # ---- session
    w("## Global session policies (evaluated in priority order, first policy with a matching rule decides)")
    w("")
    for p in result.session:
        flag = "" if p.decides else " — **never decides**"
        w(f"### {p.policy.name} (priority {p.policy.priority}){flag}")
        w("")
        if p.fall_through_who:
            w("Falls through to the next policy for:")
            w(_bullets(p.fall_through_who))
            w("")
        w("| rule | action | who it decides for |")
        w("|---|---|---|")
        for r in p.rules:
            who = "<br>".join(_md_escape(x) for x in r.who) if r.who else "(nobody)"
            w(f"| {r.rule.name} | {_md_escape(r.summary)} | {who} |")
        w("")
    # ---- enrollment
    if result.enrollment:
        w("## Authenticator enrollment policies")
        w("")
        for p in result.enrollment:
            flag = "" if p.decides else " — **never decides**"
            w(f"### {p.policy.name} (priority {p.policy.priority}){flag}")
            settings = (
                ", ".join(f"{s.key}={s.enroll_self.value}" for s in p.policy.authenticator_settings)
                or "(no authenticator settings)"
            )
            w(f"Authenticators: {settings}")
            w("")
            for r in p.rules:
                w(f"- rule {r.rule.name}: {r.summary}; decides for: {'; '.join(r.who) or '(nobody)'}")
            w("")
    if result.apps_without_policy:
        w("## Apps without an authentication policy")
        w("")
        w(_bullets(result.apps_without_policy, ""))
        w("")
    w("## Modelling assumptions")
    w("")
    w(_bullets(result.assumptions, ""))
    w("")
    if result.warnings:
        w("## Loader warnings")
        w("")
        w(_bullets(result.warnings, ""))
        w("")
    return "\n".join(out)


def _policy_markdown(a: AccessPolicyAnalysis) -> list[str]:
    out: list[str] = []
    w = out.append
    apps = ", ".join(a.app_labels) if a.app_labels else "(no apps mapped)"
    w(f"### {a.policy.name}")
    w("")
    w(f"Apps: {apps}  ·  status: {a.policy.status.value}")
    w("")
    w(
        f"**Weakest way in:** {a.weakest.label}"
        + (f" — e.g. {a.weakest_witness}" if a.weakest_witness else "")
    )
    if a.combined_weakest is not None:
        w("")
        w(f"**With the global session policy:** {a.combined_weakest.label}")
    w("")
    w("#### Outcomes (who can obtain each form of authentication, in some context)")
    w("")
    w("| outcome | decided by rules | who |")
    w("|---|---|---|")
    for o in a.outcomes:
        who = "<br>".join(_md_escape(x) for x in o.who) + ("" if o.complete else "<br>… (incomplete)")
        w(f"| {o.strength.label} | {', '.join(r.name for r in o.rules)} | {who} |")
    w("")
    w("#### Rules in evaluation order")
    w("")
    w("| # | rule | outcome | reachable | who (any context) | when (some user) |")
    w("|---|---|---|---|---|---|")
    for r in a.rules:
        reach = (
            "yes"
            if r.reachable
            else (
                "shadowed by " + ", ".join(x.name for x in r.shadowed_by)
                if r.shadowed_by
                else "never (conditions unsatisfiable)"
            )
        )
        if r.redundant:
            reach += " (redundant)"
        who = "<br>".join(_md_escape(x) for x in r.who) if r.who else ""
        when = "<br>".join(_md_escape(x) for x in r.when) if r.when else ""
        name = f"{r.rule.name}" + (" *(catch-all)*" if r.rule.system else "")
        w(f"| {r.rule.priority} | {name} | {r.assurance.label} | {reach} | {who} | {when} |")
    if a.inactive_rules:
        w("")
        w("Inactive rules (not evaluated): " + ", ".join(r.name for r in a.inactive_rules))
    for r in a.rules:
        if r.assurance.paths and r.reachable:
            w("")
            w(
                f"<details><summary>Authentication paths accepted by rule <b>{r.rule.name}</b> ({len(r.assurance.paths)})</summary>"
            )
            w("")
            for p in r.assurance.paths:
                w(f"- {p.describe()} — {p.strength.label}")
            w("")
            w("</details>")
    if a.combined:
        w("")
        w("<details><summary>Composition with the global session policy</summary>")
        w("")
        w("| session policy / rule | app rule | effective strength | who |")
        w("|---|---|---|---|")
        for c in a.combined:
            w(
                f"| {c.session_policy.name} / {c.session_rule.name} | {c.app_rule.name} | {c.strength.label} | {'<br>'.join(_md_escape(x) for x in c.who)} |"
            )
        w("")
        w("</details>")
    w("")
    return out


# ------------------------------------------------------------------------------------------ terminal


def render_console(
    result: AnalysisResult,
    assertions: list[AssertionResult] | None,
    file: TextIO | None = None,
    *,
    verbose: bool = False,
) -> None:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    # When output is not a terminal (files, pipes, CI logs) rich falls back to 80 columns, which truncates the tables.
    width = None if (file is None and sys.stdout.isatty()) else 160
    console = Console(file=file, highlight=False, width=width)
    s = result.stats
    console.print(
        Panel(
            f"[bold]{result.org_url or 'snapshot'}[/bold]  {result.fetched_at}\n"
            f"{s['authentication_policies']} authentication policies · {s['rules']} rules · {s['groups']} groups · {s['zones']} zones · {s['apps']} apps\n"
            f"{s['solver_queries']} solver queries in {s['seconds']}s",
            title="okta-policy-analyzer",
        )
    )
    wk = result.weakest_overall
    if wk is not None:
        strength, a = wk
        console.print(
            f"[bold]Weakest way into any app:[/bold] {strength.label} — {', '.join(a.app_labels) or a.policy.name}"
        )
    # findings
    by_sev = result.findings_by_severity()
    for sev, color in (("HIGH", "red"), ("MEDIUM", "dark_orange"), ("LOW", "yellow"), ("INFO", "blue")):
        items = by_sev.get(sev, [])
        if not items or (sev == "INFO" and not verbose):
            continue
        console.print(f"\n[bold {color}]{sev} findings ({len(items)})[/bold {color}]")
        for f in items:
            console.print(f"[{color}]●[/{color}] [bold]{f.title}[/bold]  [dim]{f.kind}[/dim]")
            ctx = " · ".join(
                x
                for x in [
                    f"policy: {f.policy}" if f.policy else "",
                    f"apps: {', '.join(f.apps)}" if f.apps else "",
                ]
                if x
            )
            if ctx:
                console.print(f"    [dim]{ctx}[/dim]")
            console.print(f"    {f.detail}")
            for line in f.who[:6]:
                console.print(f"    [cyan]who:[/cyan] {line}")
            if len(f.who) > 6:
                console.print(f"    [cyan]who:[/cyan] … {len(f.who) - 6} more")
            for line in (f.data or {}).get("when", [])[:4]:
                console.print(f"    [magenta]when:[/magenta] {line}")
            if f.witness:
                console.print(f"    [green]witness:[/green] {f.witness}")
            hint = (f.data or {}).get("fix_hint")
            if hint:
                console.print(f"    [bold]fix hint:[/bold] the intended rule would apply {hint}")
    if not verbose and by_sev.get("INFO"):
        console.print(f"\n[dim]{len(by_sev['INFO'])} INFO findings hidden (use --verbose)[/dim]")
    # assertions
    if assertions is not None:
        console.print("\n[bold]Assertions[/bold]")
        t = Table(show_lines=False)
        t.add_column("assertion")
        t.add_column("policy")
        t.add_column("result")
        t.add_column("violating rule / outcome")
        for r in assertions:
            if r.error:
                status, detail = "[red]ERROR[/red]", r.error
            elif r.vacuous:
                status, detail = "[yellow]VACUOUS[/yellow]", "premise matches nobody"
            elif r.holds:
                status, detail = "[green]holds[/green]", ""
            else:
                status, detail = "[red bold]VIOLATED[/red bold]", f"{r.violating_outcome}"
            t.add_row(r.assertion.name, r.policy.name, status, detail)
        console.print(t)
        for r in assertions:
            if not r.holds and not r.error:
                console.print(f"[red]✗ {r.assertion.name}[/red] ({r.policy.name})")
                console.print(f"    counterexample: {r.counterexample}")
                for line in r.who[:6]:
                    console.print(f"    who: {line}")
    # per policy
    console.print("\n[bold]Who can do what, per authentication policy[/bold]")
    for a in result.access:
        title = f"{a.policy.name}  →  {', '.join(a.app_labels) or '(no apps)'}"
        t = Table(title=title, title_justify="left", show_lines=True, expand=True)
        t.add_column("outcome", style="bold", no_wrap=True)
        t.add_column("rules")
        t.add_column("who (in some context)")
        for o in a.outcomes:
            style = (
                "red"
                if o.strength == Strength.DENY
                else ("yellow" if o.strength <= Strength.ONE_FA_PHISHING_RESISTANT else "green")
            )
            t.add_row(
                f"[{style}]{o.strength.label}[/{style}]",
                "\n".join(r.name for r in o.rules),
                "\n".join(o.who) + ("" if o.complete else "\n… (incomplete)"),
            )
        console.print(t)
        console.print(
            f"  weakest way in: [bold]{a.weakest.label}[/bold]"
            + (f" — e.g. {a.weakest_witness}" if a.weakest_witness else "")
        )
        if a.combined_weakest is not None:
            console.print(f"  with the global session policy: [bold]{a.combined_weakest.label}[/bold]")
        if verbose:
            rt = Table(show_lines=True, expand=True)
            rt.add_column("#", no_wrap=True)
            rt.add_column("rule")
            rt.add_column("outcome")
            rt.add_column("reachable")
            rt.add_column("who (any context)")
            rt.add_column("when (some user)")
            for r in a.rules:
                reach = (
                    "yes"
                    if r.reachable
                    else (
                        "shadowed by " + ", ".join(x.name for x in r.shadowed_by)
                        if r.shadowed_by
                        else "never"
                    )
                )
                if r.redundant:
                    reach += " (redundant)"
                rt.add_row(
                    str(r.rule.priority),
                    r.rule.name + (" (catch-all)" if r.rule.system else ""),
                    r.assurance.label,
                    reach,
                    "\n".join(r.who),
                    "\n".join(r.when),
                )
            console.print(rt)
    # session policies
    console.print(
        "\n[bold]Global session policies[/bold] (priority order; the first policy with a matching rule decides)"
    )
    for p in result.session:
        flag = "" if p.decides else "  [red](never decides)[/red]"
        console.print(f"  [bold]{p.policy.name}[/bold] (priority {p.policy.priority}){flag}")
        for r in p.rules:
            console.print(f"    - {r.rule.name}: {r.summary}")
            for line in r.who[:3]:
                console.print(f"        who: {line}")
        for line in p.fall_through_who:
            console.print(f"        [yellow]falls through for:[/yellow] {line}")
    if verbose:
        console.print("\n[bold]Modelling assumptions[/bold]")
        for a_ in result.assumptions:
            console.print(f"  - {a_}")


def render_sarif(result: AnalysisResult, *, snapshot_uri: str = "okta-snapshot/policies.json") -> str:
    """SARIF 2.1.0 for code-scanning integrations (one result per finding; locations point at the snapshot's policies file)."""
    import hashlib
    import json

    uri = snapshot_uri if snapshot_uri.endswith(".json") else snapshot_uri.rstrip("/") + "/policies.json"

    level = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
    rules: dict[str, dict] = {}
    results = []
    for f in result.findings:
        rules.setdefault(
            f.kind,
            {
                "id": f.kind,
                "shortDescription": {"text": f.kind},
                "defaultConfiguration": {"level": level.get(f.severity, "note")},
            },
        )
        message = f.title + "\n" + f.detail
        if f.who:
            message += "\nWho: " + "; ".join(f.who)
        if f.witness:
            message += "\nWitness: " + f.witness
        fingerprint = hashlib.sha1(f"{f.kind}|{f.policy}|{f.rule}|{f.title}".encode()).hexdigest()[:16]
        results.append(
            {
                "ruleId": f.kind,
                "level": level.get(f.severity, "note"),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {"artifactLocation": {"uri": uri}},
                        "logicalLocations": [
                            {
                                "name": f.rule or f.policy or f.kind,
                                "fullyQualifiedName": f"{f.policy or ''}/{f.rule or ''}".strip("/"),
                                "kind": "rule" if f.rule else "policy",
                            }
                        ],
                    }
                ],
                "partialFingerprints": {"primaryLocationLineHash": fingerprint},
                "properties": {
                    "severity": f.severity,
                    "policy": f.policy,
                    "rule": f.rule,
                    "apps": f.apps,
                    **{k: v for k, v in (f.data or {}).items() if isinstance(v, str | list)},
                },
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "okta-policy-analyzer",
                        "informationUri": "https://github.com/sapphirebeehive/okta-policy-analyzer",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {"org": result.org_url, "fetched_at": result.fetched_at, "stats": result.stats},
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def findings_summary(findings: list[Finding]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return ", ".join(f"{counts.get(s, 0)} {s}" for s in ("HIGH", "MEDIUM", "LOW", "INFO"))
