"""The analyses: who can do what form of authentication, and what is wrong with the policies.

Every result is derived from solver queries over the encoding in :mod:`okta_policy_analyzer.smt`; nothing here
re-implements policy semantics. Each finding carries a human-readable WHO description (a complete DNF of prime
implicants over group membership and user attributes) and, where useful, a concrete witness world.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import z3

from .assurance import Catalogue, RuleAssurance, Strength, classify_rule, combined_rule_strength
from .model import Access, AccessAction, EnrollStatus, Policy, Rule, SignOnAction, Status, Tenant
from .smt.dnf import DNF, describe_dnf, prime_implicants, project, var_names
from .smt.encoder import EncodedPolicy, PolicyEncoder
from .smt.universe import Universe, UniverseOptions, Witness

SEVERITIES = ("HIGH", "MEDIUM", "LOW", "INFO")


@dataclass
class AnalysisOptions:
    universe: UniverseOptions = field(default_factory=UniverseOptions)
    authenticator_overrides: dict[str, Any] | None = None
    dnf_limit: int = 48  # max prime implicants per description
    include_inactive_policies: bool = True
    full_cubes: bool = True  # also compute joint who+context cubes per rule (bounded)
    full_cube_limit: int = 12
    combined_who: bool = False  # WHO descriptions for every session-rule × app-rule pair (expensive)
    group_view: bool = True  # weakest/strongest outcome per referenced group per policy
    group_view_limit: int = 40


@dataclass
class Finding:
    severity: str
    kind: str
    title: str
    detail: str
    policy: str | None = None
    rule: str | None = None
    apps: list[str] = field(default_factory=list)
    who: list[str] = field(default_factory=list)
    witness: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v not in (None, [], {})}


@dataclass
class RuleAnalysis:
    rule: Rule
    index: int
    assurance: RuleAssurance
    reachable: bool
    shadowed_by: list[Rule] = field(default_factory=list)
    redundant: bool = False  # removing the rule changes no outcome
    who: list[str] = field(default_factory=list)  # DNF over WHO vars (any context)
    when: list[str] = field(default_factory=list)  # DNF over CONTEXT vars (some user)
    cubes: list[str] = field(default_factory=list)  # joint who+context prime implicants (bounded)
    who_complete: bool = True
    enrollment_gap_who: list[str] = field(
        default_factory=list
    )  # who matches but cannot enroll a satisfying set
    enrollment_gap_witness: str | None = None

    @property
    def strength(self) -> Strength:
        return self.assurance.weakest

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule.id,
            "name": self.rule.name,
            "priority": self.rule.priority,
            "system": self.rule.system,
            "status": self.rule.status.value,
            "access": self.assurance.access.value,
            "strength": self.strength.name,
            "strength_label": self.assurance.label,
            "paths": [p.describe() for p in self.assurance.paths],
            "passwordless_possible": self.assurance.passwordless_possible,
            "reachable": self.reachable,
            "shadowed_by": [r.name for r in self.shadowed_by],
            "redundant": self.redundant,
            "who": self.who,
            "who_complete": self.who_complete,
            "when": self.when,
            "cubes": self.cubes,
            "enrollment_gap_who": self.enrollment_gap_who,
            "enrollment_gap_witness": self.enrollment_gap_witness,
        }


@dataclass
class OutcomeRow:
    strength: Strength
    rules: list[Rule]
    who: list[str]
    complete: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "strength": self.strength.name,
            "label": self.strength.label,
            "rules": [r.name for r in self.rules],
            "who": self.who,
            "complete": self.complete,
        }


@dataclass
class CombinedRow:
    session_policy: Policy
    session_rule: Rule
    app_rule: Rule
    strength: Strength
    who: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_policy": self.session_policy.name,
            "session_rule": self.session_rule.name,
            "app_rule": self.app_rule.name,
            "strength": self.strength.name,
            "who": self.who,
        }


@dataclass
class AccessPolicyAnalysis:
    policy: Policy
    app_labels: list[str]
    rules: list[RuleAnalysis]
    outcomes: list[OutcomeRow]  # exactly-this-class rows, weakest first
    weakest: Strength
    weakest_witness: str | None
    combined: list[CombinedRow]  # with global session policy
    combined_weakest: Strength | None
    inactive_rules: list[Rule]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.policy.id,
            "name": self.policy.name,
            "status": self.policy.status.value,
            "apps": self.app_labels,
            "rules": [r.to_dict() for r in self.rules],
            "outcomes": [o.to_dict() for o in self.outcomes],
            "weakest": self.weakest.name,
            "weakest_label": self.weakest.label,
            "weakest_witness": self.weakest_witness,
            "combined": [c.to_dict() for c in self.combined],
            "combined_weakest": self.combined_weakest.name if self.combined_weakest is not None else None,
            "inactive_rules": [r.name for r in self.inactive_rules],
        }


@dataclass
class FamilyRule:
    rule: Rule
    reachable: bool
    summary: str
    who: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.rule.name,
            "priority": self.rule.priority,
            "reachable": self.reachable,
            "summary": self.summary,
            "who": self.who,
        }


@dataclass
class FamilyPolicy:
    policy: Policy
    reachable: bool  # some user is evaluated against it
    decides: bool  # some user gets their outcome from it
    fall_through_who: list[str]  # users for whom it applies but no rule matches
    rules: list[FamilyRule]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.policy.id,
            "name": self.policy.name,
            "priority": self.policy.priority,
            "groups": self.policy.group_include,
            "reachable": self.reachable,
            "decides": self.decides,
            "fall_through_who": self.fall_through_who,
            "rules": [r.to_dict() for r in self.rules],
        }


@dataclass
class GroupCell:
    group: str
    policy: str
    apps: list[str]
    weakest: Strength  # weakest outcome a member of the group can obtain (DENY = members can only be denied)
    strongest: Strength
    rule: str  # rule delivering the weakest outcome

    def to_dict(self) -> dict[str, Any]:
        return {
            "group": self.group,
            "policy": self.policy,
            "apps": self.apps,
            "weakest": self.weakest.name,
            "strongest": self.strongest.name,
            "rule": self.rule,
        }


@dataclass
class AnalysisResult:
    org_url: str
    fetched_at: str
    access: list[AccessPolicyAnalysis]
    session: list[FamilyPolicy]
    enrollment: list[FamilyPolicy]
    findings: list[Finding]
    assumptions: list[str]
    warnings: list[str]
    stats: dict[str, Any]
    apps_without_policy: list[str]
    group_view: list[GroupCell] = field(default_factory=list)

    @property
    def weakest_overall(self) -> tuple[Strength, AccessPolicyAnalysis] | None:
        allowed = [a for a in self.access if a.weakest > Strength.NO_PATH]
        if not allowed:
            return None
        a = min(allowed, key=lambda x: x.weakest)
        return a.weakest, a

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_url": self.org_url,
            "fetched_at": self.fetched_at,
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
            "authentication_policies": [a.to_dict() for a in self.access],
            "global_session_policies": [p.to_dict() for p in self.session],
            "enrollment_policies": [p.to_dict() for p in self.enrollment],
            "apps_without_policy": self.apps_without_policy,
            "group_view": [c.to_dict() for c in self.group_view],
            "assumptions": self.assumptions,
            "warnings": self.warnings,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {s: [] for s in SEVERITIES}
        for f in self.findings:
            out.setdefault(f.severity, []).append(f)
        return out


# ------------------------------------------------------------------------------------------ analyzer


class Analyzer:
    def __init__(self, tenant: Tenant, options: AnalysisOptions | None = None):
        self.t = tenant
        self.opt = options or AnalysisOptions()
        self.u = Universe(tenant, self.opt.universe)
        self.enc = PolicyEncoder(self.u)
        self.catalogue = Catalogue.for_tenant(tenant, self.opt.authenticator_overrides)
        self.findings: list[Finding] = []
        self._queries = 0
        # encode everything up-front so that all attribute literals / opaque atoms exist before axioms are used
        self._access = [
            self.enc.access_policy(p)
            for p in tenant.access_policies
            if p.is_active or self.opt.include_inactive_policies
        ]
        self._session = self.enc.session_policies
        self._enroll = self.enc.enrollment_policies
        self.axioms = self.u.axioms()
        self._axiom_names = [var_names(a) for a in self.axioms]
        self._slice_cache: dict[frozenset[str], list[z3.BoolRef]] = {}

    # ------------------------------------------------------------------------------ solver helpers
    def axioms_for(self, *fs: z3.BoolRef) -> list[z3.BoolRef]:
        """The axioms connected (transitively, through shared variables) to the formulas.

        Axioms about variables the formulas never touch cannot change their satisfiability or their
        projections, so dropping them is exact; it keeps solver problems small on large tenants.
        """
        names: set[str] = set()
        for f in fs:
            names |= var_names(f)
        key = frozenset(names)
        cached = self._slice_cache.get(key)
        if cached is not None:
            return cached
        kept: set[int] = set()
        changed = True
        while changed:
            changed = False
            for i, an_ in enumerate(self._axiom_names):
                if i in kept or not an_ & names:
                    continue
                kept.add(i)
                if not an_ <= names:
                    names |= an_
                    changed = True
        result = [self.axioms[i] for i in sorted(kept)]
        if len(self._slice_cache) > 4096:
            self._slice_cache.clear()
        self._slice_cache[key] = result
        return result

    def sat(self, *fs: z3.BoolRef) -> bool:
        self._queries += 1
        s = z3.Solver()
        s.add(*self.axioms_for(*fs), *fs)
        return s.check() == z3.sat

    def model(self, *fs: z3.BoolRef) -> z3.ModelRef | None:
        self._queries += 1
        s = z3.Solver()
        s.add(*self.axioms_for(*fs), *fs)
        return s.model() if s.check() == z3.sat else None

    def who(self, f: z3.BoolRef, *, limit: int | None = None) -> DNF:
        self._queries += 1
        ax = self.axioms_for(f)
        dnf = prime_implicants(
            project(f, self.u.context_vars(), ax), self.u.who_vars(), ax, limit=limit or self.opt.dnf_limit
        )
        if not dnf.complete:
            dnf = self._coarse_who(f, ax, dnf)
        return dnf

    def _coarse_who(self, f: z3.BoolRef, ax: list[z3.BoolRef], fine: DNF) -> DNF:
        """Fallback when the exact WHO enumeration hits its bound: describe the population in a smaller vocabulary.

        Everything but the group-membership variables the formula itself mentions is projected away, which yields
        the exact set of memberships that *may* obtain the outcome (a sound over-approximation of the fine
        description) and is usually small. The result is marked ``coarse`` so reports can say so.
        """
        names = var_names(f)
        vocab = [
            v for v in self.u.who_vars() if v.decl().name().startswith("member[") and v.decl().name() in names
        ]
        if not vocab:
            return fine
        keep = {v.decl().name() for v in vocab}
        eliminate = [v for v in self.u.all_vars() if v.decl().name() not in keep]
        self._queries += 1
        coarse = prime_implicants(project(f, eliminate, ax), vocab, ax, limit=self.opt.dnf_limit)
        coarse.coarse = True
        coarse.fine_count = len(fine.cubes)
        return coarse

    def when(self, f: z3.BoolRef, *, limit: int | None = None) -> DNF:
        self._queries += 1
        ax = self.axioms_for(f)
        return prime_implicants(
            project(f, self.u.who_vars(), ax), self.u.context_vars(), ax, limit=limit or self.opt.dnf_limit
        )

    def cubes(self, f: z3.BoolRef, *, limit: int | None = None) -> DNF:
        self._queries += 1
        return prime_implicants(
            f, self.u.all_vars(), self.axioms_for(f), limit=limit or self.opt.full_cube_limit
        )

    def lines(self, dnf: DNF) -> list[str]:
        return [line[2:] for line in describe_dnf(dnf, self.u.literal_text, bullet="• ")]

    def witness_text(self, f: z3.BoolRef) -> str | None:
        """A minimal readable witness: the smallest prime implicant, plus one concrete completion."""
        m = self.model(f)
        if m is None:
            return None
        cube = prime_implicants(f, self.u.all_vars(), self.axioms_for(f), limit=1)
        minimal = self.lines(cube)[0] if cube.cubes else ""
        concrete: Witness = self.u.witness(m, full=True)
        return f"{minimal}  (e.g. {concrete.describe(self.t)})" if minimal else concrete.describe(self.t)

    def fix_hint(self, bad: z3.BoolRef, good: z3.BoolRef) -> str | None:
        """Contrastive explanation: one literal of a minimal witness of ``bad`` whose flip makes ``good`` hold.

        ``bad`` is the situation reported (e.g. the DENY rule's population reaching an earlier ALLOW rule) and
        ``good`` the intended one (the DENY rule deciding). The returned text reads "if <literal were different>".
        """
        cube = prime_implicants(bad, self.u.all_vars(), self.axioms_for(bad, good), limit=1)
        if not cube.cubes:
            return None
        lits = cube.cubes[0].lits
        ax = self.axioms_for(bad, good)
        for lit in lits:
            others = [x.expr() for x in lits if x is not lit]
            s = z3.Solver()
            s.add(*ax, *others, z3.Not(lit.expr()), good)
            if s.check() == z3.sat:
                return (
                    "if " + self.u.literal_text(lit.var, lit.value, not lit.positive)
                    if z3.is_bool(lit.var)
                    else "if not (" + self.u.literal_text(lit.var, lit.value, lit.positive) + ")"
                )
        return None

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    # ------------------------------------------------------------------------------ main
    def run(self, *, jobs: int = 1) -> AnalysisResult:
        """Run every analysis. With ``jobs > 1`` authentication policies are analysed in worker processes."""
        t0 = time.time()
        t = self.t
        if jobs > 1 and len(self._access) > 1:
            access = self._run_access_parallel(jobs)
        else:
            access = [self._analyse_access_policy(ep) for ep in self._access]
        session = self._analyse_family(self._session, "global session policy")
        enrollment = self._analyse_family(self._enroll, "enrollment policy")
        self._session_findings()
        self._enrollment_findings()
        self._inventory_findings()
        apps_without = sorted(
            a.label for a in t.apps.values() if a.access_policy_id is None and a.status == Status.ACTIVE
        )
        for label in apps_without:
            self.add(
                Finding(
                    "INFO",
                    "app-without-policy",
                    f"App {label!r} has no authentication policy",
                    "The app has no accessPolicy link; it is either an API service app or its policy could not be read.",
                    apps=[label],
                )
            )
        self.findings.sort(
            key=lambda f: (SEVERITIES.index(f.severity) if f.severity in SEVERITIES else 9, f.kind, f.title)
        )
        stats = {
            "authentication_policies": len(access),
            "rules": sum(len(a.rules) for a in access),
            "groups": len(t.groups),
            "zones": len(t.zones),
            "apps": len(t.apps),
            "who_variables": len(self.u.who_vars()),
            "context_variables": len(self.u.context_vars()),
            "solver_queries": self._queries,
            "seconds": round(time.time() - t0, 2),
        }
        group_view = self._group_view(access) if self.opt.group_view else []
        stats["solver_queries"] = self._queries
        stats["seconds"] = round(time.time() - t0, 2)
        return AnalysisResult(
            org_url=t.org_url,
            fetched_at=t.fetched_at,
            access=access,
            session=session,
            enrollment=enrollment,
            findings=self.findings,
            assumptions=sorted(set(self.u.assumptions) | set(self.catalogue.warnings)),
            warnings=list(t.warnings),
            stats=stats,
            apps_without_policy=apps_without,
            group_view=group_view,
        )

    # ------------------------------------------------------------------------------ group view
    def _group_view(self, access: list[AccessPolicyAnalysis]) -> list[GroupCell]:
        """For every group a rule references (bounded), the weakest and strongest outcome its members can obtain per policy."""
        referenced: list[str] = []
        for pol in self.t.access_policies:
            for r in pol.rules:
                if r.conditions.people:
                    for g in [*r.conditions.people.groups_include, *r.conditions.people.groups_exclude]:
                        if g in self.t.groups and g != self.u.everyone and g not in referenced:
                            referenced.append(g)
        if len(referenced) > self.opt.group_view_limit:
            self.u.assumptions.append(
                f"group view limited to the first {self.opt.group_view_limit} of {len(referenced)} referenced groups"
            )
            referenced = referenced[: self.opt.group_view_limit]
        cells: list[GroupCell] = []
        for a in access:
            ep = self.enc.access_policy(a.policy)
            by_rule = {ra.rule.id: ra for ra in a.rules}
            for gid in referenced:
                member = self.u.member[gid]
                reachable = [(ra, ep.effective[ra.index]) for ra in a.rules if ra.reachable]
                classes: list[tuple[Strength, RuleAnalysis]] = []
                for ra, eff in reachable:
                    c = ra.strength if ra.assurance.access == Access.ALLOW else Strength.DENY
                    if self.sat(member, eff):
                        classes.append((c, ra))
                if not classes:
                    continue
                classes.sort(key=lambda x: x[0])
                weakest_allow = next(((c, ra) for c, ra in classes if c > Strength.DENY), None)
                weakest, rule = weakest_allow if weakest_allow else (Strength.DENY, classes[0][1])
                strongest = max(c for c, _ in classes)
                cells.append(
                    GroupCell(
                        self.t.group_name(gid),
                        a.policy.name,
                        a.app_labels,
                        weakest,
                        strongest,
                        rule.rule.name,
                    )
                )
                _ = by_rule
        return cells

    def _run_access_parallel(self, jobs: int) -> list[AccessPolicyAnalysis]:
        """Analyse authentication policies in processes; each worker rebuilds the model from the snapshot."""
        from concurrent.futures import ProcessPoolExecutor

        from .okta.snapshot import Snapshot

        snap_dict = self._snapshot_dict
        if snap_dict is None:
            raise RuntimeError(
                "parallel analysis needs the snapshot; construct the Analyzer via Analyzer.from_snapshot()"
            )
        ids = [ep.policy.id for ep in self._access]
        chunks = [ids[i::jobs] for i in range(jobs) if ids[i::jobs]]
        results: dict[str, AccessPolicyAnalysis] = {}
        findings: list[Finding] = []
        with ProcessPoolExecutor(max_workers=len(chunks)) as pool:
            for out in pool.map(_analyse_chunk, [(snap_dict, self.opt, chunk) for chunk in chunks]):
                for a in out["access"]:
                    results[a.policy.id] = a
                findings.extend(out["findings"])
                self._queries += out["queries"]
        self.findings.extend(findings)
        _ = Snapshot
        return [results[i] for i in ids if i in results]

    _snapshot_dict: dict[str, Any] | None = None

    @classmethod
    def from_snapshot(cls, snapshot: Any, options: AnalysisOptions | None = None) -> Analyzer:
        from .loader import load_tenant

        an = cls(load_tenant(snapshot), options)
        an._snapshot_dict = snapshot.to_dict()
        return an

    # ------------------------------------------------------------------------------ authentication policies
    def _analyse_access_policy(self, ep: EncodedPolicy) -> AccessPolicyAnalysis:
        pol = ep.policy
        labels = [self.t.app_label(a) for a in pol.app_ids]
        rules: list[RuleAnalysis] = []
        for i, rule in enumerate(ep.rules):
            ra = classify_rule(rule, self.catalogue)
            reachable = self.sat(ep.effective[i])
            analysis = RuleAnalysis(rule=rule, index=i, assurance=ra, reachable=reachable)
            if not reachable:
                analysis.shadowed_by = self._shadowing_rules(ep, i)
                self._dead_rule_finding(ep, analysis, labels)
            else:
                who = self.who(ep.effective[i])
                analysis.who = self.lines(who)
                analysis.who_complete = who.complete
                analysis.when = self.lines(self.when(ep.effective[i]))
                if self.opt.full_cubes:
                    cubes = self.cubes(ep.effective[i])
                    analysis.cubes = self.lines(cubes)
                analysis.redundant = self._is_redundant(ep, i)
                if analysis.redundant:
                    self.add(
                        Finding(
                            "LOW",
                            "redundant-rule",
                            f"Rule {rule.name!r} is redundant",
                            "Every user/context that this rule decides would receive an identical outcome from a later rule if it were removed.",
                            policy=pol.name,
                            rule=rule.name,
                            apps=labels,
                        )
                    )
                self._enrollment_gap(ep, analysis, labels)
                if ra.weakest == Strength.NO_PATH:
                    self.add(
                        Finding(
                            "HIGH",
                            "unsatisfiable-rule",
                            f"Rule {rule.name!r} allows access but no enabled authenticator can satisfy it",
                            "The verification method's constraints are not met by any active authenticator/method in the org; users matched by this rule are effectively locked out.",
                            policy=pol.name,
                            rule=rule.name,
                            apps=labels,
                            who=analysis.who,
                        )
                    )
            rules.append(analysis)
        self._deny_bypass_findings(ep, rules, labels)
        self._downgrade_findings(ep, rules, labels)
        self._weak_default_finding(ep, rules, labels)
        self._lint_rules(ep, labels)
        outcomes, weakest, weakest_witness = self._outcomes(ep, rules)
        combined, combined_weakest = self._combined(ep, rules)
        if not pol.is_active and pol.app_ids:
            self.add(
                Finding(
                    "MEDIUM",
                    "inactive-policy-mapped",
                    f"Authentication policy {pol.name!r} is INACTIVE but governs {len(pol.app_ids)} app(s)",
                    "Okta does not document how an inactive authentication policy is enforced; the analysis evaluates it as if active.",
                    policy=pol.name,
                    apps=labels,
                )
            )
        return AccessPolicyAnalysis(
            policy=pol,
            app_labels=labels,
            rules=rules,
            outcomes=outcomes,
            weakest=weakest,
            weakest_witness=weakest_witness,
            combined=combined,
            combined_weakest=combined_weakest,
            inactive_rules=[r for r in pol.rules if not r.is_active],
        )

    def _shadowing_rules(self, ep: EncodedPolicy, i: int) -> list[Rule]:
        """Minimal set of earlier rules whose matches cover rule i's match (why it is unreachable)."""
        prior = list(range(i))
        keep = list(prior)
        for j in prior:
            trial = [k for k in keep if k != j]
            cover = z3.Or(*[ep.match[k] for k in trial]) if trial else z3.BoolVal(False)
            if not self.sat(ep.match[i], z3.Not(cover)):
                keep = trial
        return [ep.rules[k] for k in keep]

    def _dead_rule_finding(self, ep: EncodedPolicy, ra: RuleAnalysis, labels: list[str]) -> None:
        rule = ra.rule
        if not self.sat(ep.match[ra.index]):
            reason = "its conditions can never all hold (e.g. it references only deleted groups or zones, or contradicts a domain axiom)"
            kind = "unsatisfiable-conditions"
        else:
            names = ", ".join(repr(r.name) for r in ra.shadowed_by)
            reason = f"every user/context it matches is already decided by earlier rule(s) {names}"
            kind = "shadowed-rule"
        sev = "MEDIUM" if ra.assurance.access == Access.DENY else "LOW"
        if rule.system:
            sev = "INFO"
        self.add(
            Finding(
                sev,
                kind,
                f"Rule {rule.name!r} can never apply",
                f"Rule {rule.name!r} ({ra.assurance.label}) is unreachable: {reason}.",
                policy=ep.policy.name,
                rule=rule.name,
                apps=labels,
                data={"shadowed_by": [r.name for r in ra.shadowed_by]},
            )
        )

    def _is_redundant(self, ep: EncodedPolicy, i: int) -> bool:
        """Removing rule i changes no outcome: whenever i decides, the rule that would decide instead acts identically."""
        sig_i = _action_signature(ep.rules[i])
        later = list(range(i + 1, len(ep.rules)))
        if not later:
            return False
        differing: list[z3.BoolRef] = []
        for j in later:
            if _action_signature(ep.rules[j]) == sig_i:
                continue
            between = [ep.match[k] for k in range(i + 1, j)]
            eff_without_i = z3.And(ep.match[j], z3.Not(z3.Or(*between))) if between else ep.match[j]
            differing.append(eff_without_i)
        no_later = z3.Not(z3.Or(*[ep.match[j] for j in later]))
        differing.append(no_later)  # falling off the end would be a different (deny) outcome
        return not self.sat(ep.effective[i], z3.Or(*differing))

    def _deny_bypass_findings(self, ep: EncodedPolicy, rules: list[RuleAnalysis], labels: list[str]) -> None:
        """A DENY rule pre-empted, for part of the population it targets, by an earlier ALLOW rule that is not
        specifically about that population.

        The pattern "ALLOW contractors from corp, then DENY contractors" is an intentional carve-out (same
        population, narrower context) and is not reported. "ALLOW managed devices (everyone), then DENY
        contractors" is reported: contractors on managed devices slip past the DENY. A DENY without a people
        condition (risk, zone, device based) is reported whenever any earlier ALLOW lets a matching context in.
        """
        for ra in rules:
            if ra.assurance.access != Access.DENY or ra.rule.system:
                continue
            i = ra.index
            people_d = self.enc.people(ra.rule)
            context_deny = not self.sat(
                z3.Not(people_d)
            )  # the DENY targets everyone (risk/zone/device based)
            culprits: list[int] = []
            for j in range(i):
                if rules[j].assurance.access != Access.ALLOW:
                    continue
                if not self.sat(ep.match[i], ep.effective[j]):
                    continue  # no overlap at all
                # carve-out: the ALLOW is about a sub-population of the DENY's population
                if not context_deny and not self.sat(self.enc.people(ep.rules[j]), z3.Not(people_d)):
                    continue
                culprits.append(j)
            if not culprits:
                continue
            f = z3.And(ep.match[i], z3.Or(*[ep.effective[j] for j in culprits]))
            names = [ep.rules[j].name for j in culprits]
            hint = self.fix_hint(f, ep.effective[i])
            self.add(
                Finding(
                    "HIGH",
                    "deny-bypassed",
                    f"DENY rule {ra.rule.name!r} is pre-empted by earlier ALLOW rule(s) {', '.join(repr(n) for n in names)}",
                    "Some users/contexts targeted by this DENY rule are allowed in by a higher-priority rule that is not "
                    "specific to that population. If the DENY expresses intent, move it above the ALLOW or narrow the ALLOW.",
                    policy=ep.policy.name,
                    rule=ra.rule.name,
                    apps=labels,
                    who=self.lines(self.who(f)),
                    witness=self.witness_text(f),
                    data={"bypassing_rules": names, "when": self.lines(self.when(f)), "fix_hint": hint},
                )
            )

    def _downgrade_findings(self, ep: EncodedPolicy, rules: list[RuleAnalysis], labels: list[str]) -> None:
        """The population a stricter rule targets can, in some context, be decided by a weaker later rule.

        Example: "Finance -> phishing-resistant" followed by a catch-all "anyone -> 2FA": a Finance user whose
        context misses the first rule (e.g. the rule also requires a managed device) silently gets the weaker
        requirement. Reported once per (stricter rule, weaker rule) pair with the WHEN projection.
        """
        for i, stricter in enumerate(rules):
            if not stricter.reachable or stricter.assurance.access != Access.ALLOW:
                continue
            people_i = self.enc.people(stricter.rule)
            if not self.sat(z3.Not(people_i)):
                continue  # rule targets everyone: nothing population-specific to downgrade
            for j in range(i + 1, len(rules)):
                weaker = rules[j]
                if not weaker.reachable or weaker.assurance.access != Access.ALLOW:
                    continue
                if weaker.strength >= stricter.strength:
                    continue
                f = z3.And(people_i, ep.effective[j])
                if not self.sat(f):
                    continue
                hint = self.fix_hint(f, ep.effective[i])
                self.add(
                    Finding(
                        "MEDIUM",
                        "downgrade-path",
                        f"Users targeted by {stricter.rule.name!r} ({stricter.assurance.label}) can fall through to "
                        f"{weaker.rule.name!r} ({weaker.assurance.label})",
                        "In the contexts below the stricter rule does not match, so its population is decided by a weaker "
                        "later rule. If the stricter requirement is meant unconditionally, drop the extra conditions or add "
                        "a DENY for the remaining contexts.",
                        policy=ep.policy.name,
                        rule=weaker.rule.name,
                        apps=labels,
                        who=self.lines(self.who(f)),
                        witness=self.witness_text(f),
                        data={
                            "when": self.lines(self.when(f)),
                            "stricter_rule": stricter.rule.name,
                            "fix_hint": hint,
                        },
                    )
                )

    def _weak_default_finding(self, ep: EncodedPolicy, rules: list[RuleAnalysis], labels: list[str]) -> None:
        for ra in rules:
            if not ra.rule.system or not ra.reachable:
                continue
            if ra.assurance.access == Access.DENY:
                continue
            if ra.strength <= Strength.ONE_FA_PHISHING_RESISTANT:
                self.add(
                    Finding(
                        "HIGH",
                        "weak-catch-all",
                        f"Catch-all rule of {ep.policy.name!r} allows {ra.assurance.label}",
                        "Everyone not matched by an explicit rule gets single-factor access. Consider a 2FA catch-all or an explicit DENY.",
                        policy=ep.policy.name,
                        rule=ra.rule.name,
                        apps=labels,
                        who=ra.who,
                    )
                )
            elif ra.strength == Strength.TWO_FA and any(
                r.strength > Strength.TWO_FA and r.reachable and r.assurance.access == Access.ALLOW
                for r in rules
            ):
                self.add(
                    Finding(
                        "LOW",
                        "catch-all-weaker-than-rules",
                        f"Catch-all rule of {ep.policy.name!r} is weaker than explicit rules",
                        "Explicit rules require phishing-resistant authentication but users falling through to the catch-all only need any two factors.",
                        policy=ep.policy.name,
                        rule=ra.rule.name,
                        apps=labels,
                        who=ra.who,
                    )
                )
        # weak explicit 1FA rules
        for ra in rules:
            if ra.rule.system or not ra.reachable or ra.assurance.access != Access.ALLOW:
                continue
            if ra.strength <= Strength.ONE_FA_POSSESSION:
                self.add(
                    Finding(
                        "MEDIUM",
                        "single-factor-rule",
                        f"Rule {ra.rule.name!r} grants {ra.assurance.label}",
                        "Users matched by this rule can access the app(s) with a single factor.",
                        policy=ep.policy.name,
                        rule=ra.rule.name,
                        apps=labels,
                        who=ra.who,
                        data={"when": ra.when},
                    )
                )

    def _lint_rules(self, ep: EncodedPolicy, labels: list[str]) -> None:
        for rule in ep.policy.rules:
            c = rule.conditions
            if c.people and c.people.users_include and c.people.groups_include:
                self.add(
                    Finding(
                        "INFO",
                        "ambiguous-people-condition",
                        f"Rule {rule.name!r} lists both users and groups to include",
                        "Okta does not document whether the two include lists are OR-ed or AND-ed; the analysis assumes OR (union). Validate with the policy simulation API.",
                        policy=ep.policy.name,
                        rule=rule.name,
                        apps=labels,
                    )
                )
            if c.el and c.el.parse_error:
                self.add(
                    Finding(
                        "LOW",
                        "opaque-expression",
                        f"Rule {rule.name!r} has an expression the tool cannot parse",
                        f"Treated as an unconstrained predicate: {c.el.text}",
                        policy=ep.policy.name,
                        rule=rule.name,
                        apps=labels,
                    )
                )
            if c.unsupported:
                self.add(
                    Finding(
                        "LOW",
                        "unsupported-condition",
                        f"Rule {rule.name!r} uses unsupported condition(s) {sorted(c.unsupported)}",
                        "These conditions are ignored (treated as always matching), which over-approximates who is matched.",
                        policy=ep.policy.name,
                        rule=rule.name,
                        apps=labels,
                    )
                )
            if c.device and c.device.managed is not None and c.device.registered is not True:
                self.add(
                    Finding(
                        "INFO",
                        "malformed-device-condition",
                        f"Rule {rule.name!r} sets device.managed without registered=true",
                        "Okta requires registered=true whenever managed is set.",
                        policy=ep.policy.name,
                        rule=rule.name,
                        apps=labels,
                    )
                )
            if c.network and c.network.include and c.network.exclude:
                self.add(
                    Finding(
                        "INFO",
                        "network-include-and-exclude",
                        f"Rule {rule.name!r} has both included and excluded zones",
                        "Okta expects exactly one of include/exclude; the analysis uses the conjunction.",
                        policy=ep.policy.name,
                        rule=rule.name,
                        apps=labels,
                    )
                )
            if c.people:
                for gid in [*c.people.groups_include, *c.people.groups_exclude]:
                    if gid not in self.t.groups:
                        self.add(
                            Finding(
                                "LOW",
                                "dangling-group",
                                f"Rule {rule.name!r} references a group that does not exist ({gid})",
                                "The group was probably deleted; the reference matches nobody (an include list of only deleted groups makes the rule dead).",
                                policy=ep.policy.name,
                                rule=rule.name,
                                apps=labels,
                            )
                        )
        if not any(r.system for r in ep.policy.rules):
            self.add(
                Finding(
                    "MEDIUM",
                    "missing-catch-all",
                    f"Policy {ep.policy.name!r} has no catch-all (system) rule",
                    "Users matching no rule are treated as denied by the analysis; Okta normally guarantees a catch-all.",
                    policy=ep.policy.name,
                    apps=labels,
                )
            )

    def _enrollment_gap(self, ep: EncodedPolicy, ra: RuleAnalysis, labels: list[str]) -> None:
        """Users matched by an ALLOW rule whose enrollment policy allows no authenticator set satisfying the rule."""
        if ra.assurance.access != Access.ALLOW or not ra.assurance.paths or not self._enroll:
            return
        feasible = self._feasible_paths_formula(ra.assurance)
        gap = z3.And(ep.effective[ra.index], z3.Not(feasible))
        if not self.sat(gap):
            return
        who = self.lines(self.who(gap))
        ra.enrollment_gap_who = who
        ra.enrollment_gap_witness = self.witness_text(gap)
        needed = sorted({k for p in ra.assurance.paths for k in p.authenticator_keys})
        self.add(
            Finding(
                "HIGH",
                "unenrollable-requirement",
                f"Rule {ra.rule.name!r} requires authenticators some matched users cannot enroll",
                f"The rule allows access only with authenticator sets drawn from {needed}, but the enrollment policy that applies to the users below allows no such set. These users are effectively locked out of the app(s).",
                policy=ep.policy.name,
                rule=ra.rule.name,
                apps=labels,
                who=who,
                witness=ra.enrollment_gap_witness,
                data={"paths": [p.describe() for p in ra.assurance.paths]},
            )
        )

    def _enrollable(self, key: str) -> z3.BoolRef:
        """The user's deciding enrollment policy allows enrolling authenticator ``key``."""
        parts: list[z3.BoolRef] = []
        for ep in self._enroll:
            settings = {s.key: s.enroll_self for s in ep.policy.authenticator_settings}
            if not ep.policy.authenticator_settings:
                parts.append(ep.selected)  # no settings known for this policy: assume enrollable
                continue
            if settings.get(key, EnrollStatus.NOT_ALLOWED) != EnrollStatus.NOT_ALLOWED:
                parts.append(ep.selected)
        # if no enrollment policy decides at all, do not claim a gap
        parts.append(self.enc.family_no_decision(self._enroll))
        return z3.Or(*parts) if parts else z3.BoolVal(True)

    def _feasible_paths_formula(self, ra: RuleAssurance) -> z3.BoolRef:
        cache: dict[str, z3.BoolRef] = {}

        def enr(k: str) -> z3.BoolRef:
            if k not in cache:
                cache[k] = self._enrollable(k)
            return cache[k]

        return z3.Or(*[z3.And(*[enr(k) for k in sorted(p.authenticator_keys)]) for p in ra.paths])

    def _outcomes(
        self, ep: EncodedPolicy, rules: list[RuleAnalysis]
    ) -> tuple[list[OutcomeRow], Strength, str | None]:
        by_strength: dict[Strength, list[RuleAnalysis]] = {}
        for ra in rules:
            if ra.reachable:
                by_strength.setdefault(
                    ra.strength if ra.assurance.access == Access.ALLOW else Strength.DENY, []
                ).append(ra)
        rows: list[OutcomeRow] = []
        weakest: Strength | None = None
        weakest_witness = None
        for strength in sorted(by_strength):
            ras = by_strength[strength]
            f = z3.Or(*[ep.effective[ra.index] for ra in ras])
            dnf = self.who(f)
            rows.append(OutcomeRow(strength, [ra.rule for ra in ras], self.lines(dnf), dnf.complete))
            if weakest is None and strength > Strength.DENY:
                weakest = strength
                weakest_witness = self.witness_text(f)
        if weakest is None:
            weakest = Strength.DENY if by_strength else Strength.DENY
        return rows, weakest, weakest_witness

    def _combined(
        self, ep: EncodedPolicy, rules: list[RuleAnalysis]
    ) -> tuple[list[CombinedRow], Strength | None]:
        if not self._session:
            return [], None
        rows: list[CombinedRow] = []
        weakest: Strength | None = None
        for sep in self._session:
            for k, srule in enumerate(sep.rules):
                action = srule.action
                if not isinstance(action, SignOnAction):
                    continue
                for ra in rules:
                    if not ra.reachable:
                        continue
                    f = z3.And(sep.decides(k), ep.effective[ra.index])
                    if not self.sat(f):
                        continue
                    strength = combined_rule_strength(action, ra.assurance)
                    rows.append(
                        CombinedRow(sep.policy, srule, ra.rule, strength, self.lines(self.who(f, limit=8)))
                    )
                    if strength > Strength.DENY and (weakest is None or strength < weakest):
                        weakest = strength
        rows.sort(key=lambda r: (r.strength, r.session_policy.priority, r.app_rule.priority))
        return rows, weakest if weakest is not None else Strength.DENY

    # ------------------------------------------------------------------------------ session / enrollment families
    def _analyse_family(self, encoded: list[EncodedPolicy], label: str) -> list[FamilyPolicy]:
        out: list[FamilyPolicy] = []
        for ep in encoded:
            reachable = self.sat(ep.reachable)
            decides = self.sat(ep.selected)
            fall = z3.And(ep.reachable, ep.no_match)
            fall_who = self.lines(self.who(fall)) if self.sat(fall) else []
            frules: list[FamilyRule] = []
            for i, rule in enumerate(ep.rules):
                d = ep.decides(i)
                r_reach = self.sat(d)
                frules.append(
                    FamilyRule(
                        rule, r_reach, _summarise_action(rule), self.lines(self.who(d)) if r_reach else []
                    )
                )
                if not r_reach and decides:
                    self.add(
                        Finding(
                            "LOW",
                            "dead-rule",
                            f"Rule {rule.name!r} of {label} {ep.policy.name!r} never applies",
                            "Earlier rules or policies decide every user/context this rule could match.",
                            policy=ep.policy.name,
                            rule=rule.name,
                        )
                    )
            if not decides:
                self.add(
                    Finding(
                        "MEDIUM" if not ep.policy.system else "INFO",
                        "shadowed-policy",
                        f"{label.capitalize()} {ep.policy.name!r} never decides for anyone",
                        "Higher-priority policies cover every user of its groups (or it has no groups / no matching rules).",
                        policy=ep.policy.name,
                    )
                )
            elif fall_who:
                self.add(
                    Finding(
                        "MEDIUM",
                        "policy-fall-through",
                        f"{label.capitalize()} {ep.policy.name!r} applies to users it has no rule for",
                        "For these users no rule of the policy matches, so Okta falls through to the next policy. They silently receive another policy's treatment.",
                        policy=ep.policy.name,
                        who=fall_who,
                    )
                )
            out.append(FamilyPolicy(ep.policy, reachable, decides, fall_who, frules))
        return out

    def _session_findings(self) -> None:
        for ep in self._session:
            for i, rule in enumerate(ep.rules):
                a = rule.action
                if not isinstance(a, SignOnAction):
                    continue
                d = ep.decides(i)
                if not self.sat(d):
                    continue
                if a.access == Access.DENY:
                    self.add(
                        Finding(
                            "INFO",
                            "session-deny",
                            f"Global session rule {rule.name!r} denies Okta sign-in",
                            "Users/contexts below cannot sign in to Okta at all (no app is reachable).",
                            policy=ep.policy.name,
                            rule=rule.name,
                            who=self.lines(self.who(d)),
                        )
                    )
                    continue
                if not a.require_factor:
                    sev = "LOW" if a.primary_factor.value == "PASSWORD_IDP_ANY_FACTOR" else "INFO"
                    self.add(
                        Finding(
                            sev,
                            "session-without-mfa",
                            f"Global session rule {rule.name!r} establishes sessions without MFA",
                            (
                                "Passwordless single-factor sessions are possible (primary factor: any factor used to meet the app policy); each app's authentication policy alone decides the assurance."
                                if sev == "LOW"
                                else "Sessions are established with a password only; app policies must add MFA."
                            ),
                            policy=ep.policy.name,
                            rule=rule.name,
                            who=self.lines(self.who(d)),
                        )
                    )
        if self.sat(self.enc.family_no_decision(self._session)) and self._session:
            self.add(
                Finding(
                    "HIGH",
                    "no-session-policy",
                    "Some users are matched by no global session policy rule",
                    "The default global session policy's catch-all is missing or inactive.",
                    who=self.lines(self.who(self.enc.family_no_decision(self._session))),
                )
            )

    def _enrollment_findings(self) -> None:
        pr_keys = {s.key for s in self.catalogue.specs if s.phishing_resistant}
        for ep in self._enroll:
            if not ep.policy.authenticator_settings or not self.sat(ep.selected):
                continue
            allowed = {
                s.key for s in ep.policy.authenticator_settings if s.enroll_self != EnrollStatus.NOT_ALLOWED
            }
            if pr_keys and not (allowed & pr_keys):
                self.add(
                    Finding(
                        "INFO",
                        "no-phishing-resistant-enrollment",
                        f"Enrollment policy {ep.policy.name!r} allows no phishing-resistant authenticator",
                        f"Users under this policy can enroll {sorted(allowed)} only; any app rule requiring phishing resistance locks them out.",
                        policy=ep.policy.name,
                        who=self.lines(self.who(ep.selected)),
                    )
                )
            if not any(s.enroll_self == EnrollStatus.REQUIRED for s in ep.policy.authenticator_settings):
                self.add(
                    Finding(
                        "INFO",
                        "no-required-authenticator",
                        f"Enrollment policy {ep.policy.name!r} requires no authenticator",
                        "Okta expects at least one REQUIRED authenticator.",
                        policy=ep.policy.name,
                    )
                )

    def _inventory_findings(self) -> None:
        for w in self.t.warnings:
            self.add(Finding("INFO", "loader-warning", w, "Reported while normalising the snapshot."))
        for a in self.u.assumptions:
            if a.startswith("closed world:"):
                self.add(
                    Finding(
                        "LOW",
                        "group-criteria-match-nothing",
                        "An expression's group criteria match no existing group",
                        a
                        + ". The tool resolves name/type-based group criteria against the snapshot (closed world); a group created later could change this.",
                    )
                )


# ------------------------------------------------------------------------------------------ helpers


def _analyse_chunk(args: tuple[dict[str, Any], AnalysisOptions, list[str]]) -> dict[str, Any]:
    """Worker: analyse a subset of authentication policies (module-level so it can be pickled)."""
    from .loader import load_tenant
    from .okta.snapshot import Snapshot

    snap_dict, options, policy_ids = args
    an = Analyzer(load_tenant(Snapshot.from_dict(snap_dict)), options)
    wanted = set(policy_ids)
    access = [an._analyse_access_policy(ep) for ep in an._access if ep.policy.id in wanted]
    return {"access": access, "findings": an.findings, "queries": an._queries}


def _action_signature(rule: Rule) -> str:
    a = rule.action
    if isinstance(a, AccessAction):
        vm = a.verification
        return json.dumps({"access": a.access.value, "vm": _dc(vm)}, sort_keys=True, default=str)
    return json.dumps(_dc(a), sort_keys=True, default=str)


def _dc(obj: Any) -> Any:
    from dataclasses import asdict, is_dataclass

    if obj is None:
        return None
    if is_dataclass(obj):
        return asdict(obj)
    return obj


def _summarise_action(rule: Rule) -> str:
    a = rule.action
    if isinstance(a, SignOnAction):
        if a.access == Access.DENY:
            return "DENY sign-in"
        parts = [
            "ALLOW",
            "primary="
            + ("password" if a.primary_factor.value == "PASSWORD_IDP" else "any factor (passwordless ok)"),
        ]
        parts.append(
            "MFA="
            + (
                f"required ({a.factor_prompt_mode.value.lower() if a.factor_prompt_mode else 'session'})"
                if a.require_factor
                else "not required"
            )
        )
        if a.max_session_idle_minutes is not None:
            parts.append(f"idle={a.max_session_idle_minutes}m")
        if a.max_session_lifetime_minutes:
            parts.append(f"lifetime={a.max_session_lifetime_minutes}m")
        return " ".join(parts)
    if isinstance(a, AccessAction):
        return a.access.value
    from .model import EnrollAction

    if isinstance(a, EnrollAction):
        return f"enroll: {a.self_enroll}"
    return "?"
