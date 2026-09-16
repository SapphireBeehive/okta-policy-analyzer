"""Assurance semantics: which concrete authenticators satisfy a rule's verification method, and how strong that is.

Okta evaluates an ``ASSURANCE`` verification method as follows (Policy API, ``AccessPolicyConstraint``):

* ``factorMode`` 1FA requires one factor, 2FA requires two *different factor types*
  (knowledge / possession / inherence). Inherence is never configured directly; a possession
  authenticator that performs user verification (biometric or PIN) supplies the second factor type.
* ``constraints`` is a list of constraint *sets*; **one** set must be satisfied (OR), and **every**
  constraint inside a set must be satisfied (AND). A ``knowledge`` constraint restricts the knowledge
  factor; a ``possession`` constraint restricts the possession factor (``types``, ``methods``,
  ``authenticationMethods``, ``excludedAuthenticationMethods``, and the REQUIRED/OPTIONAL flags
  ``phishingResistant``, ``hardwareProtection``, ``deviceBound``, ``userPresence``, ``userVerification``).
* A constraint with ``required: false`` (only excluded methods) does not demand its factor type; it
  merely removes methods from consideration.

This module turns a verification method into the finite set of *authentication paths* (sets of
(authenticator key, method) pairs) that satisfy it in a given tenant, and classifies each path and each
rule on a total *strength* order used by the reports ("weakest way in").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from importlib import resources
from itertools import combinations
from typing import Any

import yaml

from .model import (
    Access,
    AccessAction,
    Authenticator,
    Constraint,
    ConstraintSet,
    FactorMode,
    Requirement,
    Rule,
    Status,
    Tenant,
    VerificationMethod,
    VerificationType,
)

KNOWLEDGE = "KNOWLEDGE"
POSSESSION = "POSSESSION"


class Strength(IntEnum):
    """Total order on authentication strength. Higher is stronger."""

    DENY = 0
    NO_PATH = 1  # ALLOW rule that no enabled authenticator can satisfy (effective lock-out)
    ONE_FA_KNOWLEDGE = 2  # password / security question only
    ONE_FA_POSSESSION = 3  # passwordless with a non-phishing-resistant factor (email, SMS, OTP, push)
    ONE_FA_PHISHING_RESISTANT = 4  # passwordless with FIDO2 / FastPass / smart card, no user verification
    TWO_FA = 5  # two factor types, at least one path not phishing-resistant
    TWO_FA_PHISHING_RESISTANT = 6  # every path uses a phishing-resistant possession factor
    TWO_FA_PHISHING_RESISTANT_HARDWARE = 7  # ... that is also hardware protected

    @property
    def label(self) -> str:
        return _LABELS[self]


_LABELS = {
    Strength.DENY: "DENY",
    Strength.NO_PATH: "ALLOW but unsatisfiable (no enabled authenticator fits)",
    Strength.ONE_FA_KNOWLEDGE: "1FA knowledge (password only)",
    Strength.ONE_FA_POSSESSION: "1FA possession (passwordless, not phishing-resistant)",
    Strength.ONE_FA_PHISHING_RESISTANT: "1FA phishing-resistant (passwordless FIDO2/FastPass)",
    Strength.TWO_FA: "2FA (any factor types)",
    Strength.TWO_FA_PHISHING_RESISTANT: "2FA phishing-resistant",
    Strength.TWO_FA_PHISHING_RESISTANT_HARDWARE: "2FA phishing-resistant + hardware-protected",
}


@dataclass(frozen=True)
class MethodSpec:
    key: str
    method: str
    factor_type: str  # KNOWLEDGE | POSSESSION
    constraint_type: str
    constraint_method: str
    phishing_resistant: bool
    device_bound: bool
    hardware_protected: bool | str  # True | False | "conditional"
    user_presence: bool
    user_verification: bool
    display: str = ""

    @property
    def id(self) -> str:
        return f"{self.key}/{self.method}"

    @property
    def name(self) -> str:
        return self.display or self.id

    @property
    def hardware_ok(self) -> bool:
        return bool(self.hardware_protected)  # "conditional" counts as satisfiable


@dataclass(frozen=True)
class AuthPath:
    """One way to satisfy a verification method: the methods used plus whether user verification is relied on."""

    methods: tuple[MethodSpec, ...]
    uses_user_verification: bool = False
    hardware_enforced: bool = False  # the possession constraint required hardware protection

    @property
    def factor_count(self) -> int:
        return len(self.methods) + (1 if self.uses_user_verification else 0)

    @property
    def possession(self) -> tuple[MethodSpec, ...]:
        return tuple(m for m in self.methods if m.factor_type == POSSESSION)

    @property
    def phishing_resistant(self) -> bool:
        """A path is phishing-resistant when it has a possession factor and every possession factor is."""
        return bool(self.possession) and all(m.phishing_resistant for m in self.possession)

    @property
    def hardware_protected(self) -> bool:
        """Hardware protection counts when the method always has it, or the policy enforces it at runtime."""
        if not self.possession:
            return False
        return all(
            m.hardware_protected is True or (m.hardware_protected == "conditional" and self.hardware_enforced)
            for m in self.possession
        )

    @property
    def uses_password(self) -> bool:
        return any(m.key == "okta_password" for m in self.methods)

    @property
    def authenticator_keys(self) -> frozenset[str]:
        return frozenset(m.key for m in self.methods)

    @property
    def strength(self) -> Strength:
        if self.factor_count >= 2:
            if self.phishing_resistant:
                return (
                    Strength.TWO_FA_PHISHING_RESISTANT_HARDWARE
                    if self.hardware_protected
                    else Strength.TWO_FA_PHISHING_RESISTANT
                )
            return Strength.TWO_FA
        m = self.methods[0]
        if m.factor_type == KNOWLEDGE:
            return Strength.ONE_FA_KNOWLEDGE
        return Strength.ONE_FA_PHISHING_RESISTANT if m.phishing_resistant else Strength.ONE_FA_POSSESSION

    def describe(self) -> str:
        parts = [m.name for m in self.methods]
        if self.uses_user_verification:
            parts.append("user verification (biometric/PIN)")
        return " + ".join(parts)


# ------------------------------------------------------------------------------------------ catalogue


def load_method_specs(overrides: dict[str, Any] | None = None) -> list[MethodSpec]:
    """Load the built-in characteristics table, optionally overriding/adding entries."""
    text = resources.files("okta_policy_analyzer.data").joinpath("authenticators.yaml").read_text()
    data = yaml.safe_load(text)
    entries: dict[tuple[str, str], dict[str, Any]] = {
        (e["key"], e["method"]): dict(e) for e in data["methods"]
    }
    for e in (overrides or {}).get("methods", []) or []:
        k = (e["key"], e["method"])
        entries[k] = {**entries.get(k, {}), **e}
    specs = []
    for e in entries.values():
        specs.append(
            MethodSpec(
                key=e["key"],
                method=e["method"],
                factor_type=str(e.get("factor_type", POSSESSION)).upper(),
                constraint_type=str(e.get("constraint_type", "APP")).upper(),
                constraint_method=str(e.get("constraint_method", e["method"])).upper(),
                phishing_resistant=bool(e.get("phishing_resistant", False)),
                device_bound=bool(e.get("device_bound", False)),
                hardware_protected=e.get("hardware_protected", False),
                user_presence=bool(e.get("user_presence", True)),
                user_verification=bool(e.get("user_verification", False)),
                display=e.get("display", ""),
            )
        )
    return specs


@dataclass
class Catalogue:
    """The (authenticator, method) pairs that are enabled in a tenant, with their characteristics."""

    specs: list[MethodSpec]
    warnings: list[str] = field(default_factory=list)
    all_specs: list[MethodSpec] = field(default_factory=list)  # including inactive, for explanations

    @classmethod
    def for_tenant(
        cls, tenant: Tenant, overrides: dict[str, Any] | None = None, *, assume_all_if_unknown: bool = True
    ) -> Catalogue:
        known = load_method_specs(overrides)
        by_key: dict[str, list[MethodSpec]] = {}
        for s in known:
            by_key.setdefault(s.key, []).append(s)
        warnings: list[str] = []
        if not tenant.authenticators:
            if assume_all_if_unknown:
                warnings.append(
                    "snapshot has no authenticator inventory; assuming every known authenticator/method is enabled"
                )
                return cls(specs=list(known), warnings=warnings, all_specs=list(known))
            return cls(specs=[], warnings=["no authenticator inventory"], all_specs=list(known))
        specs: list[MethodSpec] = []
        for auth in tenant.authenticators.values():
            candidates = by_key.get(auth.key)
            if not candidates:
                candidates = [_default_spec(auth)]
                warnings.append(
                    f"authenticator {auth.key!r} is not in the characteristics table; assumed possession, not phishing-resistant"
                )
            if auth.status != Status.ACTIVE:
                continue
            active_methods = set(auth.active_methods())
            for spec in candidates:
                if auth.methods and spec.method not in active_methods:
                    continue
                specs.append(spec)
        return cls(specs=specs, warnings=warnings, all_specs=list(known))

    def knowledge(self) -> list[MethodSpec]:
        return [s for s in self.specs if s.factor_type == KNOWLEDGE]

    def possession(self) -> list[MethodSpec]:
        return [s for s in self.specs if s.factor_type == POSSESSION]


def _default_spec(auth: Authenticator) -> MethodSpec:
    method = auth.active_methods()[0] if auth.active_methods() else auth.type or "unknown"
    return MethodSpec(
        key=auth.key,
        method=method,
        factor_type=KNOWLEDGE if auth.type in ("password", "security_question") else POSSESSION,
        constraint_type="APP",
        constraint_method=method.upper(),
        phishing_resistant=False,
        device_bound=False,
        hardware_protected=False,
        user_presence=True,
        user_verification=False,
        display=auth.name,
    )


# ------------------------------------------------------------------------------------------ constraints


def satisfying_methods(constraint: Constraint, catalogue: Catalogue) -> list[MethodSpec]:
    """All enabled methods of the constraint's factor type that satisfy every property of the constraint."""
    out: list[MethodSpec] = []
    for s in catalogue.specs:
        if s.factor_type != constraint.kind:
            continue
        if constraint.types and s.constraint_type not in constraint.types:
            continue
        if constraint.methods and s.constraint_method not in constraint.methods:
            continue
        if constraint.authentication_methods and not _listed(s, constraint.authentication_methods):
            continue
        if constraint.excluded_authentication_methods and _listed(
            s, constraint.excluded_authentication_methods
        ):
            continue
        if constraint.kind == POSSESSION:
            if constraint.phishing_resistant == Requirement.REQUIRED and not s.phishing_resistant:
                continue
            if constraint.hardware_protection == Requirement.REQUIRED and not s.hardware_ok:
                continue
            if constraint.device_bound == Requirement.REQUIRED and not s.device_bound:
                continue
            if constraint.user_presence == Requirement.REQUIRED and not s.user_presence:
                continue
            if constraint.user_verification == Requirement.REQUIRED and not s.user_verification:
                continue
        out.append(s)
    return out


def _listed(s: MethodSpec, pairs: list[tuple[str, str | None]]) -> bool:
    return any(k == s.key and (m is None or m.lower() == s.method) for k, m in pairs)


# ------------------------------------------------------------------------------------------ paths


def paths_for(vm: VerificationMethod, catalogue: Catalogue) -> list[AuthPath]:
    """Enumerate the authentication paths that satisfy ``vm`` given the tenant's enabled authenticators."""
    if vm.type == VerificationType.AUTH_METHOD_CHAIN:
        return _chain_paths(vm, catalogue)
    if vm.type == VerificationType.ID_PROOFING:
        return _two_fa_paths(None, None, catalogue)
    if not vm.constraints:
        return (
            _one_fa_paths(None, catalogue)
            if vm.factor_mode == FactorMode.ONE_FA
            else _two_fa_paths(None, None, catalogue)
        )
    paths: list[AuthPath] = []
    for cs in vm.constraints:
        if vm.factor_mode == FactorMode.ONE_FA:
            paths.extend(_one_fa_paths(cs, catalogue))
        else:
            paths.extend(_two_fa_paths(cs.knowledge, cs.possession, catalogue))
    return _dedupe(paths)


def _one_fa_paths(cs: ConstraintSet | None, catalogue: Catalogue) -> list[AuthPath]:
    if cs is None or (cs.knowledge is None and cs.possession is None):
        return [AuthPath((m,)) for m in catalogue.specs]
    out: list[AuthPath] = []
    k, p = cs.knowledge, cs.possession
    if k is not None and (k.required or p is None):
        out.extend(AuthPath((m,)) for m in satisfying_methods(k, catalogue))
    if p is not None and (p.required or k is None):
        for m in satisfying_methods(p, catalogue):
            out.append(
                AuthPath(
                    (m,),
                    uses_user_verification=(p.user_verification == Requirement.REQUIRED),
                    hardware_enforced=(p.hardware_protection == Requirement.REQUIRED),
                )
            )
    if k is not None and p is not None and not k.required and not p.required:
        # both constraints only exclude methods
        allowed = set(satisfying_methods(k, catalogue)) | set(satisfying_methods(p, catalogue))
        out.extend(AuthPath((m,)) for m in catalogue.specs if m in allowed)
    return out


def _two_fa_paths(k: Constraint | None, p: Constraint | None, catalogue: Catalogue) -> list[AuthPath]:
    know_all = catalogue.knowledge()
    poss_all = catalogue.possession()
    know = satisfying_methods(k, catalogue) if k is not None else know_all
    poss = satisfying_methods(p, catalogue) if p is not None else poss_all
    k_required = k is not None and k.required
    p_required = p is not None and p.required
    uv_required = p is not None and p.user_verification == Requirement.REQUIRED
    hw = p is not None and p.hardware_protection == Requirement.REQUIRED
    out: list[AuthPath] = []
    # knowledge + possession pairs (two distinct factor types)
    for kk in know:
        for pp in poss:
            out.append(
                AuthPath(
                    (kk, pp),
                    uses_user_verification=uv_required and pp.user_verification,
                    hardware_enforced=hw,
                )
            )
    # possession alone, with user verification supplying the second factor type (only when knowledge is not required)
    if not k_required:
        for pp in poss:
            if pp.user_verification:
                out.append(AuthPath((pp,), uses_user_verification=True, hardware_enforced=hw))
    # two possession factors are NOT two factor types, and neither are two knowledge factors.
    del p_required
    if uv_required:
        out = [pth for pth in out if pth.uses_user_verification]
    return _dedupe(out)


def _chain_paths(vm: VerificationMethod, catalogue: Catalogue) -> list[AuthPath]:
    by_id = {s.id: s for s in catalogue.specs}
    by_key: dict[str, list[MethodSpec]] = {}
    for s in catalogue.specs:
        by_key.setdefault(s.key, []).append(s)
    out: list[AuthPath] = []
    for chain in vm.chains:
        options: list[list[MethodSpec]] = []
        for step in chain.steps:
            opts: list[MethodSpec] = []
            for key, method in step.authentication_methods:
                if method:
                    s = by_id.get(f"{key}/{method.lower()}")
                    if s:
                        opts.append(s)
                else:
                    opts.extend(by_key.get(key, []))
            options.append(opts)
        if not options or any(not o for o in options):
            continue
        for combo in _product(options):
            out.append(AuthPath(tuple(combo)))
    return _dedupe(out)


def _product(options: list[list[MethodSpec]]) -> list[list[MethodSpec]]:
    result: list[list[MethodSpec]] = [[]]
    for opts in options:
        result = [r + [o] for r in result for o in opts if o not in r]
    return result


def _dedupe(paths: list[AuthPath]) -> list[AuthPath]:
    seen: set[tuple[tuple[str, ...], bool]] = set()
    out: list[AuthPath] = []
    for p in paths:
        key = (tuple(sorted(m.id for m in p.methods)), p.uses_user_verification, p.hardware_enforced)
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


# ------------------------------------------------------------------------------------------ rule classification


@dataclass
class RuleAssurance:
    rule: Rule
    access: Access
    paths: list[AuthPath]
    weakest: Strength
    strongest: Strength
    requires_password: bool  # every path includes the password
    passwordless_possible: bool

    @property
    def label(self) -> str:
        if self.access == Access.DENY:
            return Strength.DENY.label
        return self.weakest.label


def classify_rule(rule: Rule, catalogue: Catalogue) -> RuleAssurance:
    action = rule.action
    if not isinstance(action, AccessAction) or action.access == Access.DENY or action.verification is None:
        return RuleAssurance(rule, Access.DENY, [], Strength.DENY, Strength.DENY, False, False)
    paths = paths_for(action.verification, catalogue)
    if not paths:
        return RuleAssurance(rule, Access.ALLOW, [], Strength.NO_PATH, Strength.NO_PATH, False, False)
    strengths = [p.strength for p in paths]
    return RuleAssurance(
        rule=rule,
        access=Access.ALLOW,
        paths=paths,
        weakest=min(strengths),
        strongest=max(strengths),
        requires_password=all(p.uses_password for p in paths),
        passwordless_possible=any(not p.uses_password for p in paths),
    )


def all_pairs(
    specs: list[MethodSpec],
) -> list[tuple[MethodSpec, MethodSpec]]:  # pragma: no cover - helper for docs
    return list(combinations(specs, 2))
