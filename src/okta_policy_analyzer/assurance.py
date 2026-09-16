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

from dataclasses import dataclass, field, replace
from enum import IntEnum
from importlib import resources
from itertools import combinations
from typing import Any

import yaml

from .model import (
    Access,
    AccessAction,
    Authenticator,
    ChainItem,
    Constraint,
    ConstraintSet,
    FactorMode,
    PrimaryFactor,
    Requirement,
    Rule,
    SignOnAction,
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
    phishing_resistant: bool | str  # True | False | "conditional" (FastPass: guaranteed only when required)
    device_bound: bool
    hardware_protected: bool | str  # True | False | "conditional"
    user_presence: bool
    user_verification: bool
    display: str = ""
    biometric_uv: bool = False  # user verification can be biometric (not only PIN)
    uv_always: bool = False  # tenant setting forces user verification on every verification

    @property
    def id(self) -> str:
        return f"{self.key}/{self.method}"

    @property
    def name(self) -> str:
        return self.display or self.id

    @property
    def hardware_ok(self) -> bool:
        return bool(self.hardware_protected)  # "conditional" counts as satisfiable

    @property
    def phishing_ok(self) -> bool:
        return bool(self.phishing_resistant)  # "conditional" satisfies a REQUIRED constraint


@dataclass(frozen=True)
class AuthPath:
    """One way to satisfy a verification method: the methods used plus whether user verification is relied on."""

    methods: tuple[MethodSpec, ...]
    uses_user_verification: bool = False
    hardware_enforced: bool = False  # the possession constraint required hardware protection
    phishing_enforced: bool = False  # the possession constraint required phishing resistance

    @property
    def factor_count(self) -> int:
        """Number of distinct factor types (knowledge / possession / inherence-via-user-verification)."""
        return len({m.factor_type for m in self.methods}) + (1 if self.uses_user_verification else 0)

    @property
    def possession(self) -> tuple[MethodSpec, ...]:
        return tuple(m for m in self.methods if m.factor_type == POSSESSION)

    @property
    def phishing_resistant(self) -> bool:
        """A path is phishing-resistant when it has a possession factor and every possession factor is guaranteed to be
        (always, or conditionally when the rule requires phishing resistance, which makes Okta enforce it)."""
        if not self.possession:
            return False
        return all(
            m.phishing_resistant is True or (m.phishing_resistant == "conditional" and self.phishing_enforced)
            for m in self.possession
        )

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
        if len(self.methods) == 1 and self.methods[0].uv_always and not self.uses_user_verification:
            # the tenant forces user verification on this authenticator: it always supplies a second factor type
            return AuthPath(self.methods, True, self.hardware_enforced, self.phishing_enforced).strength
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
        return Strength.ONE_FA_PHISHING_RESISTANT if self.phishing_resistant else Strength.ONE_FA_POSSESSION

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
                phishing_resistant=e.get("phishing_resistant", False),
                device_bound=bool(e.get("device_bound", False)),
                hardware_protected=e.get("hardware_protected", False),
                user_presence=bool(e.get("user_presence", True)),
                user_verification=bool(e.get("user_verification", False)),
                display=e.get("display", ""),
                biometric_uv=bool(e.get("biometric_uv", False)),
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
                candidates = _default_specs(auth)
                warnings.append(
                    f"authenticator {auth.key!r} is not in the characteristics table; assumed possession, not phishing-resistant"
                )
            if auth.status != Status.ACTIVE:
                continue
            if not auth.usable_for_sign_in():
                warnings.append(
                    f"authenticator {auth.key!r} is allowed for {auth.allowed_for!r} only; not usable for app sign-in"
                )
                continue
            active_methods = set(auth.active_methods())
            for spec in candidates:
                if auth.methods and spec.method not in active_methods:
                    continue
                if auth.type and auth.type.upper() != spec.constraint_type:
                    spec = replace(
                        spec, constraint_type=auth.type.upper()
                    )  # the tenant's declared type wins for `types`
                if auth.user_verification_required and spec.user_verification:
                    spec = replace(spec, uv_always=True)
                specs.append(spec)
        return cls(specs=specs, warnings=warnings, all_specs=list(known))

    def knowledge(self) -> list[MethodSpec]:
        return [s for s in self.specs if s.factor_type == KNOWLEDGE]

    def possession(self) -> list[MethodSpec]:
        return [s for s in self.specs if s.factor_type == POSSESSION]


def _default_specs(auth: Authenticator) -> list[MethodSpec]:
    """Conservative characteristics for an authenticator missing from the table: one spec per active method."""
    methods = auth.active_methods() or [auth.type or "unknown"]
    knowledge = auth.type in ("password", "security_question")
    return [
        MethodSpec(
            key=auth.key,
            method=method,
            factor_type=KNOWLEDGE if knowledge else POSSESSION,
            constraint_type=(auth.type or "APP").upper(),
            constraint_method=method.upper(),
            phishing_resistant=False,
            device_bound=False,
            hardware_protected=False,
            user_presence=True,
            user_verification=False,
            display=auth.name,
        )
        for method in methods
    ]


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
            if constraint.phishing_resistant == Requirement.REQUIRED and not s.phishing_ok:
                continue
            if constraint.hardware_protection == Requirement.REQUIRED and not s.hardware_ok:
                continue
            if constraint.device_bound == Requirement.REQUIRED and not s.device_bound:
                continue
            if constraint.user_presence == Requirement.REQUIRED and not s.user_presence:
                continue
            if constraint.user_verification == Requirement.REQUIRED and not s.user_verification:
                continue
            if "BIOMETRICS" in constraint.user_verification_methods and not s.biometric_uv:
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
                    phishing_enforced=(p.phishing_resistant == Requirement.REQUIRED),
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
    pr = p is not None and p.phishing_resistant == Requirement.REQUIRED
    out: list[AuthPath] = []
    # knowledge + possession pairs (two distinct factor types)
    for kk in know:
        for pp in poss:
            out.append(
                AuthPath(
                    (kk, pp),
                    uses_user_verification=uv_required and pp.user_verification,
                    hardware_enforced=hw,
                    phishing_enforced=pr,
                )
            )
    # possession alone, with user verification supplying the second factor type (only when knowledge is not required)
    if not k_required:
        for pp in poss:
            if pp.user_verification:
                out.append(
                    AuthPath((pp,), uses_user_verification=True, hardware_enforced=hw, phishing_enforced=pr)
                )
    # two possession factors are NOT two factor types, and neither are two knowledge factors.
    del p_required
    if uv_required:
        out = [pth for pth in out if pth.uses_user_verification]
    return _dedupe(out)


def _chain_paths(vm: VerificationMethod, catalogue: Catalogue) -> list[AuthPath]:
    """Auth method chains: OR over chains, ordered AND over steps, OR within a step; per-item qualifiers apply."""
    by_key: dict[str, list[MethodSpec]] = {}
    for spec in catalogue.specs:
        by_key.setdefault(spec.key, []).append(spec)
    out: list[AuthPath] = []
    Opt = tuple[
        MethodSpec, bool, bool, bool
    ]  # spec, uv required, hardware required, phishing-resistant required
    for chain in vm.chains:
        options: list[list[Opt]] = []
        for step in chain.steps:
            opts: list[Opt] = []
            items = step.items or [ChainItem(key=k, method=m) for k, m in step.authentication_methods]
            for it in items:
                for spec in by_key.get(it.key, []):
                    if it.method and it.method.lower() != spec.method:
                        continue
                    if it.phishing_resistant == Requirement.REQUIRED and not spec.phishing_ok:
                        continue
                    if it.hardware_protection == Requirement.REQUIRED and not spec.hardware_ok:
                        continue
                    if it.user_verification == Requirement.REQUIRED and not spec.user_verification:
                        continue
                    opts.append(
                        (
                            spec,
                            it.user_verification == Requirement.REQUIRED,
                            it.hardware_protection == Requirement.REQUIRED,
                            it.phishing_resistant == Requirement.REQUIRED,
                        )
                    )
            options.append(opts)
        if not options or any(not o for o in options):
            continue
        combos: list[list[Opt]] = [[]]
        for opts in options:
            combos = [c + [o] for c in combos for o in opts if all(o[0] is not x[0] for x in c)]
        for combo in combos:
            poss = [o for o in combo if o[0].factor_type == POSSESSION]
            out.append(
                AuthPath(
                    tuple(o[0] for o in combo),
                    uses_user_verification=any(o[1] and o[0].user_verification for o in combo),
                    hardware_enforced=bool(poss) and all(o[2] for o in poss),
                    phishing_enforced=bool(poss) and all(o[3] for o in poss),
                )
            )
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
        key = (
            tuple(sorted(m.id for m in p.methods)),
            p.uses_user_verification,
            p.hardware_enforced,
            p.phishing_enforced,
        )
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


# ------------------------------------------------------------------------------------------ session composition


def combined_strength(signon: SignOnAction, path: AuthPath) -> Strength:
    """Strength of an authentication path once the global session policy's requirements are added.

    Factors verified for the Okta session are credited towards the app policy, so the user experiences the
    *union* of both requirements: ``PASSWORD_IDP`` forces a knowledge factor even for a passwordless app rule,
    and ``requireFactor`` forces a second factor type even for a 1FA app rule. The global session policy never
    constrains *which* possession factor is used, so phishing resistance comes from the app path alone.
    """
    if signon.access == Access.DENY:
        return Strength.DENY
    count = path.factor_count
    if signon.primary_factor == PrimaryFactor.PASSWORD_IDP and not any(
        m.factor_type == KNOWLEDGE for m in path.methods
    ):
        count += 1  # the session requires a password (or IdP assertion) in addition
    if signon.require_factor and count < 2:
        count = 2
    if count >= 2:
        if path.phishing_resistant:
            return (
                Strength.TWO_FA_PHISHING_RESISTANT_HARDWARE
                if path.hardware_protected
                else Strength.TWO_FA_PHISHING_RESISTANT
            )
        return Strength.TWO_FA
    return path.strength


def combined_rule_strength(signon: SignOnAction, assurance: RuleAssurance) -> Strength:
    if assurance.access == Access.DENY or signon.access == Access.DENY:
        return Strength.DENY
    if not assurance.paths:
        return Strength.NO_PATH
    return min(combined_strength(signon, p) for p in assurance.paths)
