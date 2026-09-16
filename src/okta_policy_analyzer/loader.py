"""Convert a raw :class:`~okta_policy_analyzer.okta.snapshot.Snapshot` into the normalized :class:`Tenant` IR.

The loader is deliberately tolerant: unknown fields are ignored, unknown condition keys are recorded in
``RuleConditions.unsupported`` and surfaced as warnings, and dangling references (groups, zones, apps
that no longer exist) are kept as ids so the analyses can report them.
"""

from __future__ import annotations

import logging
from typing import Any

from .el import ELSyntaxError, parse
from .model import (
    Access,
    AccessAction,
    App,
    Authenticator,
    AuthenticatorMethod,
    AuthenticatorSetting,
    Chain,
    ChainStep,
    Constraint,
    ConstraintSet,
    DeviceAssurance,
    DeviceCondition,
    DevicePlatform,
    ElCondition,
    EnrollAction,
    EnrollStatus,
    FactorMode,
    FactorPromptMode,
    Group,
    GroupRule,
    IdpCondition,
    NetworkCondition,
    OtherAction,
    PeopleCondition,
    PlatformCondition,
    PlatformSpec,
    Policy,
    PolicyType,
    PrimaryFactor,
    Requirement,
    RiskLevel,
    Rule,
    RuleConditions,
    SignOnAction,
    Status,
    Tenant,
    User,
    UserType,
    UserTypeCondition,
    VerificationMethod,
    VerificationType,
    Zone,
)
from .okta.snapshot import Snapshot

log = logging.getLogger(__name__)

KNOWN_CONDITION_KEYS = {
    "people",
    "network",
    "device",
    "platform",
    "riskScore",
    "userType",
    "elCondition",
    "authContext",
    "identityProvider",
    # keys we knowingly ignore because they do not affect who-can-authenticate analysis
    "app",
    "apps",
    "authProvider",
    "passwordExpiration",
    "beforeScheduledAction",
    "userIdentifier",
    "risk",  # behaviors, modelled as opaque atoms
    "riskDetection",
    "behaviors",
    "userStatus",
    "userLifecycleAttribute",
    "grantTypes",
    "clients",
    "scopes",
    "context",
    "mdmEnrollment",
    "additionalProperties",
}

_PLATFORM_ALIASES = {
    "OSX": DevicePlatform.MACOS,
    "MACOS": DevicePlatform.MACOS,
    "IOS": DevicePlatform.IOS,
    "ANDROID": DevicePlatform.ANDROID,
    "WINDOWS": DevicePlatform.WINDOWS,
    "CHROMEOS": DevicePlatform.CHROMEOS,
    "LINUX": DevicePlatform.LINUX,
    "OTHER": DevicePlatform.OTHER,
}


def _status(value: Any, default: Status = Status.ACTIVE) -> Status:
    try:
        return Status(str(value).upper()) if value is not None else default
    except ValueError:
        return default


def _platform(value: Any) -> DevicePlatform | None:
    if value is None:
        return None
    return _PLATFORM_ALIASES.get(str(value).upper())


def _pairs(items: Any) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = []
    for it in items or []:
        if isinstance(it, dict) and it.get("key"):
            out.append((str(it["key"]), it.get("method")))
    return out


def _requirement(value: Any, default: Requirement) -> Requirement:
    if value is None:
        return default
    try:
        return Requirement(str(value).upper())
    except ValueError:
        return default


# ------------------------------------------------------------------------------------------ loader


class TenantLoader:
    def __init__(self, snapshot: Snapshot):
        self.snap = snapshot
        self.tenant = Tenant(org_url=snapshot.manifest.org_url, fetched_at=snapshot.manifest.fetched_at)
        self.tenant.warnings.extend(f"snapshot: {w}" for w in snapshot.manifest.warnings)

    def warn(self, msg: str) -> None:
        log.warning(msg)
        self.tenant.warnings.append(msg)

    # ---------------------------------------------------------------------------- inventory
    def load(self) -> Tenant:
        t = self.tenant
        for g in self.snap.groups:
            prof = g.get("profile") or {}
            stats = (g.get("_embedded") or {}).get("stats") or {}
            t.groups[g["id"]] = Group(
                id=g["id"],
                name=prof.get("name") or g["id"],
                type=g.get("type") or "OKTA_GROUP",
                users_count=stats.get("usersCount"),
                description=prof.get("description") or "",
            )
        for gr in self.snap.group_rules:
            t.group_rules.append(self._group_rule(gr))
        for z in self.snap.zones:
            t.zones[z["id"]] = Zone(
                id=z["id"],
                name=z.get("name") or z["id"],
                type=z.get("type") or "IP",
                status=_status(z.get("status")),
                usage=z.get("usage") or "POLICY",
                system=bool(z.get("system", False)),
                summary=_zone_summary(z),
            )
        for d in self.snap.device_assurances:
            plat = _platform(d.get("platform")) or DevicePlatform.OTHER
            t.device_assurances[d["id"]] = DeviceAssurance(
                id=d["id"], name=d.get("name") or d["id"], platform=plat
            )
        for a in self.snap.authenticators:
            methods = [
                AuthenticatorMethod(type=str(m.get("type")), status=_status(m.get("status")))
                for m in (a.get("_methods") or [])
                if isinstance(m, dict) and m.get("type")
            ]
            auth = Authenticator(
                id=a.get("id", a["key"]),
                key=a["key"],
                name=a.get("name") or a["key"],
                type=a.get("type") or "",
                status=_status(a.get("status")),
                methods=methods,
                allowed_for=str(((a.get("settings") or {}).get("allowedFor")) or "any"),
            )
            t.authenticators[auth.key] = auth
        for ut in self.snap.user_types:
            t.user_types[ut["id"]] = UserType(
                id=ut["id"],
                name=ut.get("name") or ut["id"],
                display_name=ut.get("displayName") or "",
                default=bool(ut.get("default", False)),
            )
        for idp in self.snap.idps:
            t.idps[idp["id"]] = idp.get("name") or idp["id"]
        for app in self.snap.apps:
            href = ((app.get("_links") or {}).get("accessPolicy") or {}).get("href")
            pid = href.rstrip("/").rsplit("/", 1)[-1] if href else None
            t.apps[app["id"]] = App(
                id=app["id"],
                label=app.get("label") or app.get("name") or app["id"],
                name=app.get("name") or "",
                status=_status(app.get("status")),
                sign_on_mode=app.get("signOnMode") or "",
                access_policy_id=pid,
            )
        # explicit mappings (from /mappings or from app links collected by the fetcher)
        for pid, app_ids in (self.snap.policy_mappings or {}).items():
            for aid in app_ids:
                if aid in t.apps:
                    t.apps[aid].access_policy_id = t.apps[aid].access_policy_id or pid
                else:
                    t.apps[aid] = App(id=aid, label=aid, access_policy_id=pid)
        for u in self.snap.users:
            prof = u.get("profile") or {}
            t.users.append(
                User(
                    id=u["id"],
                    login=prof.get("login") or u["id"],
                    status=u.get("status") or "ACTIVE",
                    user_type_id=(u.get("type") or {}).get("id"),
                    group_ids=list(u.get("_groupIds") or []),
                    profile=dict(prof),
                )
            )

        # ---------------------------------------------------------------------- policies
        for p in self.snap.policies:
            pol = self._policy(p)
            if pol.is_account_management:
                t.account_management_policies.append(pol)
                continue
            bucket = {
                PolicyType.ACCESS_POLICY: t.access_policies,
                PolicyType.OKTA_SIGN_ON: t.session_policies,
                PolicyType.MFA_ENROLL: t.enrollment_policies,
                PolicyType.PASSWORD: t.password_policies,
            }.get(pol.type, t.other_policies)
            bucket.append(pol)
        for bucket in (t.access_policies, t.session_policies, t.enrollment_policies, t.password_policies):
            bucket.sort(key=lambda p: (p.system, p.priority, p.name))
        for pol in t.access_policies:
            pol.app_ids = sorted(a.id for a in t.apps.values() if a.access_policy_id == pol.id)

        self._sanity_checks()
        return t

    # ------------------------------------------------------------------------------ pieces
    def _group_rule(self, gr: dict[str, Any]) -> GroupRule:
        cond = gr.get("conditions") or {}
        expr = ((cond.get("expression") or {}).get("value")) or ""
        people = cond.get("people") or {}
        ast = None
        err = None
        if expr:
            try:
                ast = parse(expr)
            except ELSyntaxError as e:
                err = str(e)
                self.warn(f"group rule {gr.get('name')!r} ({gr.get('id')}): unparsable expression: {e}")
        return GroupRule(
            id=gr["id"],
            name=gr.get("name") or gr["id"],
            status=_status(gr.get("status")),
            expression=expr,
            target_group_ids=list(
                ((gr.get("actions") or {}).get("assignUserToGroups") or {}).get("groupIds") or []
            ),
            exclude_user_ids=list(((people.get("users") or {}).get("exclude")) or []),
            exclude_group_ids=list(((people.get("groups") or {}).get("exclude")) or []),
            expr_ast=ast,
            parse_error=err,
        )

    def _policy(self, p: dict[str, Any]) -> Policy:
        try:
            ptype = PolicyType(p.get("type"))
        except ValueError:
            ptype = PolicyType.OTHER
        cond = p.get("conditions") or {}
        groups_include = list((((cond.get("people") or {}).get("groups") or {}).get("include")) or [])
        rules = [self._rule(r, ptype, p["id"]) for r in (p.get("_rules") or [])]
        # Evaluation order: ascending priority; the Okta-created catch-all (system=true) is always last.
        # Ties are not documented by Okta: break them deterministically (creation time, then id) and warn.
        rules.sort(key=lambda r: (r.system, r.priority, str(r.raw.get("created") or ""), r.id))
        seen: dict[int, str] = {}
        for r in rules:
            if r.is_active and not r.system:
                if r.priority in seen:
                    self.warn(
                        f"policy {p.get('name')!r}: rules {seen[r.priority]!r} and {r.name!r} share priority {r.priority}; "
                        "evaluation order between them is undocumented"
                    )
                seen.setdefault(r.priority, r.name)
        pol = Policy(
            id=p["id"],
            name=p.get("name") or p["id"],
            type=ptype,
            priority=int(p.get("priority") or 0),
            status=_status(p.get("status")),
            system=bool(p.get("system", False)),
            rules=rules,
            group_include=groups_include,
            description=p.get("description") or "",
            resource_type=str(
                p.get("_resourceType") or ((p.get("_embedded") or {}).get("resourceType")) or "APP"
            ),
            raw=p,
        )
        if pol.is_account_management:
            self.warn(
                f"policy {pol.name!r} is the Okta account management policy (self-service account flows); "
                "it is analysed separately from app sign-in policies"
            )
        if ptype == PolicyType.MFA_ENROLL:
            settings = p.get("settings") or {}
            for a in settings.get("authenticators") or []:
                enroll = (a.get("enroll") or {}).get("self")
                try:
                    es = EnrollStatus(str(enroll).upper()) if enroll else EnrollStatus.NOT_ALLOWED
                except ValueError:
                    es = EnrollStatus.NOT_ALLOWED
                pol.authenticator_settings.append(
                    AuthenticatorSetting(
                        key=a.get("key", ""), enroll_self=es, constraints=a.get("constraints")
                    )
                )
            if "factors" in settings and not pol.authenticator_settings:
                # Classic-migrated shape: settings.factors = {factorKey: {enroll: {self: ...}}}
                merged: dict[str, EnrollStatus] = {}
                for fkey, fval in (settings.get("factors") or {}).items():
                    akey = _CLASSIC_FACTOR_KEYS.get(fkey)
                    if akey is None:
                        self.warn(
                            f"enrollment policy {pol.name!r}: unknown Classic factor key {fkey!r} ignored"
                        )
                        continue
                    enroll = ((fval or {}).get("enroll") or {}).get("self")
                    try:
                        es = EnrollStatus(str(enroll).upper()) if enroll else EnrollStatus.NOT_ALLOWED
                    except ValueError:
                        es = EnrollStatus.NOT_ALLOWED
                    # several Classic factors map to one authenticator: the most permissive status wins
                    if akey not in merged or _ENROLL_RANK[es] > _ENROLL_RANK[merged[akey]]:
                        merged[akey] = es
                for akey, es in merged.items():
                    pol.authenticator_settings.append(AuthenticatorSetting(key=akey, enroll_self=es))
                self.warn(
                    f"enrollment policy {pol.name!r} uses Classic 'factors' settings; mapped onto authenticator keys"
                )
        return pol

    def _rule(self, r: dict[str, Any], ptype: PolicyType, policy_id: str) -> Rule:
        cond_raw = r.get("conditions") or {}
        conditions = self._conditions(cond_raw, r)
        actions = r.get("actions") or {}
        action: Any
        if ptype == PolicyType.ACCESS_POLICY:
            action = self._access_action(actions.get("appSignOn") or {}, r)
        elif ptype == PolicyType.OKTA_SIGN_ON:
            action = self._signon_action(actions.get("signon") or {})
        elif ptype == PolicyType.MFA_ENROLL:
            action = EnrollAction(self_enroll=str(((actions.get("enroll") or {}).get("self")) or "CHALLENGE"))
        else:
            action = OtherAction(raw=actions)
        prio = r.get("priority")
        return Rule(
            id=r.get("id") or f"{policy_id}:{r.get('name')}",
            name=r.get("name") or r.get("id") or "<unnamed>",
            priority=int(prio) if prio is not None else 10**6,
            status=_status(r.get("status")),
            system=bool(r.get("system", False)),
            conditions=conditions,
            action=action,
            policy_id=policy_id,
            raw=r,
        )

    def _conditions(self, c: dict[str, Any], r: dict[str, Any]) -> RuleConditions:
        rc = RuleConditions()
        people = c.get("people")
        if people:
            users = people.get("users") or {}
            groups = people.get("groups") or {}
            pc = PeopleCondition(
                users_include=list(users.get("include") or []),
                users_exclude=list(users.get("exclude") or []),
                groups_include=list(groups.get("include") or []),
                groups_exclude=list(groups.get("exclude") or []),
            )
            rc.people = None if pc.is_trivial() else pc
        net = c.get("network")
        if net and (net.get("connection") or "ANYWHERE").upper() != "ANYWHERE":
            rc.network = NetworkCondition(
                connection="ZONE",
                include=list(net.get("include") or []),
                exclude=list(net.get("exclude") or []),
            )
        dev = c.get("device")
        if dev:
            plat = dev.get("platform") or {}
            types = [p for p in (_platform(x) for x in (plat.get("types") or [])) if p]
            dc = DeviceCondition(
                registered=dev.get("registered"),
                managed=dev.get("managed"),
                assurance_include=list(((dev.get("assurance") or {}).get("include")) or []),
                platform_types=types,
                mdm_frameworks=list(plat.get("supportedMDMFrameworks") or []),
            )
            if (
                dc.registered is not None
                or dc.managed is not None
                or dc.assurance_include
                or dc.platform_types
            ):
                rc.device = dc
        plat_c = c.get("platform")
        if plat_c and (plat_c.get("include") or plat_c.get("exclude")):
            rc.platform = PlatformCondition(
                include=[_platform_spec(x) for x in plat_c.get("include") or []],
                exclude=[_platform_spec(x) for x in plat_c.get("exclude") or []],
            )
            if _platform_is_trivial(rc.platform):
                rc.platform = None
        risk = c.get("riskScore")
        if risk and str(risk.get("level", "ANY")).upper() != "ANY":
            try:
                rc.risk_level = RiskLevel(str(risk["level"]).upper())
            except ValueError:
                self.warn(f"rule {r.get('name')!r}: unknown risk level {risk.get('level')!r}; treated as ANY")
        ut = c.get("userType")
        if ut and (ut.get("include") or ut.get("exclude")):
            rc.user_type = UserTypeCondition(
                include=list(ut.get("include") or []), exclude=list(ut.get("exclude") or [])
            )
        el = c.get("elCondition")
        if el and el.get("condition"):
            text = str(el["condition"])
            ast = None
            err = None
            try:
                ast = parse(text)
            except ELSyntaxError as e:
                err = str(e)
                self.warn(f"rule {r.get('name')!r}: unparsable elCondition; treated as opaque: {e}")
            rc.el = ElCondition(text=text, ast=ast, parse_error=err)
        ac = c.get("authContext")
        if ac and str(ac.get("authType", "ANY")).upper() != "ANY":
            rc.auth_type = str(ac["authType"]).upper()
        idp = c.get("identityProvider")
        if idp and str(idp.get("provider", "ANY")).upper() != "ANY":
            rc.idp = IdpCondition(
                provider=str(idp["provider"]).upper(), idp_ids=list(idp.get("idpIds") or [])
            )
        for key, value in c.items():
            if key not in KNOWN_CONDITION_KEYS:
                rc.unsupported[key] = value
                self.warn(
                    f"rule {r.get('name')!r}: unsupported condition {key!r} ignored (treated as always matching)"
                )
        return rc

    def _access_action(self, a: dict[str, Any], r: dict[str, Any]) -> AccessAction:
        access = Access(str(a.get("access") or "ALLOW").upper())
        vm_raw = a.get("verificationMethod")
        vm = None
        if access == Access.ALLOW and vm_raw:
            vm = self._verification(vm_raw, r)
        elif access == Access.ALLOW and not vm_raw:
            self.warn(f"rule {r.get('name')!r}: ALLOW without verificationMethod; assuming 1FA any factor")
            vm = VerificationMethod(factor_mode=FactorMode.ONE_FA)
        kmsi = (a.get("keepMeSignedIn") or {}).get("postAuth")
        return AccessAction(access=access, verification=vm, keep_me_signed_in=kmsi)

    def _verification(self, v: dict[str, Any], r: dict[str, Any]) -> VerificationMethod:
        try:
            vtype = VerificationType(str(v.get("type") or "ASSURANCE").upper())
        except ValueError:
            vtype = VerificationType.ASSURANCE
            self.warn(f"rule {r.get('name')!r}: unknown verificationMethod type {v.get('type')!r}")
        vm = VerificationMethod(
            type=vtype,
            reauthenticate_in=v.get("reauthenticateIn"),
            inactivity_period=v.get("inactivityPeriod"),
        )
        if vtype == VerificationType.ASSURANCE:
            fm = str(v.get("factorMode") or "2FA").upper()
            vm.factor_mode = FactorMode.ONE_FA if fm == "1FA" else FactorMode.TWO_FA
            for cs in _as_list(v.get("constraints")):
                if not isinstance(cs, dict):
                    continue
                vm.constraints.append(
                    ConstraintSet(
                        knowledge=_constraint("KNOWLEDGE", cs.get("knowledge")),
                        possession=_constraint("POSSESSION", cs.get("possession")),
                    )
                )
        elif vtype == VerificationType.AUTH_METHOD_CHAIN:
            vm.factor_mode = FactorMode.TWO_FA
            for ch in v.get("chains") or []:
                vm.chains.append(_chain(ch))
        else:  # ID_PROOFING
            vm.factor_mode = FactorMode.TWO_FA
            self.warn(f"rule {r.get('name')!r}: ID_PROOFING verification is modelled as 2FA (any factors)")
        return vm

    def _signon_action(self, s: dict[str, Any]) -> SignOnAction:
        raw_access = str(s.get("access") or "ALLOW").upper()
        if raw_access == "CHALLENGE":  # Classic factor sequencing: allow with MFA
            self.warn(
                "global session rule uses Classic 'CHALLENGE' access; modelled as ALLOW with requireFactor=true"
            )
            access = Access.ALLOW
            s = {**s, "requireFactor": True}
        else:
            access = Access(raw_access) if raw_access in ("ALLOW", "DENY") else Access.ALLOW
        pf = str(s.get("primaryFactor") or "PASSWORD_IDP").upper()
        try:
            primary = PrimaryFactor(pf)
        except ValueError:
            primary = PrimaryFactor.PASSWORD_IDP
        fpm = s.get("factorPromptMode")
        try:
            prompt = FactorPromptMode(str(fpm).upper()) if fpm else None
        except ValueError:
            prompt = None
        sess = s.get("session") or {}
        return SignOnAction(
            access=access,
            require_factor=bool(s.get("requireFactor", False)),
            primary_factor=primary,
            factor_prompt_mode=prompt,
            factor_lifetime=s.get("factorLifetime"),
            remember_device_by_default=bool(s.get("rememberDeviceByDefault", False)),
            max_session_idle_minutes=sess.get("maxSessionIdleMinutes"),
            max_session_lifetime_minutes=sess.get("maxSessionLifetimeMinutes"),
            use_persistent_cookie=bool(sess.get("usePersistentCookie", False)),
        )

    # ------------------------------------------------------------------------------ checks
    def _sanity_checks(self) -> None:
        t = self.tenant
        if self.snap.manifest.pipeline == "v1":
            self.warn(
                "snapshot comes from a Classic Engine org (pipeline v1); authentication policies are an Identity Engine feature"
            )
        if not t.access_policies:
            self.warn(
                "no ACCESS_POLICY policies found: this looks like a Classic Engine org or the token lacks okta.policies.read"
            )
        if t.everyone_group_id is None:
            self.warn(
                "no BUILT_IN 'Everyone' group found in the snapshot; policy-level group conditions may be misjudged"
            )
        for gid in sorted(t.referenced_group_ids() - set(t.groups)):
            self.warn(f"group {gid} is referenced by a policy or rule but does not exist in the snapshot")
        known_zones = set(t.zones)
        for pol in t.all_policies():
            for r in pol.rules:
                if r.conditions.network:
                    for zid in [*r.conditions.network.include, *r.conditions.network.exclude]:
                        if zid not in known_zones:
                            self.warn(
                                f"rule {r.name!r} in {pol.name!r} references missing network zone {zid}"
                            )
                if r.conditions.device:
                    for did in r.conditions.device.assurance_include:
                        if did not in t.device_assurances:
                            self.warn(
                                f"rule {r.name!r} in {pol.name!r} references missing device assurance policy {did}"
                            )
        for app in t.apps.values():
            if app.access_policy_id and t.policy(app.access_policy_id) is None:
                self.warn(f"app {app.label!r} maps to missing authentication policy {app.access_policy_id}")


# ------------------------------------------------------------------------------------------ helpers

_CLASSIC_FACTOR_KEYS = {
    "okta_otp": "okta_verify",
    "okta_push": "okta_verify",
    "okta_sms": "phone_number",
    "okta_call": "phone_number",
    "okta_email": "okta_email",
    "okta_password": "okta_password",
    "okta_question": "security_question",
    "google_otp": "google_otp",
    "fido_webauthn": "webauthn",
    "fido_u2f": "webauthn",
    "duo": "duo",
    "rsa_token": "onprem_mfa",
    "symantec_vip": "symantec_vip",
    "yubikey_token": "yubikey_token",
    "hotp": "custom_otp",
    "onprem_mfa": "onprem_mfa",
}
_ENROLL_RANK = {EnrollStatus.NOT_ALLOWED: 0, EnrollStatus.OPTIONAL: 1, EnrollStatus.REQUIRED: 2}


_CONSTRAINT_KEYS = {
    "types",
    "methods",
    "authenticationmethods",
    "excludedauthenticationmethods",
    "required",
    "reauthenticatein",
    "devicebound",
    "hardwareprotection",
    "phishingresistant",
    "userpresence",
    "userverification",
}


def _as_list(value: Any) -> list[Any]:
    """Okta examples sometimes show a bare object where the live API returns an array."""
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _constraint(kind: str, c: dict[str, Any] | None) -> Constraint | None:
    if not c:
        return None
    # match keys case-insensitively (the spec itself contains the typo ``phishingREsistant``)
    norm = {str(k).lower(): v for k, v in c.items() if str(k).lower() in _CONSTRAINT_KEYS}
    excluded = _pairs(_as_list(norm.get("excludedauthenticationmethods")))
    required = norm.get("required")
    if required is None:
        required = not excluded  # documented default: false only when excluded methods are given
    return Constraint(
        kind=kind,
        types=[str(x).upper() for x in norm.get("types") or []],
        methods=[str(x).upper() for x in norm.get("methods") or []],
        authentication_methods=_pairs(_as_list(norm.get("authenticationmethods"))),
        excluded_authentication_methods=excluded,
        required=bool(required),
        reauthenticate_in=norm.get("reauthenticatein"),
        device_bound=_requirement(norm.get("devicebound"), Requirement.OPTIONAL),
        hardware_protection=_requirement(norm.get("hardwareprotection"), Requirement.OPTIONAL),
        phishing_resistant=_requirement(norm.get("phishingresistant"), Requirement.OPTIONAL),
        user_presence=_requirement(norm.get("userpresence"), Requirement.REQUIRED),
        user_verification=_requirement(norm.get("userverification"), Requirement.OPTIONAL),
    )


def _chain(ch: dict[str, Any]) -> Chain:
    steps: list[ChainStep] = []
    node: dict[str, Any] | None = ch
    while node:
        steps.append(
            ChainStep(
                authentication_methods=_pairs(node.get("authenticationMethods")),
                reauthenticate_in=node.get("reauthenticateIn"),
            )
        )
        nxt = node.get("next") or []
        node = nxt[0] if nxt and isinstance(nxt[0], dict) else None
    return Chain(steps=steps)


def _platform_spec(x: dict[str, Any]) -> PlatformSpec:
    os_ = x.get("os") or {}
    return PlatformSpec(
        type=str(x.get("type") or "ANY").upper(),
        os_type=(str(os_["type"]).upper() if os_.get("type") else None),
        os_expression=os_.get("expression"),
    )


def _platform_is_trivial(pc: PlatformCondition) -> bool:
    if pc.exclude:
        return False
    return all(s.type == "ANY" and (s.os_type in (None, "ANY")) for s in pc.include)


def _zone_summary(z: dict[str, Any]) -> str:
    parts: list[str] = []
    gws = z.get("gateways") or []
    if gws:
        parts.append(
            "gateways=" + ",".join(str(g.get("value")) for g in gws[:5]) + (",…" if len(gws) > 5 else "")
        )
    locs = z.get("locations") or []
    if locs:
        parts.append(
            "locations="
            + ",".join(
                f"{loc.get('country')}{'/' + loc['region'] if loc.get('region') else ''}" for loc in locs[:5]
            )
        )
    asns = z.get("asns") or []
    if asns:
        parts.append("asns=" + ",".join(map(str, asns[:5])))
    if z.get("proxyType"):
        parts.append(f"proxyType={z['proxyType']}")
    return "; ".join(parts)


def load_tenant(snapshot: Snapshot) -> Tenant:
    """Build the normalized tenant IR from a snapshot."""
    return TenantLoader(snapshot).load()
