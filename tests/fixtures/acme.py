"""Synthetic "ACME" tenant fixture in Okta Management API JSON shape.

The tenant is designed so that every analysis has something to find:

* ``rst_admin``: rule "Admins from corp (2FA)" is fully SHADOWED by "Admins phishing-resistant"; a break-glass
  user has a 1FA path to the Admin Console; default catch-all DENY.
* ``rst_dashboard``: the catch-all is DEAD because "Everyone 2FA" covers everyone.
* ``rst_std``: the managed-device passwordless rule (priority 1) BYPASSES the intended contractor DENY (priority 3);
  "Finance hardware-protected" is UNENROLLABLE for Finance under its enrollment policy; an OPAQUE EL rule gives
  Sales a 1FA path; a rule references a deleted group.
* ``rst_payroll``: Finance phishing-resistant rule + Executives; catch-all DENY; a deleted group in an exclude.
* ``rst_weak``: WEAK CATCH-ALL (password only for everyone from anywhere).
* Global session policies: admins MFA-always; contractors denied from high-risk countries; default passwordless.
* Group rules: Finance (dynamic by department), US employees (department + not contractor), one INACTIVE rule.
"""

from __future__ import annotations

from typing import Any

from okta_policy_analyzer.okta.snapshot import Snapshot, SnapshotManifest

ORG = "https://acme.okta.com"

# ---- ids -----------------------------------------------------------------------------------------
G_EVERYONE = "00g_everyone"
G_ENG = "00g_eng"
G_ADMINS = "00g_admins"
G_CONTRACTORS = "00g_contractors"
G_SALES = "00g_sales"
G_EXEC = "00g_exec"
G_SVC = "00g_svc"
G_FINANCE = "00g_finance"
G_US = "00g_us"
G_DELETED = "00g_deleted"  # referenced but not present

Z_CORP = "nzo_corp"
Z_VPN = "nzo_vpn"
Z_BLOCKED = "nzo_blocked"
Z_LEGACY = "nzo_legacy"
Z_HIGHRISK = "nzo_highrisk"

DA_MAC = "dap_macos_secure"
DA_WIN = "dap_windows_secure"

UT_DEFAULT = "oty_default"
UT_CONTRACTOR = "oty_contractor"

APP_ADMIN = "app_admin"
APP_DASH = "app_dashboard"
APP_SFDC = "app_salesforce"
APP_GITHUB = "app_github"
APP_PAYROLL = "app_payroll"
APP_LEGACY = "app_legacy"
APP_ORPHAN = "app_orphan"

P_ADMIN = "rst_admin"
P_DASH = "rst_dashboard"
P_STD = "rst_std"
P_PAYROLL = "rst_payroll"
P_WEAK = "rst_weak"

GSP_ADMINS = "gsp_admins"
GSP_CONTRACTORS = "gsp_contractors"
GSP_DEFAULT = "gsp_default"

MFA_FINANCE = "mfa_finance"
MFA_DEFAULT = "mfa_default"

U_BREAKGLASS = "00u_breakglass"
U_ALICE = "00u_alice"
U_BOB = "00u_bob"
U_CAROL = "00u_carol"
U_DAVE = "00u_dave"
U_ERIN = "00u_erin"


def _group(gid: str, name: str, gtype: str = "OKTA_GROUP", users: int = 10) -> dict[str, Any]:
    return {
        "id": gid,
        "type": gtype,
        "profile": {"name": name, "description": f"{name} group"},
        "_embedded": {"stats": {"usersCount": users}},
    }


def _zone(
    zid: str, name: str, ztype: str = "IP", usage: str = "POLICY", system: bool = False, **extra: Any
) -> dict[str, Any]:
    z = {"id": zid, "name": name, "type": ztype, "status": "ACTIVE", "usage": usage, "system": system}
    z.update(extra)
    return z


def _people(
    groups_include=None, groups_exclude=None, users_include=None, users_exclude=None
) -> dict[str, Any]:
    p: dict[str, Any] = {}
    if groups_include or groups_exclude:
        p["groups"] = {}
        if groups_include:
            p["groups"]["include"] = list(groups_include)
        if groups_exclude:
            p["groups"]["exclude"] = list(groups_exclude)
    if users_include or users_exclude:
        p["users"] = {}
        if users_include:
            p["users"]["include"] = list(users_include)
        if users_exclude:
            p["users"]["exclude"] = list(users_exclude)
    return p


def _possession(**kw: Any) -> dict[str, Any]:
    c: dict[str, Any] = {
        "deviceBound": "OPTIONAL",
        "hardwareProtection": "OPTIONAL",
        "phishingResistant": "OPTIONAL",
        "userPresence": "REQUIRED",
        "userVerification": "OPTIONAL",
        "required": True,
    }
    c.update(kw)
    return c


def _assurance(
    factor_mode: str = "2FA", constraints: list[dict[str, Any]] | None = None, reauth: str = "PT2H"
) -> dict[str, Any]:
    return {
        "type": "ASSURANCE",
        "factorMode": factor_mode,
        "reauthenticateIn": reauth,
        "constraints": constraints or [],
    }


def _allow(vm: dict[str, Any]) -> dict[str, Any]:
    return {"appSignOn": {"access": "ALLOW", "verificationMethod": vm}}


DENY = {"appSignOn": {"access": "DENY"}}
TWO_FA_ANY = _allow(_assurance("2FA"))
ONE_FA_PASSWORD = _allow(
    _assurance(
        "1FA",
        [{"knowledge": {"types": ["PASSWORD"], "methods": ["PASSWORD"], "required": True}}],
        reauth="PT12H",
    )
)
TWO_FA_PHISHING_RESISTANT = _allow(
    _assurance(
        "2FA", [{"possession": _possession(phishingResistant="REQUIRED", userVerification="REQUIRED")}]
    )
)
TWO_FA_HARDWARE = _allow(
    _assurance(
        "2FA", [{"possession": _possession(hardwareProtection="REQUIRED", phishingResistant="REQUIRED")}]
    )
)
PASSWORDLESS_FASTPASS = _allow(
    _assurance(
        "2FA",
        [
            {
                "possession": _possession(
                    phishingResistant="REQUIRED", deviceBound="REQUIRED", userVerification="REQUIRED"
                )
            }
        ],
        reauth="PT43800H",
    )
)


def _rule(
    rid: str,
    name: str,
    prio: int,
    conditions: dict[str, Any],
    actions: dict[str, Any],
    *,
    system: bool = False,
    status: str = "ACTIVE",
    rtype: str = "ACCESS_POLICY",
) -> dict[str, Any]:
    return {
        "id": rid,
        "name": name,
        "priority": prio,
        "status": status,
        "system": system,
        "type": rtype,
        "conditions": conditions,
        "actions": actions,
    }


def _policy(
    pid: str,
    name: str,
    ptype: str,
    prio: int,
    rules: list[dict[str, Any]],
    *,
    system: bool = False,
    groups_include: list[str] | None = None,
    settings: dict[str, Any] | None = None,
    status: str = "ACTIVE",
) -> dict[str, Any]:
    p: dict[str, Any] = {
        "id": pid,
        "name": name,
        "type": ptype,
        "priority": prio,
        "status": status,
        "system": system,
        "description": f"{name} (fixture)",
        "_rules": rules,
    }
    if groups_include is not None:
        p["conditions"] = {"people": {"groups": {"include": groups_include}}}
    if settings is not None:
        p["settings"] = settings
    return p


def _app(aid: str, label: str, policy_id: str | None, sign_on_mode: str = "SAML_2_0") -> dict[str, Any]:
    a: dict[str, Any] = {
        "id": aid,
        "label": label,
        "name": label.lower().replace(" ", "_"),
        "status": "ACTIVE",
        "signOnMode": sign_on_mode,
        "_links": {},
    }
    if policy_id:
        a["_links"]["accessPolicy"] = {"href": f"{ORG}/api/v1/policies/{policy_id}"}
    return a


def _authenticator(
    key: str,
    name: str,
    atype: str,
    methods: list[str],
    status: str = "ACTIVE",
    method_status: dict[str, str] | None = None,
) -> dict[str, Any]:
    ms = method_status or {}
    return {
        "id": f"aut_{key}",
        "key": key,
        "name": name,
        "type": atype,
        "status": status,
        "_methods": [{"type": m, "status": ms.get(m, "ACTIVE")} for m in methods],
    }


def _enroll_setting(key: str, self_: str) -> dict[str, Any]:
    return {"key": key, "enroll": {"self": self_}}


def _user(uid: str, login: str, groups: list[str], utype: str = UT_DEFAULT, **profile: Any) -> dict[str, Any]:
    prof = {"login": login, "email": login, **profile}
    return {"id": uid, "status": "ACTIVE", "type": {"id": utype}, "profile": prof, "_groupIds": groups}


def build_acme() -> Snapshot:
    groups = [
        _group(G_EVERYONE, "Everyone", "BUILT_IN", 500),
        _group(G_ENG, "Engineering", users=120),
        _group(G_ADMINS, "Okta Administrators", users=6),
        _group(G_CONTRACTORS, "Contractors", users=40),
        _group(G_SALES, "Sales", users=80),
        _group(G_EXEC, "Executives", users=9),
        _group(G_SVC, "Service Accounts", users=15),
        _group(G_FINANCE, "Finance", users=25),
        _group(G_US, "US Employees", users=300),
    ]
    group_rules = [
        {
            "id": "grr_finance",
            "name": "Finance by department",
            "status": "ACTIVE",
            "conditions": {
                "expression": {"type": "urn:okta:expression:1.0", "value": 'user.department == "Finance"'}
            },
            "actions": {"assignUserToGroups": {"groupIds": [G_FINANCE]}},
        },
        {
            "id": "grr_us",
            "name": "US employees",
            "status": "ACTIVE",
            "conditions": {
                "expression": {
                    "type": "urn:okta:expression:1.0",
                    "value": f'user.countryCode == "US" && !isMemberOfGroup("{G_CONTRACTORS}")',
                },
                "people": {"users": {"exclude": [U_BREAKGLASS]}},
            },
            "actions": {"assignUserToGroups": {"groupIds": [G_US]}},
        },
        {
            "id": "grr_inactive",
            "name": "Old exec rule (inactive)",
            "status": "INACTIVE",
            "conditions": {"expression": {"type": "urn:okta:expression:1.0", "value": 'user.title == "CEO"'}},
            "actions": {"assignUserToGroups": {"groupIds": [G_EXEC]}},
        },
    ]
    zones = [
        _zone(Z_CORP, "Corporate Network", gateways=[{"type": "CIDR", "value": "203.0.113.0/24"}]),
        _zone(Z_VPN, "VPN", gateways=[{"type": "CIDR", "value": "198.51.100.0/24"}]),
        _zone(Z_LEGACY, "LegacyIpZone", system=True),
        _zone(
            Z_BLOCKED,
            "BlockedIpZone",
            usage="BLOCKLIST",
            system=True,
            gateways=[{"type": "CIDR", "value": "192.0.2.0/24"}],
        ),
        _zone(
            Z_HIGHRISK,
            "High-risk countries",
            ztype="DYNAMIC",
            locations=[{"country": "KP"}, {"country": "IR"}],
        ),
    ]
    device_assurances = [
        {
            "id": DA_MAC,
            "name": "macOS secure",
            "platform": "MACOS",
            "osVersion": {"minimum": "14.0"},
            "diskEncryptionType": {"include": ["ALL_INTERNAL_VOLUMES"]},
        },
        {
            "id": DA_WIN,
            "name": "Windows secure",
            "platform": "WINDOWS",
            "osVersion": {"minimum": "10.0.19045"},
        },
    ]
    authenticators = [
        _authenticator("okta_password", "Password", "password", ["password"]),
        _authenticator("okta_email", "Email", "email", ["email"]),
        _authenticator(
            "phone_number", "Phone", "phone", ["sms", "voice"], method_status={"voice": "INACTIVE"}
        ),
        _authenticator("okta_verify", "Okta Verify", "app", ["push", "totp", "signed_nonce"]),
        _authenticator("webauthn", "FIDO2 (WebAuthn)", "security_key", ["webauthn"]),
        _authenticator("security_question", "Security Question", "security_question", ["security_question"]),
        _authenticator("google_otp", "Google Authenticator", "app", ["otp"], status="INACTIVE"),
    ]
    user_types = [
        {"id": UT_DEFAULT, "name": "user", "displayName": "User", "default": True},
        {"id": UT_CONTRACTOR, "name": "contractor", "displayName": "Contractor", "default": False},
    ]
    apps = [
        _app(APP_ADMIN, "Okta Admin Console", P_ADMIN, "OPENID_CONNECT"),
        _app(APP_DASH, "Okta Dashboard", P_DASH, "OPENID_CONNECT"),
        _app(APP_SFDC, "Salesforce", P_STD),
        _app(APP_GITHUB, "GitHub", P_STD),
        _app(APP_PAYROLL, "Payroll (Workday)", P_PAYROLL),
        _app(APP_LEGACY, "Legacy Intranet", P_WEAK, "BROWSER_PLUGIN"),
        _app(APP_ORPHAN, "Orphan App", None, "BOOKMARK"),
    ]

    # ---- authentication policies -----------------------------------------------------------------
    p_admin = _policy(
        P_ADMIN,
        "Okta Admin Console policy",
        "ACCESS_POLICY",
        1,
        [
            _rule(
                "rul_admin_deny_contractors",
                "Deny contractors",
                0,
                {"people": _people(groups_include=[G_CONTRACTORS])},
                DENY,
            ),
            _rule(
                "rul_admin_pr",
                "Admins phishing-resistant",
                1,
                {"people": _people(groups_include=[G_ADMINS]), "network": {"connection": "ANYWHERE"}},
                TWO_FA_PHISHING_RESISTANT,
            ),
            _rule(
                "rul_admin_corp",
                "Admins from corp (2FA)",
                2,
                {
                    "people": _people(groups_include=[G_ADMINS]),
                    "network": {"connection": "ZONE", "include": [Z_CORP]},
                },
                TWO_FA_ANY,
            ),
            _rule(
                "rul_admin_breakglass",
                "Break-glass account",
                3,
                {"people": _people(users_include=[U_BREAKGLASS])},
                ONE_FA_PASSWORD,
            ),
            _rule(
                "rul_admin_default",
                "Catch-all Rule",
                99,
                {"people": _people(groups_include=[G_EVERYONE])},
                DENY,
                system=True,
            ),
        ],
    )
    p_dash = _policy(
        P_DASH,
        "Okta Dashboard policy",
        "ACCESS_POLICY",
        2,
        [
            _rule(
                "rul_dash_everyone",
                "Everyone 2FA",
                0,
                {"people": _people(groups_include=[G_EVERYONE])},
                TWO_FA_ANY,
            ),
            _rule(
                "rul_dash_default",
                "Catch-all Rule",
                99,
                {"people": _people(groups_include=[G_EVERYONE])},
                TWO_FA_ANY,
                system=True,
            ),
        ],
    )
    p_std = _policy(
        P_STD,
        "Standard apps policy",
        "ACCESS_POLICY",
        3,
        [
            _rule(
                "rul_std_svc_deny",
                "Service accounts denied",
                0,
                {"people": _people(groups_include=[G_SVC])},
                DENY,
            ),
            _rule(
                "rul_std_managed",
                "Managed device passwordless",
                1,
                {"device": {"registered": True, "managed": True, "assurance": {"include": [DA_MAC, DA_WIN]}}},
                PASSWORDLESS_FASTPASS,
            ),
            _rule(
                "rul_std_contractor_corp",
                "Contractors from corp/VPN",
                2,
                {
                    "people": _people(groups_include=[G_CONTRACTORS]),
                    "network": {"connection": "ZONE", "include": [Z_CORP, Z_VPN]},
                },
                TWO_FA_ANY,
            ),
            _rule(
                "rul_std_contractor_deny",
                "Contractors elsewhere denied",
                3,
                {"people": _people(groups_include=[G_CONTRACTORS])},
                DENY,
            ),
            _rule("rul_std_high_risk", "High risk denied", 4, {"riskScore": {"level": "HIGH"}}, DENY),
            _rule(
                "rul_std_finance_hw",
                "Finance hardware-protected",
                5,
                {"people": _people(groups_include=[G_FINANCE], groups_exclude=[G_DELETED])},
                TWO_FA_HARDWARE,
            ),
            _rule(
                "rul_std_sales_mobile",
                "Sales on mobile (custom expression)",
                6,
                {
                    "people": _people(groups_include=[G_SALES]),
                    "elCondition": {
                        "condition": 'user.department == "Sales" && String.stringContains(request.userAgent, "Mobile")'
                    },
                },
                ONE_FA_PASSWORD,
            ),
            _rule(
                "rul_std_inactive",
                "Old rule (inactive)",
                7,
                {"people": _people(groups_include=[G_ENG])},
                ONE_FA_PASSWORD,
                status="INACTIVE",
            ),
            _rule(
                "rul_std_default",
                "Catch-all Rule",
                99,
                {"people": _people(groups_include=[G_EVERYONE])},
                TWO_FA_ANY,
                system=True,
            ),
        ],
    )
    p_payroll = _policy(
        P_PAYROLL,
        "Payroll policy",
        "ACCESS_POLICY",
        4,
        [
            _rule(
                "rul_pay_finance",
                "Finance phishing-resistant",
                0,
                {
                    "people": _people(groups_include=[G_FINANCE], groups_exclude=[G_CONTRACTORS]),
                    "userType": {"include": [UT_DEFAULT], "exclude": []},
                },
                TWO_FA_PHISHING_RESISTANT,
            ),
            _rule(
                "rul_pay_exec",
                "Executives",
                1,
                {"people": _people(groups_include=[G_EXEC], groups_exclude=[G_DELETED])},
                TWO_FA_ANY,
            ),
            _rule(
                "rul_pay_default",
                "Catch-all Rule",
                99,
                {"people": _people(groups_include=[G_EVERYONE])},
                DENY,
                system=True,
            ),
        ],
    )
    p_weak = _policy(
        P_WEAK,
        "Legacy intranet policy",
        "ACCESS_POLICY",
        5,
        [
            _rule("rul_weak_high_risk", "High risk denied", 0, {"riskScore": {"level": "HIGH"}}, DENY),
            _rule(
                "rul_weak_default",
                "Catch-all Rule",
                99,
                {"people": _people(groups_include=[G_EVERYONE])},
                ONE_FA_PASSWORD,
                system=True,
            ),
        ],
    )

    # ---- global session policies -----------------------------------------------------------------
    def signon(
        access="ALLOW",
        require_factor=False,
        prompt=None,
        primary="PASSWORD_IDP",
        lifetime=None,
        idle=120,
        life=0,
    ) -> dict[str, Any]:
        s: dict[str, Any] = {"access": access}
        if access == "ALLOW":
            s.update(
                {
                    "requireFactor": require_factor,
                    "primaryFactor": primary,
                    "rememberDeviceByDefault": False,
                    "session": {
                        "maxSessionIdleMinutes": idle,
                        "maxSessionLifetimeMinutes": life,
                        "usePersistentCookie": False,
                    },
                }
            )
            if require_factor:
                s["factorPromptMode"] = prompt or "SESSION"
                if (prompt or "SESSION") == "SESSION":
                    s["factorLifetime"] = lifetime or 15
        return {"signon": s}

    gsp_admins = _policy(
        GSP_ADMINS,
        "Admins session policy",
        "OKTA_SIGN_ON",
        1,
        [
            _rule(
                "rul_gsp_admin_mfa",
                "MFA every sign-in",
                0,
                {
                    "people": {"users": {"exclude": []}},
                    "network": {"connection": "ANYWHERE"},
                    "authContext": {"authType": "ANY"},
                },
                signon(require_factor=True, prompt="ALWAYS", idle=60, life=480),
                rtype="SIGN_ON",
            ),
        ],
        groups_include=[G_ADMINS],
    )
    gsp_contractors = _policy(
        GSP_CONTRACTORS,
        "Contractors session policy",
        "OKTA_SIGN_ON",
        2,
        [
            _rule(
                "rul_gsp_ctr_deny",
                "Deny from high-risk countries",
                0,
                {"network": {"connection": "ZONE", "include": [Z_HIGHRISK]}},
                signon(access="DENY"),
                rtype="SIGN_ON",
            ),
            _rule(
                "rul_gsp_ctr_mfa",
                "MFA per session",
                1,
                {"network": {"connection": "ANYWHERE"}},
                signon(require_factor=True, prompt="SESSION", lifetime=720),
                rtype="SIGN_ON",
            ),
        ],
        groups_include=[G_CONTRACTORS],
    )
    gsp_default = _policy(
        GSP_DEFAULT,
        "Default Policy",
        "OKTA_SIGN_ON",
        3,
        [
            _rule(
                "rul_gsp_default",
                "Default Rule",
                1,
                {
                    "people": {"users": {"exclude": []}},
                    "network": {"connection": "ANYWHERE"},
                    "authContext": {"authType": "ANY"},
                },
                signon(primary="PASSWORD_IDP_ANY_FACTOR"),
                system=True,
                rtype="SIGN_ON",
            ),
        ],
        system=True,
        groups_include=[G_EVERYONE],
    )

    # ---- authenticator enrollment policies -------------------------------------------------------
    mfa_finance = _policy(
        MFA_FINANCE,
        "Finance enrollment",
        "MFA_ENROLL",
        1,
        [
            _rule(
                "rul_mfa_fin",
                "Enroll at sign-in",
                0,
                {"network": {"connection": "ANYWHERE"}},
                {"enroll": {"self": "CHALLENGE"}},
                rtype="MFA_ENROLL",
            )
        ],
        groups_include=[G_FINANCE],
        settings={
            "type": "AUTHENTICATORS",
            "authenticators": [
                _enroll_setting("okta_password", "REQUIRED"),
                _enroll_setting("phone_number", "REQUIRED"),
                _enroll_setting("okta_email", "OPTIONAL"),
                _enroll_setting("security_question", "OPTIONAL"),
                _enroll_setting("okta_verify", "NOT_ALLOWED"),
                _enroll_setting("webauthn", "NOT_ALLOWED"),
            ],
        },
    )
    mfa_default = _policy(
        MFA_DEFAULT,
        "Default Policy",
        "MFA_ENROLL",
        2,
        [
            _rule(
                "rul_mfa_default",
                "Default Rule",
                1,
                {"network": {"connection": "ANYWHERE"}},
                {"enroll": {"self": "CHALLENGE"}},
                system=True,
                rtype="MFA_ENROLL",
            )
        ],
        system=True,
        groups_include=[G_EVERYONE],
        settings={
            "type": "AUTHENTICATORS",
            "authenticators": [
                _enroll_setting("okta_password", "REQUIRED"),
                _enroll_setting("okta_verify", "REQUIRED"),
                _enroll_setting("webauthn", "OPTIONAL"),
                _enroll_setting("phone_number", "OPTIONAL"),
                _enroll_setting("okta_email", "OPTIONAL"),
                _enroll_setting("google_otp", "OPTIONAL"),
            ],
        },
    )

    users = [
        _user(
            U_ALICE, "alice@acme.com", [G_EVERYONE, G_ENG, G_US], department="Engineering", countryCode="US"
        ),
        _user(
            U_BOB,
            "bob@contractor.example",
            [G_EVERYONE, G_CONTRACTORS],
            UT_CONTRACTOR,
            department="Engineering",
            countryCode="US",
        ),
        _user(
            U_CAROL, "carol@acme.com", [G_EVERYONE, G_ADMINS, G_ENG, G_US], department="IT", countryCode="US"
        ),
        _user(U_DAVE, "dave@acme.com", [G_EVERYONE, G_FINANCE, G_US], department="Finance", countryCode="US"),
        _user(U_ERIN, "erin@acme.com", [G_EVERYONE, G_SALES], department="Sales", countryCode="GB"),
        _user(U_BREAKGLASS, "breakglass@acme.com", [G_EVERYONE], department="IT", countryCode="US"),
    ]

    snap = Snapshot(
        manifest=SnapshotManifest(
            org_url=ORG, fetched_at="2026-01-01T00:00:00+00:00", tool_version="fixture", with_users=True
        ),
        policies=[
            p_admin,
            p_dash,
            p_std,
            p_payroll,
            p_weak,
            gsp_admins,
            gsp_contractors,
            gsp_default,
            mfa_finance,
            mfa_default,
        ],
        policy_mappings={},
        apps=apps,
        groups=groups,
        group_rules=group_rules,
        zones=zones,
        device_assurances=device_assurances,
        authenticators=authenticators,
        user_types=user_types,
        idps=[],
        users=users,
    )
    snap.manifest.counts = snap._counts()
    return snap


if __name__ == "__main__":  # pragma: no cover
    import sys

    build_acme().save_dir(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/acme")
