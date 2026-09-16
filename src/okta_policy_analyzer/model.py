"""Normalized intermediate representation (IR) of an Okta tenant's policy configuration.

The IR is independent of the Okta JSON shapes. Everything downstream (the SMT encoder, the reference
interpreter, the reports and the TLA+ exporter) works only on these dataclasses. Missing optional
conditions are represented by ``None`` and always mean "any".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .el.ast import Expr

# --------------------------------------------------------------------------------------------- enums


class PolicyType(StrEnum):
    ACCESS_POLICY = "ACCESS_POLICY"  # authentication (app sign-on) policy
    OKTA_SIGN_ON = "OKTA_SIGN_ON"  # global session policy
    MFA_ENROLL = "MFA_ENROLL"  # authenticator enrollment policy
    PASSWORD = "PASSWORD"
    PROFILE_ENROLLMENT = "PROFILE_ENROLLMENT"
    IDP_DISCOVERY = "IDP_DISCOVERY"
    OTHER = "OTHER"


class Status(StrEnum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    INVALID = "INVALID"


class Access(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class FactorMode(StrEnum):
    ONE_FA = "1FA"
    TWO_FA = "2FA"


class VerificationType(StrEnum):
    ASSURANCE = "ASSURANCE"
    AUTH_METHOD_CHAIN = "AUTH_METHOD_CHAIN"
    ID_PROOFING = "ID_PROOFING"


class Requirement(StrEnum):
    OPTIONAL = "OPTIONAL"
    REQUIRED = "REQUIRED"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class DevicePlatform(StrEnum):
    """Device platform values used by device conditions and device assurance policies.

    Okta uses ``OSX`` in ``DevicePolicyPlatformType`` and ``MACOS`` in device assurance; both are
    normalised to ``MACOS``.
    """

    ANDROID = "ANDROID"
    IOS = "IOS"
    MACOS = "MACOS"
    WINDOWS = "WINDOWS"
    CHROMEOS = "CHROMEOS"
    LINUX = "LINUX"
    OTHER = "OTHER"


class PrimaryFactor(StrEnum):
    PASSWORD_IDP = "PASSWORD_IDP"
    PASSWORD_IDP_ANY_FACTOR = "PASSWORD_IDP_ANY_FACTOR"


class FactorPromptMode(StrEnum):
    ALWAYS = "ALWAYS"
    DEVICE = "DEVICE"
    SESSION = "SESSION"


class EnrollStatus(StrEnum):
    REQUIRED = "REQUIRED"
    OPTIONAL = "OPTIONAL"
    NOT_ALLOWED = "NOT_ALLOWED"


# ---------------------------------------------------------------------------------------- inventory


@dataclass
class Group:
    id: str
    name: str
    type: str = "OKTA_GROUP"  # OKTA_GROUP | APP_GROUP | BUILT_IN
    users_count: int | None = None
    description: str = ""

    @property
    def is_everyone(self) -> bool:
        return self.type == "BUILT_IN" and self.name == "Everyone"


@dataclass
class GroupRule:
    id: str
    name: str
    status: Status
    expression: str
    target_group_ids: list[str]
    exclude_user_ids: list[str] = field(default_factory=list)
    exclude_group_ids: list[str] = field(default_factory=list)
    expr_ast: Expr | None = None
    parse_error: str | None = None


@dataclass
class Zone:
    id: str
    name: str
    type: str  # IP | DYNAMIC | DYNAMIC_V2
    status: Status = Status.ACTIVE
    usage: str = "POLICY"  # POLICY | BLOCKLIST
    system: bool = False
    summary: str = ""  # human-readable summary of gateways/locations/asns


@dataclass
class DeviceAssurance:
    id: str
    name: str
    platform: DevicePlatform


@dataclass
class AuthenticatorMethod:
    type: (
        str  # password email sms voice push totp signed_nonce otp webauthn security_question idp duo cert tac
    )
    status: Status = Status.ACTIVE


@dataclass
class Authenticator:
    id: str
    key: str  # okta_password okta_verify webauthn ...
    name: str
    type: str  # password app security_key email phone security_question federated ...
    status: Status = Status.ACTIVE
    methods: list[AuthenticatorMethod] = field(default_factory=list)
    allowed_for: str = (
        "any"  # settings.allowedFor: any | sso | recovery | none (email/phone/security question)
    )

    def usable_for_sign_in(self) -> bool:
        return self.status == Status.ACTIVE and self.allowed_for.lower() not in ("none", "recovery")

    def active_methods(self) -> list[str]:
        return [m.type for m in self.methods if m.status == Status.ACTIVE]


@dataclass
class UserType:
    id: str
    name: str
    display_name: str = ""
    default: bool = False


@dataclass
class App:
    id: str
    label: str
    name: str = ""
    status: Status = Status.ACTIVE
    sign_on_mode: str = ""
    access_policy_id: str | None = None


@dataclass
class User:
    """A concrete user, only present in snapshots fetched with ``--with-users``."""

    id: str
    login: str
    status: str = "ACTIVE"
    user_type_id: str | None = None
    group_ids: list[str] = field(default_factory=list)
    profile: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------------------- conditions


@dataclass
class PeopleCondition:
    users_include: list[str] = field(default_factory=list)
    users_exclude: list[str] = field(default_factory=list)
    groups_include: list[str] = field(default_factory=list)
    groups_exclude: list[str] = field(default_factory=list)

    def is_trivial(self) -> bool:
        return not (self.users_include or self.users_exclude or self.groups_include or self.groups_exclude)


@dataclass
class NetworkCondition:
    connection: str = "ANYWHERE"  # ANYWHERE | ZONE
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)


@dataclass
class DeviceCondition:
    registered: bool | None = None
    managed: bool | None = None
    assurance_include: list[str] = field(default_factory=list)
    platform_types: list[DevicePlatform] = field(default_factory=list)
    mdm_frameworks: list[str] = field(default_factory=list)


@dataclass
class PlatformSpec:
    type: str  # ANY | DESKTOP | MOBILE | OTHER
    os_type: str | None = None  # ANDROID IOS OSX WINDOWS CHROMEOS OTHER ANY ...
    os_expression: str | None = None


@dataclass
class PlatformCondition:
    include: list[PlatformSpec] = field(default_factory=list)
    exclude: list[PlatformSpec] = field(default_factory=list)


@dataclass
class UserTypeCondition:
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)


@dataclass
class ElCondition:
    text: str
    ast: Expr | None = None
    parse_error: str | None = None


@dataclass
class IdpCondition:
    provider: str = "ANY"  # ANY | OKTA | SPECIFIC_IDP
    idp_ids: list[str] = field(default_factory=list)


@dataclass
class RuleConditions:
    people: PeopleCondition | None = None
    network: NetworkCondition | None = None
    device: DeviceCondition | None = None
    platform: PlatformCondition | None = None
    risk_level: RiskLevel | None = None  # ANY normalised to None
    user_type: UserTypeCondition | None = None
    el: ElCondition | None = None
    auth_type: str | None = None  # ANY normalised to None; LDAP_INTERFACE | RADIUS
    idp: IdpCondition | None = None
    behaviors: list[str] = field(default_factory=list)  # risk.behaviors (behavior ids/names), any-of
    unsupported: dict[str, Any] = field(default_factory=dict)  # condition keys we do not model


# ------------------------------------------------------------------------------------------ actions

KNOWLEDGE = "KNOWLEDGE"
POSSESSION = "POSSESSION"


@dataclass
class Constraint:
    """One knowledge or possession constraint inside a constraint set."""

    kind: str  # KNOWLEDGE | POSSESSION
    types: list[str] = field(
        default_factory=list
    )  # SECURITY_KEY PHONE EMAIL PASSWORD SECURITY_QUESTION APP FEDERATED
    methods: list[str] = field(default_factory=list)  # PASSWORD ... WEBAUTHN DUO IDP CERT
    authentication_methods: list[tuple[str, str | None]] = field(default_factory=list)  # (key, method)
    excluded_authentication_methods: list[tuple[str, str | None]] = field(default_factory=list)
    required: bool = True
    reauthenticate_in: str | None = None
    # possession only
    device_bound: Requirement = Requirement.OPTIONAL
    hardware_protection: Requirement = Requirement.OPTIONAL
    phishing_resistant: Requirement = Requirement.OPTIONAL
    user_presence: Requirement = Requirement.REQUIRED
    user_verification: Requirement = Requirement.OPTIONAL


@dataclass
class ConstraintSet:
    """Constraint sets are OR-ed; the constraints inside one set are AND-ed."""

    knowledge: Constraint | None = None
    possession: Constraint | None = None


@dataclass
class ChainStep:
    authentication_methods: list[tuple[str, str | None]] = field(default_factory=list)
    reauthenticate_in: str | None = None


@dataclass
class Chain:
    steps: list[ChainStep] = field(default_factory=list)


@dataclass
class VerificationMethod:
    type: VerificationType = VerificationType.ASSURANCE
    factor_mode: FactorMode = FactorMode.TWO_FA
    reauthenticate_in: str | None = None
    inactivity_period: str | None = None
    constraints: list[ConstraintSet] = field(default_factory=list)
    chains: list[Chain] = field(default_factory=list)


@dataclass
class AccessAction:
    access: Access = Access.ALLOW
    verification: VerificationMethod | None = None
    keep_me_signed_in: str | None = None  # ALLOWED | NOT_ALLOWED


@dataclass
class SignOnAction:
    access: Access = Access.ALLOW
    require_factor: bool = False
    primary_factor: PrimaryFactor = PrimaryFactor.PASSWORD_IDP
    factor_prompt_mode: FactorPromptMode | None = None
    factor_lifetime: int | None = None
    remember_device_by_default: bool = False
    max_session_idle_minutes: int | None = None
    max_session_lifetime_minutes: int | None = None
    use_persistent_cookie: bool = False


@dataclass
class EnrollAction:
    self_enroll: str = "CHALLENGE"  # CHALLENGE | LOGIN | NEVER | NEVER_INCLUDING_RECOVERY


@dataclass
class OtherAction:
    raw: dict[str, Any] = field(default_factory=dict)


Action = AccessAction | SignOnAction | EnrollAction | OtherAction


# ------------------------------------------------------------------------------------------ policies


@dataclass
class Rule:
    id: str
    name: str
    priority: int
    status: Status
    system: bool
    conditions: RuleConditions
    action: Action
    policy_id: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def is_active(self) -> bool:
        return self.status == Status.ACTIVE


@dataclass
class AuthenticatorSetting:
    key: str
    enroll_self: EnrollStatus
    constraints: dict[str, Any] | None = None


@dataclass
class Policy:
    id: str
    name: str
    type: PolicyType
    priority: int
    status: Status
    system: bool
    rules: list[Rule]  # sorted in evaluation order (priority ascending, catch-all last)
    group_include: list[str] = field(default_factory=list)  # policy-level people.groups.include
    description: str = ""
    app_ids: list[str] = field(default_factory=list)  # ACCESS_POLICY: apps governed by this policy
    authenticator_settings: list[AuthenticatorSetting] = field(default_factory=list)  # MFA_ENROLL
    resource_type: str = (
        "APP"  # ACCESS_POLICY: APP, or END_USER_ACCOUNT_MANAGEMENT (Okta account management policy)
    )
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def is_active(self) -> bool:
        return self.status == Status.ACTIVE

    @property
    def is_account_management(self) -> bool:
        return self.type == PolicyType.ACCESS_POLICY and self.resource_type == "END_USER_ACCOUNT_MANAGEMENT"

    def active_rules(self) -> list[Rule]:
        return [r for r in self.rules if r.is_active]


# -------------------------------------------------------------------------------------------- tenant


@dataclass
class Tenant:
    org_url: str = ""
    fetched_at: str = ""
    groups: dict[str, Group] = field(default_factory=dict)
    group_rules: list[GroupRule] = field(default_factory=list)
    zones: dict[str, Zone] = field(default_factory=dict)
    device_assurances: dict[str, DeviceAssurance] = field(default_factory=dict)
    authenticators: dict[str, Authenticator] = field(default_factory=dict)  # by key
    user_types: dict[str, UserType] = field(default_factory=dict)
    apps: dict[str, App] = field(default_factory=dict)
    idps: dict[str, str] = field(default_factory=dict)  # id -> name
    users: list[User] = field(default_factory=list)
    access_policies: list[Policy] = field(default_factory=list)  # priority order
    session_policies: list[Policy] = field(default_factory=list)  # priority order
    enrollment_policies: list[Policy] = field(default_factory=list)  # priority order
    password_policies: list[Policy] = field(default_factory=list)
    account_management_policies: list[Policy] = field(default_factory=list)  # Okta account management policy
    other_policies: list[Policy] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # ----------------------------------------------------------------------------- lookups
    @property
    def everyone_group_id(self) -> str | None:
        for g in self.groups.values():
            if g.is_everyone:
                return g.id
        return None

    def policy(self, policy_id: str) -> Policy | None:
        for pol in self.all_policies():
            if pol.id == policy_id:
                return pol
        return None

    def all_policies(self) -> list[Policy]:
        return [
            *self.access_policies,
            *self.session_policies,
            *self.enrollment_policies,
            *self.password_policies,
            *self.account_management_policies,
            *self.other_policies,
        ]

    def access_policy_for_app(self, app_id: str) -> Policy | None:
        app = self.apps.get(app_id)
        if app is None or app.access_policy_id is None:
            return None
        return self.policy(app.access_policy_id)

    def group_name(self, group_id: str) -> str:
        g = self.groups.get(group_id)
        return g.name if g else f"<missing group {group_id}>"

    def zone_name(self, zone_id: str) -> str:
        z = self.zones.get(zone_id)
        return z.name if z else f"<missing zone {zone_id}>"

    def app_label(self, app_id: str) -> str:
        a = self.apps.get(app_id)
        return a.label if a else f"<missing app {app_id}>"

    def referenced_group_ids(self) -> set[str]:
        """Every group id mentioned by any policy, rule or group rule."""
        ids: set[str] = set()
        for pol in self.all_policies():
            ids.update(pol.group_include)
            for r in pol.rules:
                if r.conditions.people:
                    ids.update(r.conditions.people.groups_include)
                    ids.update(r.conditions.people.groups_exclude)
        for gr in self.group_rules:
            ids.update(gr.target_group_ids)
            ids.update(gr.exclude_group_ids)
        return ids
