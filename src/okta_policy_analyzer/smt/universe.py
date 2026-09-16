"""The symbolic world a policy is evaluated in.

One *world* is a user together with a request context. Every fact a rule can test is a z3 variable:

WHO (user) variables
    ``member[g]``        Bool  – the user belongs to group g (Everyone is the constant True)
    ``user_is[u]``       Bool  – the user *is* the specific user u referenced by a rule (at most one true)
    ``user_type``        Int   – index into the tenant's user types (+ OTHER)
    ``attr:<path>``      Int   – value of a profile attribute referenced by an expression, as an index into
                                 the literals it is compared with (+ OTHER, and NULL when compared to null)
    ``pred:<...>``       Bool  – result of a string predicate on an attribute (linked to the literal values)

CONTEXT variables
    ``zone[z]``          Bool  – request IP is inside network zone z (zones may overlap)
    ``dev_registered``   Bool, ``dev_managed`` Bool, ``dev_platform`` Int (enum), ``assurance[d]`` Bool
    ``risk``             Int (LOW/MEDIUM/HIGH)
    ``auth_type``        Int (WEB/LDAP_INTERFACE/RADIUS), ``idp`` Int (OKTA / specific idps / OTHER)
    ``opaque:<text>``    Bool  – an expression fragment the tool cannot interpret (free, over-approximating)

Domain axioms tie them together (managed ⇒ registered, assurance ⇒ platform, group rules ⇒ membership,
blocklist zones never reach policy evaluation, ...). Everything is deterministic and named so that results
are reproducible and witnesses are readable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import z3

from ..model import DevicePlatform, GroupRule, RiskLevel, Status, Tenant

PLATFORMS: list[DevicePlatform] = [
    DevicePlatform.ANDROID,
    DevicePlatform.IOS,
    DevicePlatform.MACOS,
    DevicePlatform.WINDOWS,
    DevicePlatform.CHROMEOS,
    DevicePlatform.LINUX,
    DevicePlatform.OTHER,
]
MOBILE = {DevicePlatform.ANDROID, DevicePlatform.IOS}
DESKTOP = {DevicePlatform.MACOS, DevicePlatform.WINDOWS, DevicePlatform.CHROMEOS, DevicePlatform.LINUX}
RISKS: list[RiskLevel] = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH]
AUTH_TYPES = ["WEB", "LDAP_INTERFACE", "RADIUS"]
OTHER = "OTHER"
NULL = "<null>"


@dataclass
class UniverseOptions:
    #: group rules imply membership only (manual membership possible). If True, membership ⇔ expression.
    strict_group_rules: bool = False
    #: device assurance policies need Okta Verify signals, i.e. a registered device.
    assurance_requires_registered: bool = True
    #: requests from BLOCKLIST zones never reach policy evaluation.
    blocklist_zones_unreachable: bool = True
    #: users in the snapshot pin the membership of the corresponding ``user_is`` variables.
    pin_known_users: bool = True


@dataclass
class Witness:
    """A concrete, human-readable world extracted from a z3 model."""

    groups_in: list[str] = field(default_factory=list)
    groups_out: list[str] = field(default_factory=list)
    user: str | None = None
    user_type: str | None = None
    attributes: dict[str, str] = field(default_factory=dict)
    zones_in: list[str] = field(default_factory=list)
    registered: bool | None = None
    managed: bool | None = None
    platform: str | None = None
    assurances: list[str] = field(default_factory=list)
    risk: str | None = None
    auth_type: str | None = None
    idp: str | None = None
    opaque: dict[str, bool] = field(default_factory=dict)
    predicates: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v not in (None, [], {})}

    def describe(self, tenant: Tenant | None = None) -> str:
        name = (lambda g: tenant.group_name(g) if tenant else g) if tenant else (lambda g: g)
        zname = (lambda z: tenant.zone_name(z) if tenant else z) if tenant else (lambda z: z)
        parts: list[str] = []
        if self.user:
            login = (
                next((usr.login for usr in tenant.users if usr.id == self.user), self.user)
                if tenant
                else self.user
            )
            parts.append(f"user={login}")
        parts.append("groups={" + ", ".join(name(g) for g in self.groups_in) + "}")
        if self.user_type:
            ut = tenant.user_types.get(self.user_type) if tenant else None
            parts.append(f"userType={ut.name if ut else self.user_type}")
        for k, v in self.attributes.items():
            parts.append(f"{k}={v}")
        parts.append(
            "zones={" + ", ".join(zname(z) for z in self.zones_in) + "}"
            if self.zones_in
            else "zones={} (no zone)"
        )
        dev = []
        if self.registered is not None:
            dev.append("registered" if self.registered else "unregistered")
        if self.managed is not None:
            dev.append("managed" if self.managed else "unmanaged")
        if self.platform:
            dev.append(self.platform)
        if self.assurances:
            names_ = [
                (tenant.device_assurances[a].name if tenant and a in tenant.device_assurances else a)
                for a in self.assurances
            ]
            dev.append("assurance={" + ", ".join(names_) + "}")
        if dev:
            parts.append("device=" + " ".join(dev))
        if self.risk:
            parts.append(f"risk={self.risk}")
        if self.auth_type and self.auth_type != "WEB":
            parts.append(f"authType={self.auth_type}")
        if self.idp and self.idp != "OKTA":
            parts.append(f"idp={self.idp}")
        for k, v in self.opaque.items():
            parts.append(f"[{k}]={'true' if v else 'false'}")
        return ", ".join(parts)


class Universe:
    """Builds and owns every symbolic variable plus the domain axioms for one tenant."""

    def __init__(self, tenant: Tenant, options: UniverseOptions | None = None):
        self.tenant = tenant
        self.opt = options or UniverseOptions()
        self.assumptions: list[str] = []  # modelling assumptions surfaced in reports
        # --- WHO ------------------------------------------------------------------------------
        self.group_ids: list[str] = sorted(set(tenant.groups) | tenant.referenced_group_ids())
        self.everyone = tenant.everyone_group_id
        self.member: dict[str, z3.BoolRef] = {}
        for gid in self.group_ids:
            self.member[gid] = z3.BoolVal(True) if gid == self.everyone else z3.Bool(f"member[{gid}]")
        self.user_ids: list[str] = sorted(self._referenced_user_ids())
        self.user_is: dict[str, z3.BoolRef] = {u: z3.Bool(f"user_is[{u}]") for u in self.user_ids}
        self.user_type_ids: list[str] = sorted(tenant.user_types)
        self.user_type = z3.Int("user_type")  # 0..n (n = OTHER)
        self.attr_literals: dict[str, list[Any]] = {}  # attribute path -> literals (None = null)
        self.attr_vars: dict[str, z3.ArithRef] = {}
        self.pred_vars: dict[str, z3.BoolRef] = {}
        self.pred_meta: dict[str, tuple[str, str, Any]] = {}  # name -> (function, attr path, literal)
        self.revision = (
            0  # bumped whenever a new variable/literal/opaque atom is created (axioms must be re-read)
        )
        self._pred_truth: dict[str, Any] = {}  # name -> callable deciding the predicate for a concrete value
        self._pred_linked: set[tuple[str, Any]] = set()  # (predicate name, literal) pairs already constrained
        self.opaque_vars: dict[str, z3.BoolRef] = {}
        # --- CONTEXT ---------------------------------------------------------------------------
        self.zone_ids: list[str] = sorted(set(tenant.zones) | self._referenced_zone_ids())
        self.zone: dict[str, z3.BoolRef] = {z: z3.Bool(f"zone[{z}]") for z in self.zone_ids}
        self.registered = z3.Bool("dev_registered")
        self.managed = z3.Bool("dev_managed")
        self.platform = z3.Int("dev_platform")
        self.assurance_ids: list[str] = sorted(
            set(tenant.device_assurances) | self._referenced_assurance_ids()
        )
        self.assurance: dict[str, z3.BoolRef] = {d: z3.Bool(f"assurance[{d}]") for d in self.assurance_ids}
        self.risk = z3.Int("risk")
        self.auth_type = z3.Int("auth_type")
        self.idp_ids: list[str] = sorted(tenant.idps)
        self.idp = z3.Int("idp")  # 0 = OKTA, 1..n = idps, n+1 = OTHER
        self._axioms: list[z3.BoolRef] = []
        self._build_axioms()

    # ------------------------------------------------------------------------------ discovery
    def _referenced_user_ids(self) -> set[str]:
        ids: set[str] = set()
        for pol in self.tenant.all_policies():
            for r in pol.rules:
                if r.conditions.people:
                    ids.update(r.conditions.people.users_include)
                    ids.update(r.conditions.people.users_exclude)
        for gr in self.tenant.group_rules:
            ids.update(gr.exclude_user_ids)
        return ids

    def _referenced_zone_ids(self) -> set[str]:
        ids: set[str] = set()
        for pol in self.tenant.all_policies():
            for r in pol.rules:
                if r.conditions.network:
                    ids.update(r.conditions.network.include)
                    ids.update(r.conditions.network.exclude)
        return ids

    def _referenced_assurance_ids(self) -> set[str]:
        ids: set[str] = set()
        for pol in self.tenant.all_policies():
            for r in pol.rules:
                if r.conditions.device:
                    ids.update(r.conditions.device.assurance_include)
        return ids

    # ------------------------------------------------------------------------------ enum helpers
    def platform_is(self, p: DevicePlatform) -> z3.BoolRef:
        return self.platform == PLATFORMS.index(p)

    def platform_in(self, ps: set[DevicePlatform] | list[DevicePlatform]) -> z3.BoolRef:
        return z3.Or(*[self.platform_is(p) for p in ps]) if ps else z3.BoolVal(False)

    def risk_is(self, level: RiskLevel) -> z3.BoolRef:
        return self.risk == RISKS.index(level)

    def auth_type_is(self, name: str) -> z3.BoolRef:
        return self.auth_type == AUTH_TYPES.index(name if name in AUTH_TYPES else "WEB")

    def user_type_is(self, type_id: str) -> z3.BoolRef:
        if type_id in self.user_type_ids:
            return self.user_type == self.user_type_ids.index(type_id)
        return z3.BoolVal(False)  # unknown user type id can never match

    def idp_is(self, idp_id: str) -> z3.BoolRef:
        if idp_id in self.idp_ids:
            return self.idp == 1 + self.idp_ids.index(idp_id)
        return z3.BoolVal(False)

    def idp_is_okta(self) -> z3.BoolRef:
        return self.idp == 0

    # ------------------------------------------------------------------------------ attributes
    def attr_var(self, path: str) -> z3.ArithRef:
        if path not in self.attr_vars:
            self.attr_vars[path] = z3.Int(f"attr:{path}")
            self.attr_literals.setdefault(path, [])
            self.revision += 1
        return self.attr_vars[path]

    def attr_equals(self, path: str, literal: Any) -> z3.BoolRef:
        """``user.<path> == literal`` as an index equality; literals are interned per attribute."""
        v = self.attr_var(path)
        lits = self.attr_literals[path]
        key = NULL if literal is None else literal
        if key not in lits:
            lits.append(key)
            self.revision += 1
        return v == lits.index(key)

    def attr_other(self, path: str) -> z3.BoolRef:
        v = self.attr_var(path)
        return v == len(self.attr_literals[path])

    def predicate(self, function: str, path: str, literal: Any, truth: Any) -> z3.BoolRef:
        """A Boolean for ``function(user.<path>, literal)``, consistent with the interned literal values.

        ``truth(value)`` computes the predicate for a concrete attribute value; it is used to constrain the
        variable for every literal the attribute is compared with elsewhere. For the OTHER value it stays free.
        """
        name = f"pred:{function}({path},{literal!r})"
        if name not in self.pred_vars:
            self.revision += 1
            self.pred_vars[name] = z3.Bool(name)
            self.pred_meta[name] = (function, path, literal)
            self.attr_var(path)
            self._pred_truth[name] = truth
        return self.pred_vars[name]

    def opaque(self, text: str) -> z3.BoolRef:
        """A free Boolean standing for an uninterpreted expression fragment (shared by identical text)."""
        if text not in self.opaque_vars:
            self.revision += 1
            self.opaque_vars[text] = z3.Bool(f"opaque:{text}")
            self.assumptions.append(f"expression fragment treated as an unconstrained predicate: {text}")
        return self.opaque_vars[text]

    # ------------------------------------------------------------------------------ axioms
    def _build_axioms(self) -> None:
        t = self.tenant
        ax = self._axioms
        # at most one specific referenced user
        if len(self.user_is) > 1:
            ax.append(z3.AtMost(*self.user_is.values(), 1))
        # known users pin their memberships (and user type)
        if self.opt.pin_known_users:
            known = {u.id: u for u in t.users}
            for uid, var in self.user_is.items():
                u = known.get(uid)
                if u is None:
                    continue
                for gid in self.group_ids:
                    if gid == self.everyone:
                        continue
                    ax.append(z3.Implies(var, self.member[gid] == z3.BoolVal(gid in u.group_ids)))
                if u.user_type_id and u.user_type_id in self.user_type_ids:
                    ax.append(z3.Implies(var, self.user_type_is(u.user_type_id)))
        ax.append(z3.And(self.user_type >= 0, self.user_type <= len(self.user_type_ids)))
        ax.append(z3.And(self.platform >= 0, self.platform < len(PLATFORMS)))
        ax.append(z3.And(self.risk >= 0, self.risk < len(RISKS)))
        ax.append(z3.And(self.auth_type >= 0, self.auth_type < len(AUTH_TYPES)))
        ax.append(z3.And(self.idp >= 0, self.idp <= len(self.idp_ids) + 1))
        ax.append(z3.Implies(self.managed, self.registered))
        self.assumptions.append("a managed device is always a registered device")
        for did, var in self.assurance.items():
            da = t.device_assurances.get(did)
            if da is not None:
                ax.append(z3.Implies(var, self.platform_is(da.platform)))
                if self.opt.assurance_requires_registered:
                    ax.append(z3.Implies(var, self.registered))
            else:
                ax.append(z3.Not(var))  # a deleted assurance policy can never be satisfied
        if self.opt.assurance_requires_registered and self.assurance:
            self.assumptions.append(
                "satisfying a device assurance policy requires a registered device (Okta Verify signals)"
            )
        for zid, var in self.zone.items():
            z = t.zones.get(zid)
            if z is None:
                ax.append(z3.Not(var))  # deleted zone: nothing is inside it
            elif z.status != Status.ACTIVE:
                ax.append(z3.Not(var))
            elif z.usage == "BLOCKLIST" and self.opt.blocklist_zones_unreachable:
                ax.append(z3.Not(var))
        if any(z.usage == "BLOCKLIST" for z in t.zones.values()) and self.opt.blocklist_zones_unreachable:
            self.assumptions.append("requests from IP blocklist zones are rejected before policy evaluation")
        # unknown (deleted) groups referenced by rules can have no members
        for gid in self.group_ids:
            if gid not in t.groups and gid != self.everyone:
                ax.append(z3.Not(self.member[gid]))
        if any(gid not in t.groups for gid in self.group_ids if gid != self.everyone):
            self.assumptions.append(
                "groups referenced by rules but absent from the snapshot are treated as empty"
            )
        # group rules
        self._group_rule_axioms()

    def _group_rule_axioms(self) -> None:
        from .el_encoder import ELEncoder  # local import to avoid a cycle

        enc = ELEncoder(self)
        rule_targets: dict[str, list[z3.BoolRef]] = {}
        for gr in self.tenant.group_rules:
            if gr.status != Status.ACTIVE or gr.expr_ast is None:
                if gr.status == Status.ACTIVE and gr.expression:
                    self.assumptions.append(
                        f"group rule {gr.name!r} has an unparsable expression; its memberships are unconstrained"
                    )
                continue
            cond = enc.encode_bool(gr.expr_ast)
            excl = [self.user_is[u] for u in gr.exclude_user_ids if u in self.user_is]
            excl += [self.member[g] for g in gr.exclude_group_ids if g in self.member]
            if excl:
                cond = z3.And(cond, z3.Not(z3.Or(*excl)))
            for gid in gr.target_group_ids:
                if gid in self.member and gid != self.everyone:
                    self._axioms.append(z3.Implies(cond, self.member[gid]))
                    rule_targets.setdefault(gid, []).append(cond)
        if self.opt.strict_group_rules:
            for gid, conds in rule_targets.items():
                self._axioms.append(z3.Implies(self.member[gid], z3.Or(*conds)))
            if rule_targets:
                self.assumptions.append(
                    "strict group rules: membership of rule-managed groups holds only via a rule (no manual assignment)"
                )
        elif rule_targets:
            self.assumptions.append(
                "group rules add members; manual membership of rule-managed groups is still possible"
            )
        self._finish_predicates()

    def _finish_predicates(self) -> None:
        """Link string-predicate variables to the interned literal values of their attribute (idempotent)."""
        for name, (_function, path, _literal) in self.pred_meta.items():
            truth = self._pred_truth[name]
            for value in self.attr_literals.get(path, []):
                if (name, value) in self._pred_linked:
                    continue
                self._pred_linked.add((name, value))
                concrete = None if value == NULL else value
                try:
                    result = bool(truth(concrete))
                except Exception:  # noqa: BLE001 - predicate cannot be decided for this literal
                    continue
                self._axioms.append(
                    z3.Implies(
                        self.attr_var(path) == self.attr_literals[path].index(value),
                        self.pred_vars[name] == result,
                    )
                )

    def axioms(self) -> list[z3.BoolRef]:
        """Domain axioms for the current state of the universe (predicate links and attribute bounds are finalised lazily).

        Attribute variables are indices into their interned literal list (index ``len`` = any other value), so each
        gets the finite bound ``0 <= v <= len(literals)``; without it, all-SAT would enumerate endless "other" values.
        """
        self._finish_predicates()
        bounds = [z3.And(v >= 0, v <= len(self.attr_literals[path])) for path, v in self.attr_vars.items()]
        return list(self._axioms) + bounds

    # ------------------------------------------------------------------------------ variable classes
    def who_vars(self) -> list[z3.ExprRef]:
        vs: list[z3.ExprRef] = [v for g, v in self.member.items() if g != self.everyone]
        vs += list(self.user_is.values())
        vs.append(self.user_type)
        vs += list(self.attr_vars.values())
        vs += list(self.pred_vars.values())
        return vs

    def context_vars(self) -> list[z3.ExprRef]:
        vs: list[z3.ExprRef] = list(self.zone.values())
        vs += [self.registered, self.managed, self.platform]
        vs += list(self.assurance.values())
        vs += [self.risk, self.auth_type, self.idp]
        vs += list(self.opaque_vars.values())
        return vs

    def all_vars(self) -> list[z3.ExprRef]:
        return self.who_vars() + self.context_vars()

    # ------------------------------------------------------------------------------ witnesses
    def witness(self, model: z3.ModelRef, *, full: bool = False) -> Witness:
        """Read a model back into a Witness. With ``full=False`` only variables the model assigns are reported."""

        def val(v: z3.ExprRef) -> Any:
            r = model.eval(v, model_completion=full)
            if z3.is_true(r):
                return True
            if z3.is_false(r):
                return False
            if z3.is_int_value(r):
                return r.as_long()
            return None

        w = Witness()
        for gid, var in self.member.items():
            if gid == self.everyone:
                continue
            b = val(var)
            if b is True:
                w.groups_in.append(gid)
            elif b is False:
                w.groups_out.append(gid)
        for uid, var in self.user_is.items():
            if val(var) is True:
                w.user = uid
        ut = val(self.user_type)
        if ut is not None:
            w.user_type = self.user_type_ids[ut] if ut < len(self.user_type_ids) else OTHER
        for path, var in self.attr_vars.items():
            i = val(var)
            if i is not None:
                lits = self.attr_literals[path]
                w.attributes[path] = repr(lits[i]) if i < len(lits) else "<other>"
        for name, var in self.pred_vars.items():
            b = val(var)
            if b is not None:
                w.predicates[name] = b
        for zid, var in self.zone.items():
            if val(var) is True:
                w.zones_in.append(zid)
        w.registered = val(self.registered)
        w.managed = val(self.managed)
        p = val(self.platform)
        if p is not None:
            w.platform = PLATFORMS[p].value
        for did, var in self.assurance.items():
            if val(var) is True:
                w.assurances.append(did)
        r = val(self.risk)
        if r is not None:
            w.risk = RISKS[r].value
        a = val(self.auth_type)
        if a is not None:
            w.auth_type = AUTH_TYPES[a]
        i = val(self.idp)
        if i is not None:
            w.idp = "OKTA" if i == 0 else (self.idp_ids[i - 1] if i - 1 < len(self.idp_ids) else OTHER)
        for text, var in self.opaque_vars.items():
            b = val(var)
            if b is not None:
                w.opaque[text] = b
        return w

    # ------------------------------------------------------------------------------ naming
    def literal_text(self, var: z3.ExprRef, value: Any, positive: bool = True) -> str:
        """Human-readable text for ``var == value`` (or its negation); ``value`` may be a set of enum values."""
        name = str(var)
        t = self.tenant
        if isinstance(value, frozenset):
            domain = self._enum_domain(name)
            labels = [self._enum_label(name, v) for v in sorted(value)]
            if domain is not None and len(value) > len(domain) / 2 and len(value) < len(domain):
                rest = [self._enum_label(name, v) for v in range(len(domain)) if v not in value]
                return f"{self._enum_name(name)} {'∉' if positive else '∈'} {{{', '.join(rest)}}}"
            return f"{self._enum_name(name)} {'∈' if positive else '∉'} {{{', '.join(labels)}}}"
        if name.startswith("member["):
            g = name[7:-1]
            return ("member of " if (value is True) == positive else "not member of ") + t.group_name(g)
        if name.startswith("user_is["):
            u = name[8:-1]
            login = next((usr.login for usr in t.users if usr.id == u), u)
            return ("is user " if (value is True) == positive else "is not user ") + login
        if name.startswith("zone["):
            z = name[5:-1]
            return ("in zone " if (value is True) == positive else "not in zone ") + t.zone_name(z)
        if name.startswith("assurance["):
            d = name[10:-1]
            da = t.device_assurances.get(d)
            return ("device passes " if (value is True) == positive else "device fails ") + (
                da.name if da else d
            )
        if name == "dev_registered":
            return "device registered" if (value is True) == positive else "device not registered"
        if name == "dev_managed":
            return "device managed" if (value is True) == positive else "device not managed"
        neg = "" if positive else "not "
        if name == "dev_platform":
            return f"platform {neg}{PLATFORMS[value].value}"
        if name == "risk":
            return f"risk {neg}{RISKS[value].value}"
        if name == "auth_type":
            return f"authType {neg}{AUTH_TYPES[value]}"
        if name == "idp":
            label = (
                "OKTA"
                if value == 0
                else (
                    t.idps.get(self.idp_ids[value - 1], self.idp_ids[value - 1])
                    if value - 1 < len(self.idp_ids)
                    else OTHER
                )
            )
            return f"idp {neg}{label}"
        if name == "user_type":
            label = t.user_types[self.user_type_ids[value]].name if value < len(self.user_type_ids) else OTHER
            return f"userType {neg}{label}"
        if name.startswith("attr:"):
            path = name[5:]
            lits = self.attr_literals.get(path, [])
            lit = repr(lits[value]) if value < len(lits) else "<any other value>"
            return f"{path} {'==' if positive else '!='} {lit}"
        if name.startswith("pred:"):
            return ("" if (value is True) == positive else "not ") + name[5:]
        if name.startswith("opaque:"):
            return ("" if (value is True) == positive else "not ") + f"[{name[7:]}]"
        return f"{name} {'==' if positive else '!='} {value}"

    def _enum_domain(self, name: str) -> list[Any] | None:
        if name == "dev_platform":
            return list(PLATFORMS)
        if name == "risk":
            return list(RISKS)
        if name == "auth_type":
            return list(AUTH_TYPES)
        if name == "idp":
            return ["OKTA", *self.idp_ids, OTHER]
        if name == "user_type":
            return [*self.user_type_ids, OTHER]
        if name.startswith("attr:"):
            return [*self.attr_literals.get(name[5:], []), OTHER]
        return None

    def _enum_name(self, name: str) -> str:
        return {
            "dev_platform": "platform",
            "risk": "risk",
            "auth_type": "authType",
            "idp": "idp",
            "user_type": "userType",
        }.get(name, name[5:] if name.startswith("attr:") else name)

    def _enum_label(self, name: str, value: int) -> str:
        t = self.tenant
        if name == "dev_platform":
            return PLATFORMS[value].value
        if name == "risk":
            return RISKS[value].value
        if name == "auth_type":
            return AUTH_TYPES[value]
        if name == "idp":
            return (
                "OKTA"
                if value == 0
                else (
                    t.idps.get(self.idp_ids[value - 1], self.idp_ids[value - 1])
                    if value - 1 < len(self.idp_ids)
                    else OTHER
                )
            )
        if name == "user_type":
            return t.user_types[self.user_type_ids[value]].name if value < len(self.user_type_ids) else OTHER
        if name.startswith("attr:"):
            lits = self.attr_literals.get(name[5:], [])
            return repr(lits[value]) if value < len(lits) else "<any other value>"
        return str(value)

    def group_rule_summary(self) -> list[str]:
        return [
            f"{gr.name}: {gr.expression} -> {[self.tenant.group_name(g) for g in gr.target_group_ids]}"
            for gr in self.tenant.group_rules
            if gr.status == Status.ACTIVE
        ]


def group_rule_targets(rules: list[GroupRule]) -> set[str]:
    return {g for gr in rules if gr.status == Status.ACTIVE for g in gr.target_group_ids}
