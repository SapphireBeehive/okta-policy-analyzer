"""ELEncoder: exact atoms, opaque fallbacks and agreement with the reference interpreter."""

from __future__ import annotations

import pytest
import z3

from okta_policy_analyzer.el import parse
from okta_policy_analyzer.interpreter import Interpreter, World
from okta_policy_analyzer.model import DevicePlatform, RiskLevel, Tenant
from okta_policy_analyzer.smt.el_encoder import ELEncoder
from okta_policy_analyzer.smt.sampling import sample_models, world_from_model
from okta_policy_analyzer.smt.universe import NULL, PLATFORMS, RISKS, Universe

from .fixtures import acme as fx


def _equivalent(a: z3.BoolRef, b: z3.BoolRef, *axioms: z3.BoolRef) -> bool:
    s = z3.Solver()
    s.add(*axioms)
    s.add(a != b)
    return s.check() == z3.unsat


def _enc(acme: Tenant) -> tuple[Universe, ELEncoder]:
    u = Universe(acme)
    return u, ELEncoder(u)


def _encode(enc: ELEncoder, text: str) -> z3.BoolRef:
    return enc.encode_bool(parse(text))


# --------------------------------------------------------------------------------------------- isMemberOf


def test_is_member_of_resolves_to_member_disjunction(acme: Tenant) -> None:
    u, enc = _enc(acme)
    f = _encode(enc, "user.isMemberOf({'group.type': {'OKTA_GROUP'}}, {'group.profile.name': 'S'})")
    # OKTA_GROUP groups whose name starts with "S": Sales, Service Accounts
    assert _equivalent(f, z3.Or(u.member[fx.G_SALES], u.member[fx.G_SVC]))
    assert not _equivalent(f, u.member[fx.G_SALES])
    assert not any("closed world" in a for a in u.assumptions)


def test_is_member_of_criteria_semantics(acme: Tenant) -> None:
    u, enc = _enc(acme)
    exact = _encode(enc, "user.isMemberOf({'group.profile.name': 'Sales', 'operator': 'EXACT'})")
    assert _equivalent(exact, u.member[fx.G_SALES])
    # default operator is STARTS_WITH; values within a key are OR-ed; maps are AND-ed on the same group
    ids = _encode(enc, "user.isMemberOf({'group.id': {'00g_eng', '00g_nope', '00g_finance'}})")
    assert _equivalent(ids, z3.Or(u.member[fx.G_ENG], u.member[fx.G_FINANCE]))
    both = _encode(
        enc, "user.isMemberOf({'group.id': {'00g_eng', '00g_everyone'}}, {'group.type': 'BUILT_IN'})"
    )
    assert _equivalent(both, z3.BoolVal(True))  # Everyone is the constant True
    one_map = _encode(enc, "user.isMemberOf({'group.type': 'OKTA_GROUP', 'group.profile.name': 'Exec'})")
    assert _equivalent(one_map, u.member[fx.G_EXEC])
    # the group-id disjunction never invents members for ids the snapshot does not have
    assert "00g_nope" not in u.member


def test_is_member_of_empty_resolution_is_false_with_note(acme: Tenant) -> None:
    u, enc = _enc(acme)
    text = "user.isMemberOf({'group.profile.name': 'Nope'})"
    f = _encode(enc, text)
    assert _equivalent(f, z3.BoolVal(False))
    assert any("closed world" in a and "matches no existing group" in a for a in u.assumptions)
    _encode(enc, text)
    assert sum("closed world" in a for a in u.assumptions) == 1  # noted once


def test_is_member_of_source_id_is_opaque(acme: Tenant) -> None:
    u, enc = _enc(acme)
    text = "user.isMemberOf({'group.source.id': '0aae4be2456eb62f7c3d'}, {'group.profile.name': 'Sales'})"
    e = parse(text)
    f = _encode(enc, text)
    assert list(u.opaque_vars) == [e.source()]
    assert f is u.opaque_vars[e.source()]


def test_get_groups_forms_lower_to_membership(acme: Tenant) -> None:
    u, enc = _enc(acme)
    sales = u.member[fx.G_SALES]
    assert _equivalent(
        _encode(enc, "Arrays.isEmpty(user.getGroups({'group.profile.name': 'Sales'}))"), z3.Not(sales)
    )
    assert _equivalent(
        _encode(enc, "user.getGroups({'group.profile.name': 'Sales'}).isEmpty()"), z3.Not(sales)
    )
    assert _equivalent(
        _encode(enc, "Arrays.size(user.getGroups({'group.profile.name': 'Sales'})) > 0"), sales
    )
    assert _equivalent(
        _encode(enc, "user.getGroups({'group.profile.name': 'Sales'}).size() == 0"), z3.Not(sales)
    )
    assert _equivalent(_encode(enc, "0 < user.getGroups({'group.profile.name': 'Sales'}).size()"), sales)
    assert _equivalent(
        _encode(enc, "user.getGroups({'group.profile.name': 'Sales'}).size() >= 0"), z3.BoolVal(True)
    )
    # projections filter on the projected field
    proj = _encode(enc, "user.getGroups({'group.type': 'OKTA_GROUP'}).![profile.name].contains('Finance')")
    assert _equivalent(proj, u.member[fx.G_FINANCE])
    by_id = _encode(enc, "Arrays.contains(user.getGroups({'group.type': 'OKTA_GROUP'}).![id], '00g_eng')")
    assert _equivalent(by_id, u.member[fx.G_ENG])
    # cardinalities beyond 1 are exact too
    two = _encode(enc, "Arrays.size(user.getGroups({'group.id': {'00g_eng', '00g_sales', '00g_svc'}})) >= 2")
    ms = [u.member[g] for g in (fx.G_ENG, fx.G_SALES, fx.G_SVC)]
    assert _equivalent(two, z3.AtLeast(*ms, 2))
    assert _equivalent(
        _encode(enc, "user.getGroups({'group.id': {'00g_eng', '00g_sales'}}).size() == 2"),
        z3.And(u.member[fx.G_ENG], u.member[fx.G_SALES]),
    )


# --------------------------------------------------------------------------------------------- context atoms


def test_risk_level_ties_to_universe_risk(acme: Tenant) -> None:
    u, enc = _enc(acme)
    assert _equivalent(_encode(enc, "security.risk.level == 'HIGH'"), u.risk_is(RiskLevel.HIGH))
    assert _equivalent(_encode(enc, "security.risk.level != 'LOW'"), z3.Not(u.risk_is(RiskLevel.LOW)))
    assert _equivalent(_encode(enc, "'MEDIUM' == security.risk.level"), u.risk_is(RiskLevel.MEDIUM))
    assert _equivalent(_encode(enc, "security.risk.level == 'CRITICAL'"), z3.BoolVal(False))
    assert not u.opaque_vars


def test_device_atoms_tie_to_universe_variables(acme: Tenant) -> None:
    u, enc = _enc(acme)
    assert _equivalent(_encode(enc, "device.profile.managed == true"), u.managed)
    assert _equivalent(_encode(enc, "device.profile.managed == false"), z3.Not(u.managed))
    assert _equivalent(_encode(enc, "device.profile.managed"), u.managed)
    assert _equivalent(_encode(enc, "!device.profile.registered"), z3.Not(u.registered))
    assert _equivalent(_encode(enc, "device.profile.registered != false"), u.registered)
    assert _equivalent(
        _encode(enc, "device.profile.platform == 'MACOS'"), u.platform_is(DevicePlatform.MACOS)
    )
    assert _equivalent(_encode(enc, "device.profile.platform == 'OSX'"), u.platform_is(DevicePlatform.MACOS))
    assert _equivalent(
        _encode(enc, "device.profile.platform != 'IOS'"), z3.Not(u.platform_is(DevicePlatform.IOS))
    )
    assert not u.opaque_vars
    # values without a counterpart in the model stay opaque rather than being approximated
    f = _encode(enc, "device.profile.platform == 'MOBILE_OTHER'")
    assert f is u.opaque_vars['(device.profile.platform == "MOBILE_OTHER")']
    g = _encode(enc, "device.profile.managed == 'true'")
    assert g is u.opaque_vars['(device.profile.managed == "true")']


# --------------------------------------------------------------------------------------------- attribute atoms


def test_status_and_internal_property_share_one_attribute(acme: Tenant) -> None:
    u, enc = _enc(acme)
    a = _encode(enc, 'user.getInternalProperty("status") == "ACTIVE"')
    b = _encode(enc, "user.status == 'ACTIVE'")
    assert _equivalent(a, b) and a.eq(b)
    assert u.attr_literals["user.status"] == ["ACTIVE"]
    assert _equivalent(_encode(enc, "user.getInternalProperty('status') != 'ACTIVE'"), z3.Not(a))


def test_method_form_predicates_match_static_forms(acme: Tenant) -> None:
    u, enc = _enc(acme)
    lower_m = _encode(enc, "user.profile.department.toLowerCase() == 'sales'")
    lower_s = _encode(enc, "String.toLowerCase(user.department) == 'sales'")
    assert lower_m.eq(lower_s)
    assert "pred:String.toLowerCase(user.department,'sales')" in u.pred_vars
    contains_m = _encode(enc, "user.profile.email.contains('@acme.com')")
    contains_s = _encode(enc, "String.stringContains(user.email, '@acme.com')")
    assert contains_m.eq(contains_s)
    assert _encode(enc, "user.email.startsWith('svc-')").eq(
        _encode(enc, "String.startsWith(user.email, 'svc-')")
    )
    assert _encode(enc, "user.email.endsWith('.io')").eq(_encode(enc, "String.endsWith(user.email, '.io')"))
    composed = _encode(enc, "user.profile.department.toLowerCase().contains('sales')")
    name = "pred:String.stringContains∘String.toLowerCase(user.department,'sales')"
    assert name in u.pred_vars and composed.eq(u.pred_vars[name])
    assert _encode(enc, "Arrays.contains(user.tags, 'vip')").eq(
        u.pred_vars["pred:Arrays.contains(user.tags,'vip')"]
    )
    assert _encode(enc, "user.tags.isEmpty()").eq(u.pred_vars["pred:isEmpty(user.tags,None)"])
    assert not u.opaque_vars


def test_predicates_are_linked_to_literal_values(acme: Tenant) -> None:
    u, enc = _enc(acme)
    pred = _encode(enc, "user.profile.department.toLowerCase().contains('sales')")
    is_sales = _encode(enc, "user.department == 'Enterprise Sales'")
    is_eng = _encode(enc, "user.department == 'Engineering'")
    ax = u.axioms()
    assert _equivalent(z3.Implies(is_sales, pred), z3.BoolVal(True), *ax)
    assert _equivalent(z3.Implies(is_eng, z3.Not(pred)), z3.BoolVal(True), *ax)


def test_matches_is_exact_for_attribute_and_literal_regex(acme: Tenant) -> None:
    u, enc = _enc(acme)
    f = _encode(enc, 'user.department matches "California-[a-zA-Z]+-Sales"')
    assert f.eq(u.pred_vars["pred:matches(user.department,'California-[a-zA-Z]+-Sales')"])
    yes = _encode(enc, "user.department == 'California-North-Sales'")
    no = _encode(enc, "user.department == 'California-North-Sales-Team'")  # full match, not search
    ax = u.axioms()
    assert _equivalent(z3.Implies(yes, f), z3.BoolVal(True), *ax)
    assert _equivalent(z3.Implies(no, z3.Not(f)), z3.BoolVal(True), *ax)
    # a regex over a non-attribute, or an uncompilable one, is opaque
    g = _encode(enc, "login.identifier matches '.*@corp'")
    assert g is u.opaque_vars['(login.identifier matches ".*@corp")']
    h = _encode(enc, "user.title matches '('")
    assert h is u.opaque_vars['(user.title matches "(")']


def test_boolean_structure(acme: Tenant) -> None:
    u, enc = _enc(acme)
    m = u.member[fx.G_ADMINS]
    assert _equivalent(_encode(enc, "isMemberOfGroup('00g_admins') == true"), m)
    assert _equivalent(_encode(enc, "false == isMemberOfGroup('00g_admins')"), z3.Not(m))
    # ==/!= between two Boolean-typed expressions
    both = _encode(enc, "user.isMemberOf({'group.id': '00g_admins'}) != device.profile.managed")
    assert _equivalent(both, z3.Xor(m, u.managed))
    # ... but a bare attribute is not syntactically Boolean, so comparing it with a Boolean stays opaque
    mixed = _encode(enc, "user.isMemberOf({'group.id': '00g_admins'}) != user.isContractor")
    assert (
        mixed
        is u.opaque_vars[parse("user.isMemberOf({'group.id': '00g_admins'}) != user.isContractor").source()]
    )
    u.opaque_vars.clear()
    ternary = _encode(enc, "device.profile.managed ? isMemberOfGroup('00g_admins') : false")
    assert _equivalent(ternary, z3.And(u.managed, m))
    elvis = _encode(enc, "isMemberOfGroup('00g_admins') ?: true")
    assert _equivalent(elvis, m)
    attr_elvis = _encode(enc, "user.isContractor ?: true")
    is_null = u.attr_equals("user.isContractor", None)
    assert _equivalent(attr_elvis, z3.If(is_null, z3.BoolVal(True), u.attr_equals("user.isContractor", True)))
    assert not u.opaque_vars


# --------------------------------------------------------------------------------------------- opaque fallback


@pytest.mark.parametrize(
    "text",
    [
        "session.amr.contains('mfa')",
        "user.created.withinDays(1)",
        "device.provider.oktaVerify.version.versionGreaterThan('9.43')",
        "String.substringAfter(user.email, '@') == 'corp.com'",
        "user.level >= 5",
        "user.getLinkedObject('manager').lastName == 'Smith'",
        "Convert.toInt('2018') == user.yearJoined",
        "user.a == user.b",
    ],
)
def test_unknown_constructs_become_opaque_named_after_source(acme: Tenant, text: str) -> None:
    u, enc = _enc(acme)
    e = parse(text)
    f = _encode(enc, text)
    assert list(u.opaque_vars) == [e.source()]
    assert f is u.opaque_vars[e.source()]
    assert str(f) == f"opaque:{e.source()}"


def test_opaque_fragments_are_shared_and_nested(acme: Tenant) -> None:
    u, enc = _enc(acme)
    f = _encode(
        enc, "session.amr.contains('mfa') && !session.amr.contains('mfa') || user.department == 'Sales'"
    )
    assert list(u.opaque_vars) == ['session.amr.contains("mfa")']
    assert _equivalent(f, u.attr_equals("user.department", "Sales"))
    # a Boolean-typed opaque compared with true reuses the fragment's own variable
    g = _encode(enc, "session.amr.contains('mfa') == true")
    assert g is u.opaque_vars['session.amr.contains("mfa")']


# --------------------------------------------------------------------------------------------- agreement with the interpreter

EXPRESSIONS = [
    "user.isMemberOf({'group.type': {'OKTA_GROUP'}}, {'group.profile.name': 'S'})",
    "user.isMemberOf({'group.profile.name': 'Sales', 'operator': 'EXACT'}) && !user.isMemberOf({'group.id': '00g_contractors'})",
    "user.isMemberOf({'group.profile.name': 'Nope'})",
    "user.isMemberOf({'group.source.id': 'x'})",
    "Arrays.isEmpty(user.getGroups({'group.type': 'OKTA_GROUP'}))",
    "user.getGroups({'group.type': 'OKTA_GROUP'}).size() >= 2",
    "user.getGroups({'group.id': {'00g_eng', '00g_sales'}}).size() == 1",
    "user.getGroups({'group.type': 'OKTA_GROUP'}).![profile.name].contains('Finance')",
    "security.risk.level == 'HIGH' || device.profile.managed",
    "device.profile.platform == 'MACOS' && device.profile.registered == true",
    "device.profile.platform == 'MOBILE_OTHER'",
    "user.getInternalProperty('status') == 'ACTIVE'",
    "user.status != 'ACTIVE'",
    "user.profile.department.toLowerCase().contains('sales')",
    "user.profile.department.toLowerCase() == 'engineering'",
    "user.department == 'Engineering' && user.countryCode == 'US'",
    "user.department matches 'Eng.*'",
    "user.email.endsWith('@acme.com') ? true : isMemberOfGroup('00g_admins')",
    "user.isContractor ?: false",
    "isMemberOfGroup('00g_admins') ?: true",
    "!user.isContractor",
    "isMemberOfGroupNameStartsWith('Okta') == true",
    "session.amr.contains('mfa') && user.department == 'Engineering'",
    "String.substringAfter(user.email, '@') == 'acme.com'",
    "user.tags.isEmpty() || Arrays.contains(user.tags, 'vip')",
    "user.employeeNumber == null",
    "user.department == 'Sales' && String.stringContains(request.userAgent, 'Mobile')",
]


def _pin_world(u: Universe, w: World, axioms: list[z3.BoolRef]) -> z3.ModelRef:
    """A model of the axioms that agrees with a hand-built World on every variable the World determines."""
    s = z3.Solver()
    s.add(*axioms)
    for gid, var in u.member.items():
        if gid != u.everyone:
            s.add(var == z3.BoolVal(gid in w.groups))
    s.add(u.risk == RISKS.index(w.risk))
    s.add(u.managed == z3.BoolVal(w.managed))
    s.add(u.registered == z3.BoolVal(w.registered))
    s.add(u.platform == PLATFORMS.index(w.platform))
    for path, var in u.attr_vars.items():
        lits = u.attr_literals[path]
        value = w.attrs.get(path)
        key = NULL if value is None else value
        s.add(var == (lits.index(key) if key in lits else len(lits)))
    for text, var in u.opaque_vars.items():
        s.add(var == z3.BoolVal(w.opaque.get(text, False)))
    for name, var in u.pred_vars.items():
        _function, path, _literal = u.pred_meta[name]
        if path in w.attrs and w.attrs[path] != "<other>":
            s.add(var == z3.BoolVal(bool(u._pred_truth[name](w.attrs[path]))))
        else:
            s.add(var == z3.BoolVal(w.predicates.get(name, False)))
    assert s.check() == z3.sat, w
    return s.model()


WORLDS = [
    World(
        groups={fx.G_EVERYONE, fx.G_SALES, fx.G_US},
        attrs={
            "user.department": "Enterprise Sales",
            "user.countryCode": "US",
            "user.status": "ACTIVE",
            "user.email": "carol@acme.com",
            "user.tags": ["vip"],
        },
        risk=RiskLevel.HIGH,
        managed=True,
        registered=True,
        platform=DevicePlatform.MACOS,
        opaque={'session.amr.contains("mfa")': True},
    ),
    World(
        # countryCode US and not a contractor: ACME's group rule puts this user in US Employees
        groups={fx.G_EVERYONE, fx.G_ENG, fx.G_SVC, fx.G_ADMINS, fx.G_US},
        attrs={
            "user.department": "Engineering",
            "user.countryCode": "US",
            "user.status": "ACTIVE",
            "user.isContractor": True,
            "user.employeeNumber": None,
        },
        platform=DevicePlatform.IOS,
        predicates={"pred:isEmpty(user.tags,None)": True},
    ),
    World(
        groups={fx.G_EVERYONE, fx.G_CONTRACTORS, fx.G_SALES},
        attrs={
            "user.department": "Sales",
            "user.status": "SUSPENDED",
            "user.isContractor": False,
            "user.email": "x@other.example",
        },
        risk=RiskLevel.MEDIUM,
        registered=True,
        opaque={
            '(device.profile.platform == "MOBILE_OTHER")': True,
            '(String.substringAfter(user.email, "@") == "acme.com")': True,
        },
    ),
    World(groups={fx.G_EVERYONE}, attrs={}),
]


def test_interpreter_agrees_on_hand_built_worlds(acme: Tenant) -> None:
    u, enc = _enc(acme)
    encoded = [(parse(t), _encode(enc, t)) for t in EXPRESSIONS]
    axioms = u.axioms()
    it = Interpreter(acme)
    for w in WORLDS:
        m = _pin_world(u, w, axioms)
        for ast, f in encoded:
            got = z3.is_true(m.eval(f, model_completion=True))
            expected = it.eval_bool(ast, w)
            assert got == expected, f"{ast.source()}: encoder={got} interpreter={expected} world={w}"


def test_interpreter_agrees_on_sampled_worlds(acme: Tenant) -> None:
    u, enc = _enc(acme)
    encoded = [(parse(t), _encode(enc, t)) for t in EXPRESSIONS]
    axioms = u.axioms()
    it = Interpreter(acme)
    for m in sample_models(u, axioms, 120, seed=7):
        w = world_from_model(u, m)
        for ast, f in encoded:
            got = z3.is_true(m.eval(f, model_completion=True))
            expected = it.eval_bool(ast, w)
            assert got == expected, f"{ast.source()}: encoder={got} interpreter={expected} world={w}"
