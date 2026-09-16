from __future__ import annotations

import pytest

from okta_policy_analyzer.el import (
    ArrayLit,
    Attr,
    BinOp,
    Call,
    ELSyntaxError,
    Elvis,
    Env,
    GroupCriterion,
    Index,
    Literal,
    MapLit,
    MethodCall,
    Projection,
    Property,
    UnaryOp,
    Unknown,
    evaluate,
    parse,
)
from okta_policy_analyzer.el.evaluator import (
    bool_typed,
    context_equality,
    count_comparison,
    group_criteria,
    membership_atom,
    predicate_atom,
    string_term,
)

# --------------------------------------------------------------------------------------------- parsing


def test_parse_shapes() -> None:
    e = parse('user.department == "Engineering" && !isMemberOfGroup("00g1")')
    assert isinstance(e, BinOp) and e.op == "&&"
    assert e.left == BinOp("==", Attr(("user", "department")), Literal("Engineering"))
    assert isinstance(e.right.operand, Call)  # type: ignore[attr-defined]
    assert e.right.operand.name == "isMemberOfGroup"  # type: ignore[attr-defined]


def test_profile_prefix_is_normalized() -> None:
    assert Attr(("user", "profile", "title")).normalized == "user.title"
    assert Attr(("user", "title")).normalized == "user.title"
    assert Attr(("device", "managed")).normalized == "device.managed"


def test_method_call_and_static_call_shapes() -> None:
    e = parse("user.profile.email.toLowerCase()")
    assert e == MethodCall(Attr(("user", "profile", "email")), "toLowerCase", ())
    lower = parse('String.toLowerCase(user.email) == "x"')
    assert isinstance(lower, BinOp) and lower.left == Call("String.toLowerCase", (Attr(("user", "email")),))
    im = parse("user.isMemberOf({'group.id': {'a', 'b'}}, {'group.type': 'APP_GROUP'})")
    assert isinstance(im, MethodCall) and im.target == Attr(("user",)) and im.name == "isMemberOf"
    assert im.args[0] == MapLit((("group.id", ArrayLit((Literal("a"), Literal("b")))),))
    assert im.args[1] == MapLit((("group.type", Literal("APP_GROUP")),))
    assert parse("'x'.contains(user.y)") == MethodCall(Literal("x"), "contains", (Attr(("user", "y")),))
    assert parse("String.stringContains(user.a, 'b').toString()").target.name == "String.stringContains"  # type: ignore[attr-defined]


def test_postfix_shapes() -> None:
    proj = parse("user.getGroups({'group.profile.name': 'Everyone'}).![profile.name]")
    assert isinstance(proj, Projection) and proj.body == Attr(("profile", "name"))
    assert isinstance(proj.target, MethodCall) and proj.target.name == "getGroups"
    assert parse("user.arr[0]") == Index(Attr(("user", "arr")), Literal(0))
    assert parse('user.getLinkedObject("manager").lastName') == Property(
        MethodCall(Attr(("user",)), "getLinkedObject", (Literal("manager"),)), "lastName"
    )
    # property access on a parenthesised identifier chain folds back into one Attr
    assert parse("(user.profile).email") == Attr(("user", "profile", "email"))


def test_collections() -> None:
    assert parse("{}") == ArrayLit(())
    assert parse("{:}") == MapLit(())
    assert parse("{1, 2}") == ArrayLit((Literal(1), Literal(2)))
    assert parse("{operator: 'EXACT'}") == MapLit((("operator", Literal("EXACT")),))
    assert parse('{"a": {"b": 1}}') == MapLit((("a", MapLit((("b", Literal(1)),))),))
    assert parse("{'a', 'b'}") == parse('{"a", "b"}')


def test_operators_and_keywords() -> None:
    e = parse("user.a eq 'b' AND user.n GE 3 or not user.c NE 1")
    assert e == BinOp(
        "||",
        BinOp(
            "&&", BinOp("==", Attr(("user", "a")), Literal("b")), BinOp(">=", Attr(("user", "n")), Literal(3))
        ),
        BinOp("!=", UnaryOp("!", Attr(("user", "c"))), Literal(1)),
    )
    m = parse('user.department matches "California-[a-zA-Z]+-Sales"')
    assert m == BinOp("matches", Attr(("user", "department")), Literal("California-[a-zA-Z]+-Sales"))
    assert parse("user.x MATCHES 'a'").op == "matches"  # type: ignore[attr-defined]
    assert parse("user.x ?: 'd'") == Elvis(Attr(("user", "x")), Literal("d"))
    assert parse("+user.n") == UnaryOp("+", Attr(("user", "n")))
    assert parse("TRUE") == Literal(True) and parse("Null") == Literal(None)


def test_string_escapes() -> None:
    assert parse("'it''s'") == Literal("it's")
    assert parse('"say ""hi"""') == Literal('say "hi"')
    assert parse('"a\\"b"') == Literal('a"b')
    # backslashes that do not escape a quote are kept, so regexes survive verbatim
    assert parse("'.*@example\\.com'") == Literal(".*@example\\.com")
    assert parse("'\\d+'") == Literal("\\d+")


DOC_EXAMPLES = [
    # 3.6 criteria functions (verbatim from the Okta docs)
    "user.isMemberOf({'group.id': {'00gjitX9HqABSoqTB0g3', '00garwpuyxHaWOkdV0g4'}}, {'group.type': 'APP_GROUP'})",
    "user.isMemberOf({'group.profile.name': 'West Coast', 'operator': 'STARTS_WITH' })",
    "user.isMemberOf({'group.profile.name': 'West Coast', 'operator': 'EXACT' })",
    "user.isMemberOf({'group.source.id': '0aae4be2456eb62f7c3d'} , {'group.profile.name': {'Engineering Users'}} )",
    'user.isMemberOf({"group.type": {"OKTA_GROUP"}}, {"group.profile.name": "Sales", "operator": "STARTS_WITH"})',
    "user.getGroups({'group.profile.name': 'Everyone'}).![profile.name]",
    # 3.7 group-rule samples
    'String.stringContains(user.department, "Sales")',
    'user.city == "San Francisco"',
    "user.salary >= 1000000",
    "!user.isContractor",
    "user.salary > 1000000 AND !user.isContractor",
    'user.department matches "California-[a-zA-Z]+-Sales"',
    "user.title matches '(?i)engineer'",
    "user.employeeNumber == null",
    'user.employeeNumber == ""',
    "user.hasBadge",
    'String.stringContains(user.email, "@example.com")',
    'Arrays.contains(user.favoriteColors, "blue")',
    'user.getInternalProperty("status") == "ACTIVE"',
    'Convert.toInt("2018") == user.yearJoined',
    'isMemberOfGroupNameRegex("/.*admin.*")',
    # Identity Engine samples
    "security.risk.level == 'HIGH'",
    "user.profile.department.toLowerCase().contains('sales') && !user.isMemberOf({'group.profile.name': 'Domain', 'operator': 'STARTS_WITH'})",
    "device.provider.oktaVerify.version.versionGreaterThan('9.43') == true",
    "device.profile.osVersion.versionGreaterThan('14.2.1')",
    "security.behaviors.contains('New IP')",
    "session.amr.contains('mfa')",
    "user.created.withinDays(1)",
    "user.getLinkedObject(\"manager\").lastName == 'Smith'",
    "'This is a test'.contains('Test')",
    "user.profile.email.substring(0, 5)",
    "user.profile.isContractor ?: false",
    "device.profile.managed == true && device.profile.platform == 'MACOS'",
    "login.identifier matches '.*@corp\\.example'",
    "accessRequest.operation == 'enroll'",
]


@pytest.mark.parametrize("text", DOC_EXAMPLES)
def test_doc_examples_parse_and_roundtrip(text: str) -> None:
    e = parse(text)
    assert parse(e.source()) == e


@pytest.mark.parametrize(
    "text",
    [
        'user.department == "Eng"',
        "user.title != 'CEO' || user.level >= 5",
        'isMemberOfAnyGroup({"a", "b"}) AND NOT String.startsWith(user.email, "svc-")',
        'String.stringContains(user.title, "Manager") ? true : false',
        "(user.a == 1) OR (user.b == 2)",
        'user.countryCode == "US" && user.employeeNumber > 1000',
        'Arrays.contains(user.arrayAttr, "x")',
        "-(user.n).toString()",
        "(!user.a).toString() == 'true'",
        "{'k': {1, 2}, 'operator': 'EXACT'}['k'][0]",
        "(user.a ? 'x' : 'y').length() gt 0",
        "(user.a ?: user.b).toLowerCase()",
        "user.getGroups({:}).![id].size() > 0",
        "{}.isEmpty()",
        "String.substringAfter(user.email, '@') == 'corp.com'",
    ],
)
def test_parse_roundtrip(text: str) -> None:
    e = parse(text)
    # source() must re-parse to a structurally identical AST
    assert parse(e.source()) == e


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "user.department ==",
        "user.[0]",
        "&& a",
        "(a",
        '"unterminated',
        "user.x ?",
        "{'a': }",
        "a ? b",
        "1..2",
    ],
)
def test_parse_errors(bad: str) -> None:
    with pytest.raises(ELSyntaxError):
        parse(bad)


def test_precedence() -> None:
    # && binds tighter than ||, ! tighter than both, == tighter than &&
    e = parse("a == 1 || b == 2 && !c")
    assert e.op == "||"  # type: ignore[attr-defined]
    assert e.right.op == "&&"  # type: ignore[attr-defined]
    # postfix binds tighter than unary; relational tighter than logical; Elvis/ternary loosest
    assert parse("!user.a.isEmpty()") == UnaryOp("!", MethodCall(Attr(("user", "a")), "isEmpty", ()))
    t = parse("user.a == 1 ? user.b ?: false : true")
    assert t.then == Elvis(Attr(("user", "b")), Literal(False))  # type: ignore[attr-defined]


# --------------------------------------------------------------------------------------------- evaluation


def _env(**attrs):
    return Env(
        attrs={f"user.{k}": v for k, v in attrs.items()},
        group_ids=frozenset({"00gEng", "00gAll"}),
        group_names=frozenset({"Engineering", "Everyone"}),
    )


@pytest.mark.parametrize(
    "text,expected",
    [
        ('user.department == "Eng"', True),
        ('user.department == "eng"', False),
        ('user.department != "Eng"', False),
        ("user.missing == null", True),
        ('user.missing == "x"', False),
        ('String.stringContains(user.title, "Manager")', True),
        ('String.startsWith(user.email, "svc-")', False),
        ('String.toLowerCase(user.department) == "eng"', True),
        ('isMemberOfGroup("00gEng")', True),
        ('isMemberOfGroup("00gNope")', False),
        ('isMemberOfAnyGroup({"00gNope", "00gAll"})', True),
        ('isMemberOfAllGroups({"00gEng", "00gAll"})', True),
        ('isMemberOfAllGroups({"00gEng", "00gNope"})', False),
        ('isMemberOfGroupName("Engineering")', True),
        ('isMemberOfGroupNameStartsWith("Eng")', True),
        ('isMemberOfGroupNameContains("very")', True),
        ('isMemberOfGroupNameRegex("^E.*g$")', True),
        ("user.level >= 5 && user.level < 10", True),
        ("user.contractor == true", False),
        ('user.contractor == "false"', True),
        ("!user.contractor", True),
        ('user.level > 3 ? "senior" : "junior"', "senior"),
        ('Arrays.contains(user.tags, "vip")', True),
        ("Arrays.size(user.tags)", 2),
        ("Arrays.isEmpty(user.nothing)", True),
        ('String.substringBefore(user.email, "@")', "alice"),
        ('String.substringAfter(user.email, "@")', "example.com"),
        ("user.level + 1", 6),
        ('String.stringSwitch(user.department, "other", "Eng", "R&D", "Sales", "GTM")', "R&D"),
        ("Convert.toInt(user.employeeNumber) > 100", True),
        # Identity Engine method style
        ("user.profile.email.toUpperCase()", "ALICE@EXAMPLE.COM"),
        ("user.profile.title.toLowerCase().contains('manager')", True),
        ("user.email.startsWith('alice') && user.email.endsWith('.com')", True),
        ("'This is a test'.contains('Test')", False),
        ("user.email.length()", 17),
        ("user.email.substring(0, 5)", "alice"),
        ("user.email.substring(6)", "example.com"),
        ("user.email.replace('example', 'acme')", "alice@acme.com"),
        ("user.title.removeSpaces()", "EngineeringManager"),
        ("user.email.substringBefore('@') + '@' + user.email.substringAfter('@')", "alice@example.com"),
        ("user.employeeNumber.toInteger() + 1", 1235),
        ("user.employeeNumber.toNumber()", 1234.0),
        ("user.missing.isEmpty()", True),
        ("user.tags.isEmpty()", False),
        ("user.tags.size()", 2),
        ("user.tags.contains('vip')", True),
        ("user.tags[1]", "oncall"),
        ("user.tags.add('x').size()", 3),
        # Elvis, matches, textual operators, maps, unary plus
        ("user.missing ?: 'fallback'", "fallback"),
        ("user.department ?: 'fallback'", "Eng"),
        ("'' ?: 'fallback'", "fallback"),
        ("user.title matches '.*Manager'", True),
        ("user.title matches 'Manager'", False),
        ("user.title matches '(?i)engineering manager'", True),
        ("user.missing matches '.*'", False),
        ("user.level eq 5 and user.level ne 6 and user.level lt 6 and user.level le 5", True),
        ("user.level gt 5 or user.level ge 6", False),
        ("{'a': 1, 'b': {2, 3}}['b'][1]", 3),
        ("{'a': 1}", {"a": 1}),
        ("+user.level", 5),
        ("user.getInternalProperty('status') == 'ACTIVE'", True),
        ("user.getInternalProperty(\"status\") != 'ACTIVE'", False),
        ("'a''b'.length()", 3),
    ],
)
def test_evaluate(text: str, expected) -> None:
    env = _env(
        department="Eng",
        title="Engineering Manager",
        email="alice@example.com",
        level=5,
        contractor=False,
        tags=["vip", "oncall"],
        employeeNumber="1234",
        status="ACTIVE",
    )
    assert evaluate(parse(text), env) == expected


def _group_env(**attrs):
    return Env(
        attrs={f"user.{k}": v for k, v in attrs.items()},
        groups=[
            ("00gEVERYONE", "Everyone", "BUILT_IN"),
            ("00gSALES", "Sales", "OKTA_GROUP"),
            ("00gWEST", "West Coast Users", "OKTA_GROUP"),
            ("00gADMINS", "Domain Admins", "APP_GROUP"),
        ],
    )


def test_env_groups_derive_ids_and_names() -> None:
    env = _group_env()
    assert "00gSALES" in env.group_ids and "Domain Admins" in env.group_names
    assert evaluate(parse('isMemberOfGroup("00gSALES") && isMemberOfGroupName("Sales")'), env) is True


@pytest.mark.parametrize(
    "text,expected",
    [
        (
            "user.isMemberOf({'group.id': {'00gjitX9HqABSoqTB0g3', '00gADMINS'}}, {'group.type': 'APP_GROUP'})",
            True,
        ),
        ("user.isMemberOf({'group.id': {'00gSALES'}}, {'group.type': 'APP_GROUP'})", False),
        ("user.isMemberOf({'group.profile.name': 'West Coast', 'operator': 'STARTS_WITH' })", True),
        ("user.isMemberOf({'group.profile.name': 'West Coast', 'operator': 'EXACT' })", False),
        ("user.isMemberOf({'group.profile.name': 'West Coast Users', 'operator': 'EXACT' })", True),
        ("user.isMemberOf({'group.profile.name': 'West'})", True),  # default operator is STARTS_WITH
        ("user.isMemberOf({'group.profile.name': 'west'})", False),  # case-sensitive
        (
            'user.isMemberOf({"group.type": {"OKTA_GROUP"}}, {"group.profile.name": "Sales", "operator": "STARTS_WITH"})',
            True,
        ),
        ("user.isMemberOf({'group.type': 'OKTA_GROUP', 'group.profile.name': 'Domain'})", False),
        ("user.isMemberOf({'group.type': {'APP_GROUP', 'BUILT_IN'}})", True),
        ("user.isMemberOf({'group.id': {}})", False),
        ("user.getGroups({'group.profile.name': 'Everyone'}).![profile.name]", ["Everyone"]),
        ("user.getGroups({'group.type': 'OKTA_GROUP'}).![id]", ["00gSALES", "00gWEST"]),
        ("user.getGroups({'group.type': 'OKTA_GROUP'}).size()", 2),
        ("Arrays.size(user.getGroups({'group.type': 'OKTA_GROUP'})) > 1", True),
        ("Arrays.isEmpty(user.getGroups({'group.profile.name': 'Nope'}))", True),
        ("user.getGroups({'group.profile.name': 'Nope'}).isEmpty()", True),
        ("user.getGroups({'group.type': 'APP_GROUP'}).![profile.name].contains('Domain Admins')", True),
        ("user.getGroups({'group.type': 'APP_GROUP'})[0].profile.name", "Domain Admins"),
        ("!user.isMemberOf({'group.profile.name': 'Domain', 'operator': 'STARTS_WITH'})", False),
    ],
)
def test_evaluate_group_criteria(text: str, expected) -> None:
    assert evaluate(parse(text), _group_env()) == expected


def test_group_criteria_unknowns() -> None:
    with pytest.raises(Unknown):  # source ids are not in the snapshot
        evaluate(parse("user.isMemberOf({'group.source.id': '0aae4be2456eb62f7c3d'})"), _group_env())
    with pytest.raises(Unknown):  # operator only applies to group.profile.name
        evaluate(parse("user.isMemberOf({'group.type': 'APP_GROUP', 'operator': 'EXACT'})"), _group_env())
    with pytest.raises(Unknown):  # unknown operator
        evaluate(parse("user.isMemberOf({'group.profile.name': 'S', 'operator': 'CONTAINS'})"), _group_env())
    with pytest.raises(Unknown):  # no criteria
        evaluate(parse("user.isMemberOf()"), _group_env())
    with pytest.raises(Unknown):  # empty criteria map
        evaluate(parse("user.isMemberOf({:})"), _group_env())
    with pytest.raises(Unknown):  # env without group triples
        evaluate(parse("user.isMemberOf({'group.id': 'x'})"), _env())


def test_unknown_function_raises_unknown() -> None:
    with pytest.raises(Unknown):
        evaluate(parse("Time.now() == 1"), _env())
    with pytest.raises(Unknown):
        evaluate(parse("device.managed == true"), _env())
    with pytest.raises(Unknown):
        evaluate(parse("user.created.withinDays(1)"), _env())
    with pytest.raises(Unknown):
        evaluate(parse("user.getLinkedObject('manager').lastName"), _env())


# --------------------------------------------------------------------------------------------- recognisers


def test_string_term_recogniser() -> None:
    t = string_term(parse("user.profile.department.toLowerCase()"))
    assert t is not None and t.path == "user.department" and t.transforms == ("String.toLowerCase",)
    assert t.apply("Enterprise Sales") == "enterprise sales" and t.apply(None) is None
    assert t.function("String.stringContains") == "String.stringContains∘String.toLowerCase"
    assert string_term(parse("String.toLowerCase(user.department)")) == t
    assert string_term(parse("toLowerCase(user.department)")) == t
    st = string_term(parse('user.getInternalProperty("status")'))
    assert st is not None and st.path == "user.status" and st.transforms == ()
    assert string_term(parse("device.profile.platform")) is None
    assert string_term(parse("'lit'.toLowerCase()")) is None
    assert string_term(parse("user.x.substring(1)")) is None


def test_predicate_atom_recogniser() -> None:
    pa = predicate_atom(parse("user.profile.email.contains('@corp')"))
    assert pa is not None and (pa.function, pa.path, pa.literal) == (
        "String.stringContains",
        "user.email",
        "@corp",
    )
    assert pa.truth("a@corp") and not pa.truth("a@other") and not pa.truth(None)
    same = predicate_atom(parse("String.stringContains(user.email, '@corp')"))
    assert same is not None and (same.function, same.path, same.literal) == (pa.function, pa.path, pa.literal)
    rx = predicate_atom(parse("user.title matches '(?i)engineer'"))
    assert rx is not None and rx.function == "matches" and rx.truth("Engineer") and not rx.truth("Engineers")
    assert predicate_atom(parse("user.title matches '('")) is None  # uncompilable regex stays opaque
    assert predicate_atom(parse("login.identifier matches '.*'")) is None
    empty = predicate_atom(parse("user.profile.tags.isEmpty()"))
    assert (
        empty is not None
        and empty.truth(None)
        and empty.truth([])
        and empty.truth("")
        and not empty.truth(["a"])
    )


def test_membership_recognisers() -> None:
    c = group_criteria(
        parse("user.isMemberOf({'group.type': {'OKTA_GROUP'}}, {'group.profile.name': 'Sales'})").args
    )  # type: ignore[attr-defined]
    assert c == (
        GroupCriterion("group.type", ("OKTA_GROUP",), "EXACT"),
        GroupCriterion("group.profile.name", ("Sales",), "STARTS_WITH"),
    )
    assert membership_atom(parse("user.isMemberOf({'group.source.id': 'x'})")) is None
    ma = membership_atom(parse("Arrays.isEmpty(user.getGroups({'group.id': 'g'}))"))
    assert ma == ((GroupCriterion("group.id", ("g",), "EXACT"),), True)
    assert membership_atom(parse("user.getGroups({'group.id': 'g'}).isEmpty()")) == ma
    proj = membership_atom(
        parse("user.getGroups({'group.type': 'APP_GROUP'}).![profile.name].contains('Domain Admins')")
    )
    assert proj == (
        (
            GroupCriterion("group.type", ("APP_GROUP",)),
            GroupCriterion("group.profile.name", ("Domain Admins",)),
        ),
        False,
    )
    assert count_comparison(parse("Arrays.size(user.getGroups({'group.id': 'g'})) > 0")) == (
        (GroupCriterion("group.id", ("g",)),),
        ">",
        0,
    )
    assert count_comparison(parse("2 <= user.getGroups({'group.id': 'g'}).size()")) == (
        (GroupCriterion("group.id", ("g",)),),
        ">=",
        2,
    )
    assert count_comparison(parse("user.getGroups({'group.id': 'g'}).size() > user.n")) is None


def test_context_and_bool_typing() -> None:
    assert context_equality(Attr(("security", "risk", "level")), "HIGH") == ("risk", "HIGH")
    assert context_equality(Attr(("device", "profile", "platform")), "OSX") == ("platform", "MACOS")
    assert context_equality(Attr(("device", "profile", "platform")), "MOBILE_OTHER") is None
    assert context_equality(Attr(("device", "profile", "managed")), True) == ("managed", True)
    assert context_equality(Attr(("device", "profile", "managed")), "true") is None
    assert (
        bool_typed(parse("user.x.contains('a')"))
        and bool_typed(parse("!user.x"))
        and bool_typed(parse("a == b"))
    )
    assert not bool_typed(parse("user.x")) and not bool_typed(parse("user.x.toLowerCase()"))
