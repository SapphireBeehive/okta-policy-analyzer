from __future__ import annotations

import pytest

from okta_policy_analyzer.el import Attr, BinOp, Call, ELSyntaxError, Literal, Unknown, evaluate, parse
from okta_policy_analyzer.el.evaluator import Env


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
    ],
)
def test_parse_roundtrip(text: str) -> None:
    e = parse(text)
    # source() must re-parse to a structurally identical AST
    assert parse(e.source()) == e


@pytest.mark.parametrize("bad", ["", "user.department ==", 'user["x"]', "&& a", "(a", '"unterminated'])
def test_parse_errors(bad: str) -> None:
    with pytest.raises(ELSyntaxError):
        parse(bad)


def test_precedence() -> None:
    # && binds tighter than ||, ! tighter than both, == tighter than &&
    e = parse("a == 1 || b == 2 && !c")
    assert e.op == "||"  # type: ignore[attr-defined]
    assert e.right.op == "&&"  # type: ignore[attr-defined]


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
    )
    assert evaluate(parse(text), env) == expected


def test_unknown_function_raises_unknown() -> None:
    with pytest.raises(Unknown):
        evaluate(parse("Time.now() == 1"), _env())
    with pytest.raises(Unknown):
        evaluate(parse("device.managed == true"), _env())
