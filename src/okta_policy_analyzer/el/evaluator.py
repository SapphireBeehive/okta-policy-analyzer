"""Concrete evaluator for Okta EL, plus the atom recognisers shared by the SMT encoder and the interpreter.

Evaluation happens against an :class:`Env` that provides:

* ``attrs``: mapping of normalized attribute path (``user.department``, ``user.status``) to a Python value,
* ``group_ids`` / ``group_names``: the groups the user belongs to (classic ``isMemberOfGroup*`` functions),
* ``groups``: optional ``(id, name, type)`` triples of the user's groups, needed by the Identity Engine
  ``user.isMemberOf(...)`` / ``user.getGroups(...)`` criteria functions.

Anything the evaluator cannot interpret raises :class:`Unknown`; callers treat the sub-expression as an opaque
predicate (the formal model does the same, so the two stay aligned).

The second half of the module holds the *recognisers* — pure functions that classify an AST fragment as a
membership atom, a string predicate over a profile attribute, a context atom, ... Both ``smt.el_encoder`` and
``interpreter`` build their semantics from these, which is what keeps them in agreement construct by construct.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .ast import (
    ArrayLit,
    Attr,
    BinOp,
    Call,
    Elvis,
    Expr,
    Index,
    Literal,
    MapLit,
    MethodCall,
    Projection,
    Property,
    Ternary,
    UnaryOp,
)


class EvalError(ValueError):
    pass


class Unknown(EvalError):
    """The expression uses a construct the evaluator does not interpret."""


_USER = Attr(("user",))


@dataclass
class Env:
    attrs: Mapping[str, Any] = field(default_factory=dict)
    group_ids: frozenset[str] = frozenset()
    group_names: frozenset[str] = frozenset()
    #: the user's groups as ``(id, name, type)``; enables ``user.isMemberOf`` / ``user.getGroups``
    groups: Sequence[tuple[str, str, str]] | None = None

    def __post_init__(self) -> None:
        if self.groups:
            self.group_ids = frozenset(self.group_ids) | {g[0] for g in self.groups}
            self.group_names = frozenset(self.group_names) | {g[1] for g in self.groups}

    def attr(self, path: str) -> Any:
        if path in self.attrs:
            return self.attrs[path]
        # unknown attributes evaluate to null (Okta treats missing profile attributes as null)
        if path.startswith("user."):
            return None
        raise Unknown(f"unknown reference {path}")


def evaluate(expr: Expr, env: Env) -> Any:  # noqa: C901 - dispatch
    """Evaluate ``expr`` in ``env``. Returns a Python value (bool/str/number/list/dict/None)."""
    if isinstance(expr, Literal):
        return expr.value
    if isinstance(expr, Attr):
        return env.attr(expr.normalized)
    if isinstance(expr, ArrayLit):
        return [evaluate(i, env) for i in expr.items]
    if isinstance(expr, MapLit):
        return {k: evaluate(v, env) for k, v in expr.entries}
    if isinstance(expr, UnaryOp):
        v = evaluate(expr.operand, env)
        if expr.op == "!":
            return not _truthy(v)
        if expr.op == "-":
            return -_num(v)
        if expr.op == "+":
            return +_num(v)
        raise Unknown(f"unary {expr.op}")
    if isinstance(expr, Ternary):
        return evaluate(expr.then, env) if _truthy(evaluate(expr.cond, env)) else evaluate(expr.other, env)
    if isinstance(expr, Elvis):
        v = evaluate(expr.left, env)
        return v if v is not None and v != "" else evaluate(expr.right, env)
    if isinstance(expr, BinOp):
        return _binop(expr, env)
    if isinstance(expr, Call):
        return _call(expr, env)
    if isinstance(expr, MethodCall):
        return _method(expr, env)
    if isinstance(expr, Property):
        recv = evaluate(expr.target, env)
        if isinstance(recv, dict):
            return recv.get(expr.name)
        raise Unknown(f"property {expr.name} on {type(recv).__name__}")
    if isinstance(expr, Index):
        return _index(evaluate(expr.target, env), evaluate(expr.index, env))
    if isinstance(expr, Projection):
        recv = evaluate(expr.target, env)
        return [_project(item, expr.body) for item in _as_list(recv)]
    raise Unknown(f"unsupported node {type(expr).__name__}")


def _truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    if isinstance(v, str):
        return v.lower() == "true"
    raise EvalError(f"non-boolean value {v!r} used as a condition")


def _num(v: Any) -> float | int:
    if isinstance(v, bool) or not isinstance(v, int | float):
        raise EvalError(f"expected a number, got {v!r}")
    return v


def _binop(expr: BinOp, env: Env) -> Any:
    op = expr.op
    if op == "&&":
        return _truthy(evaluate(expr.left, env)) and _truthy(evaluate(expr.right, env))
    if op == "||":
        return _truthy(evaluate(expr.left, env)) or _truthy(evaluate(expr.right, env))
    lv = evaluate(expr.left, env)
    rv = evaluate(expr.right, env)
    if op == "==":
        return _eq(lv, rv)
    if op == "!=":
        return not _eq(lv, rv)
    if op in ("<", "<=", ">", ">="):
        a, b = _num(lv), _num(rv)
        return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
    if op == "matches":
        return regex_matches(_compile(rv), lv)
    if op == "+":
        if isinstance(lv, str) or isinstance(rv, str):
            return f"{'' if lv is None else lv}{'' if rv is None else rv}"
        return _num(lv) + _num(rv)
    if op == "-":
        return _num(lv) - _num(rv)
    if op == "*":
        return _num(lv) * _num(rv)
    if op == "/":
        return _num(lv) / _num(rv)
    if op == "%":
        return _num(lv) % _num(rv)
    raise Unknown(f"operator {op}")


def _compile(pattern: Any) -> re.Pattern[str]:
    try:
        return re.compile(_s(pattern))
    except re.error as e:
        raise EvalError(f"bad regex {pattern!r}: {e}") from e


def regex_matches(rx: re.Pattern[str], value: Any) -> bool:
    """SpEL ``matches`` (Java ``Pattern.matches``): the whole string must match; ``null`` never matches."""
    return value is not None and rx.fullmatch(str(value)) is not None


def _eq(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        if isinstance(a, str):
            a = a.lower() == "true"
        if isinstance(b, str):
            b = b.lower() == "true"
        return a == b
    if isinstance(a, int | float) and isinstance(b, int | float):
        return a == b
    if isinstance(a, int | float) and isinstance(b, str) or isinstance(b, int | float) and isinstance(a, str):
        return str(a) == str(b)
    return a == b


def _s(v: Any) -> str:
    return "" if v is None else str(v)


def _index(recv: Any, idx: Any) -> Any:
    if isinstance(recv, dict):
        return recv.get(_s(idx))
    if isinstance(recv, list | tuple | str):
        try:
            return recv[int(_num(idx))]
        except IndexError as e:
            raise EvalError(f"index {idx!r} out of range") from e
    raise Unknown(f"indexing a {type(recv).__name__}")


def _project(item: Any, body: Expr) -> Any:
    """Evaluate a projection body relative to one collection element (group records are dicts)."""
    if isinstance(body, Attr):
        cur = item
        for part in body.path:
            if not isinstance(cur, dict):
                raise Unknown(f"projection {body.source()} over {type(item).__name__}")
            cur = cur.get(part)
        return cur
    raise Unknown(f"projection body {body.source()}")


def _call(expr: Call, env: Env) -> Any:
    fn = _FUNCTIONS.get(expr.name)
    if fn is None:
        raise Unknown(f"function {expr.name}")
    return fn(env, *[evaluate(a, env) for a in expr.args])


def _method(expr: MethodCall, env: Env) -> Any:
    name = expr.name
    if expr.target == _USER:
        argv = [evaluate(a, env) for a in expr.args]
        if name == "getInternalProperty" and len(argv) == 1:
            return env.attr(f"user.{_s(argv[0])}")
        if name in ("isMemberOf", "getGroups"):
            if env.groups is None:
                raise Unknown("user groups not available in this environment")
            criteria = criteria_from_values(argv)
            matching = [g for g in env.groups if group_satisfies(criteria, *g)]
            if name == "isMemberOf":
                return bool(matching)
            return [group_record(*g) for g in matching]
        raise Unknown(f"method user.{name}")
    recv = evaluate(expr.target, env)
    argv = [evaluate(a, env) for a in expr.args]
    if isinstance(recv, list | tuple):
        fn = _ARRAY_METHODS.get(name)
        if fn is None:
            raise Unknown(f"array method {name}")
        return fn(list(recv), *argv)
    if recv is None or isinstance(recv, str | int | float | bool):
        fn = _STRING_METHODS.get(name)
        if fn is None:
            raise Unknown(f"string method {name}")
        return fn(_s(recv), *argv)
    raise Unknown(f"method {name} on {type(recv).__name__}")


def group_record(gid: str, name: str, gtype: str) -> dict[str, Any]:
    """The value ``user.getGroups`` yields per group (enough for the documented projections)."""
    return {"id": gid, "type": gtype, "profile": {"name": name}}


# --- function library ------------------------------------------------------------------------------


def _f_string_contains(env: Env, s: Any, sub: Any) -> bool:
    return _s(sub) in _s(s)


def _f_starts_with(env: Env, s: Any, pre: Any) -> bool:
    return _s(s).startswith(_s(pre))


def _f_ends_with(env: Env, s: Any, suf: Any) -> bool:
    return _s(s).endswith(_s(suf))


def _f_lower(env: Env, s: Any) -> str:
    return _s(s).lower()


def _f_upper(env: Env, s: Any) -> str:
    return _s(s).upper()


def _f_len(env: Env, s: Any) -> int:
    return len(_s(s))


def _before(s: str, sep: str) -> str:
    return s.split(sep, 1)[0] if sep in s else ""


def _after(s: str, sep: str) -> str:
    return s.split(sep, 1)[1] if sep in s else ""


def _f_substring_before(env: Env, s: Any, sep: Any) -> str:
    return _before(_s(s), _s(sep))


def _f_substring_after(env: Env, s: Any, sep: Any) -> str:
    return _after(_s(s), _s(sep))


def _f_substring(env: Env, s: Any, start: Any, end: Any) -> str:
    return _s(s)[int(_num(start)) : int(_num(end))]


def _f_replace(env: Env, s: Any, a: Any, b: Any) -> str:
    return _s(s).replace(_s(a), _s(b))


def _f_replace_first(env: Env, s: Any, a: Any, b: Any) -> str:
    return _s(s).replace(_s(a), _s(b), 1)


def _f_remove_spaces(env: Env, s: Any) -> str:
    return _s(s).replace(" ", "")


def _f_append(env: Env, s: Any, suffix: Any) -> str:
    return _s(s) + _s(suffix)


def _f_join(env: Env, sep: Any, *parts: Any) -> str:
    return _s(sep).join(_s(p) for p in parts)


def _f_string_switch(env: Env, s: Any, default: Any, *pairs: Any) -> Any:
    it = iter(pairs)
    for k, v in zip(it, it, strict=False):
        if _s(s) == _s(k):
            return v
    return default


def _f_arrays_contains(env: Env, arr: Any, v: Any) -> bool:
    return v in _as_list(arr)


def _f_arrays_size(env: Env, arr: Any) -> int:
    return len(_as_list(arr))


def _f_arrays_is_empty(env: Env, arr: Any) -> bool:
    return len(_as_list(arr)) == 0


def _f_arrays_add(env: Env, arr: Any, v: Any) -> list[Any]:
    return [*_as_list(arr), v]


def _f_arrays_remove(env: Env, arr: Any, v: Any) -> list[Any]:
    return [x for x in _as_list(arr) if x != v]


def _f_arrays_flatten(env: Env, *items: Any) -> list[Any]:
    out: list[Any] = []
    for i in items:
        out.extend(_as_list(i))
    return out


def _f_arrays_to_csv(env: Env, arr: Any) -> str:
    return ",".join(_s(x) for x in _as_list(arr))


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    if isinstance(v, list | tuple | set | frozenset):
        return list(v)
    return [v]


def _f_is_member_of_group(env: Env, gid: Any) -> bool:
    return _s(gid) in env.group_ids


def _f_is_member_of_any_group(env: Env, gids: Any) -> bool:
    return any(_s(g) in env.group_ids for g in _as_list(gids))


def _f_is_member_of_group_name(env: Env, name: Any) -> bool:
    return _s(name) in env.group_names


def _f_is_member_of_group_name_starts_with(env: Env, pre: Any) -> bool:
    return any(n.startswith(_s(pre)) for n in env.group_names)


def _f_is_member_of_group_name_contains(env: Env, sub: Any) -> bool:
    return any(_s(sub) in n for n in env.group_names)


def _f_is_member_of_group_name_regex(env: Env, pattern: Any) -> bool:
    rx = _compile(pattern)
    return any(rx.search(n) for n in env.group_names)


def _f_is_member_of_all_groups(env: Env, gids: Any) -> bool:
    return all(_s(g) in env.group_ids for g in _as_list(gids))


def _f_convert_to_int(env: Env, s: Any) -> int:
    return int(_s(s))


def _f_convert_to_num(env: Env, s: Any) -> float:
    return float(_s(s))


def _f_convert_to_string(env: Env, v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return _s(v)


_FUNCTIONS: dict[str, Any] = {
    "String.stringContains": _f_string_contains,
    "String.startsWith": _f_starts_with,
    "String.endsWith": _f_ends_with,
    "String.toLowerCase": _f_lower,
    "String.toUpperCase": _f_upper,
    "String.len": _f_len,
    "String.substringBefore": _f_substring_before,
    "String.substringAfter": _f_substring_after,
    "String.substring": _f_substring,
    "String.replace": _f_replace,
    "String.replaceFirst": _f_replace_first,
    "String.removeSpaces": _f_remove_spaces,
    "String.append": _f_append,
    "String.join": _f_join,
    "String.stringSwitch": _f_string_switch,
    # deprecated bare forms of the String functions
    "toLowerCase": _f_lower,
    "toUpperCase": _f_upper,
    "substring": _f_substring,
    "substringBefore": _f_substring_before,
    "substringAfter": _f_substring_after,
    "Arrays.contains": _f_arrays_contains,
    "Arrays.size": _f_arrays_size,
    "Arrays.isEmpty": _f_arrays_is_empty,
    "Arrays.add": _f_arrays_add,
    "Arrays.remove": _f_arrays_remove,
    "Arrays.flatten": _f_arrays_flatten,
    "Arrays.toCsvString": _f_arrays_to_csv,
    "isMemberOfGroup": _f_is_member_of_group,
    "isMemberOfAnyGroup": _f_is_member_of_any_group,
    "isMemberOfAllGroups": _f_is_member_of_all_groups,
    "isMemberOfGroupName": _f_is_member_of_group_name,
    "isMemberOfGroupNameStartsWith": _f_is_member_of_group_name_starts_with,
    "isMemberOfGroupNameContains": _f_is_member_of_group_name_contains,
    "isMemberOfGroupNameRegex": _f_is_member_of_group_name_regex,
    "Convert.toInt": _f_convert_to_int,
    "Convert.toNum": _f_convert_to_num,
    "Convert.toString": _f_convert_to_string,
}

SUPPORTED_FUNCTIONS: frozenset[str] = frozenset(_FUNCTIONS)


def _m_substring(s: str, start: Any, end: Any = None) -> str:
    return s[int(_num(start)) :] if end is None else s[int(_num(start)) : int(_num(end))]


def _m_to_integer(s: str) -> int:
    return int(s)


def _m_to_number(s: str) -> float:
    return float(s)


# Identity Engine string methods (receiver is coerced to a string; null behaves like "")
_STRING_METHODS: dict[str, Callable[..., Any]] = {
    "toLowerCase": lambda s: s.lower(),
    "toUpperCase": lambda s: s.upper(),
    "contains": lambda s, sub: _s(sub) in s,
    "startsWith": lambda s, pre: s.startswith(_s(pre)),
    "endsWith": lambda s, suf: s.endswith(_s(suf)),
    "length": len,
    "size": len,
    "isEmpty": lambda s: len(s) == 0,
    "substring": _m_substring,
    "substringBefore": lambda s, sep: _before(s, _s(sep)),
    "substringAfter": lambda s, sep: _after(s, _s(sep)),
    "replace": lambda s, a, b: s.replace(_s(a), _s(b)),
    "replaceFirst": lambda s, a, b: s.replace(_s(a), _s(b), 1),
    "removeSpaces": lambda s: s.replace(" ", ""),
    "toInteger": _m_to_integer,
    "toNumber": _m_to_number,
    "matches": lambda s, rx: regex_matches(_compile(rx), s),
}

# Identity Engine array methods
_ARRAY_METHODS: dict[str, Callable[..., Any]] = {
    "contains": lambda arr, v: v in arr,
    "size": len,
    "length": len,
    "isEmpty": lambda arr: len(arr) == 0,
    "add": lambda arr, v: [*arr, v],
    "remove": lambda arr, v: [x for x in arr if x != v],
    "flatten": lambda arr: [y for x in arr for y in _as_list(x)],
}

SUPPORTED_METHODS: frozenset[str] = frozenset(_STRING_METHODS) | frozenset(_ARRAY_METHODS)


# ===================================================================================================
# Group-membership criteria (``user.isMemberOf`` / ``user.getGroups``), section 3.6 of the research report
# ===================================================================================================

GROUP_CRITERIA_KEYS = ("group.id", "group.type", "group.profile.name")
NAME_OPERATORS = ("EXACT", "STARTS_WITH")


@dataclass(frozen=True)
class GroupCriterion:
    """One ``key: values`` entry of a criteria map; values within a key are OR-ed."""

    key: str
    values: tuple[str, ...]
    operator: str = "EXACT"  # only meaningful for group.profile.name (default there: STARTS_WITH)

    def matches(self, gid: str, name: str, gtype: str) -> bool:
        if self.key == "group.id":
            return gid in self.values
        if self.key == "group.type":
            return gtype in self.values
        if self.operator == "STARTS_WITH":
            return any(name.startswith(v) for v in self.values)
        return name in self.values


def criteria_from_values(maps: Sequence[Any]) -> tuple[GroupCriterion, ...]:
    """Build criteria from evaluated criteria maps. Raises :class:`Unknown` for anything we cannot decide
    (``group.source.id`` — the snapshot has no source ids —, unknown keys, unknown operators, no criteria)."""
    if not maps:
        raise Unknown("group criteria function without criteria")
    out: list[GroupCriterion] = []
    for m in maps:
        if not isinstance(m, dict):
            raise Unknown(f"group criteria must be a map, got {type(m).__name__}")
        operator = m.get("operator")
        keys = [k for k in m if k != "operator"]
        if operator is not None:
            operator = _s(operator)
            if operator not in NAME_OPERATORS or "group.profile.name" not in keys:
                raise Unknown(f"unsupported criteria operator {operator!r}")
        for k in keys:
            if k not in GROUP_CRITERIA_KEYS:
                raise Unknown(f"unsupported group criteria key {k!r}")
            values = tuple(_s(v) for v in _as_list(m[k]))
            op = (operator or "STARTS_WITH") if k == "group.profile.name" else "EXACT"
            out.append(GroupCriterion(k, values, op))
    return tuple(out)


def group_satisfies(criteria: Sequence[GroupCriterion], gid: str, name: str, gtype: str) -> bool:
    """All criteria maps apply to the same group (they are AND-ed)."""
    return all(c.matches(gid, name, gtype) for c in criteria)


def static_value(e: Expr) -> Any:
    """The value of a literal tree (Literal / ArrayLit / MapLit); raises :class:`Unknown` otherwise."""
    if isinstance(e, Literal):
        return e.value
    if isinstance(e, ArrayLit):
        return [static_value(i) for i in e.items]
    if isinstance(e, MapLit):
        return {k: static_value(v) for k, v in e.entries}
    raise Unknown(f"not a literal: {e.source()}")


def group_criteria(args: Sequence[Expr]) -> tuple[GroupCriterion, ...] | None:
    """Statically decode the criteria maps of ``user.isMemberOf(...)`` / ``user.getGroups(...)``; ``None``
    when they are not literal or use a key/operator without exact semantics (the atom becomes opaque)."""
    try:
        return criteria_from_values([static_value(a) for a in args])
    except Unknown:
        return None


_GROUP_FIELDS: dict[tuple[str, ...], str] = {
    ("id",): "group.id",
    ("type",): "group.type",
    ("profile", "name"): "group.profile.name",
}

Criteria = tuple[GroupCriterion, ...]


def group_set(e: Expr) -> tuple[Criteria, str | None] | None:
    """``user.getGroups(C)`` → ``(C, None)``; ``user.getGroups(C).![id|type|profile.name]`` → ``(C, field)``."""
    if isinstance(e, MethodCall) and e.target == _USER and e.name == "getGroups":
        c = group_criteria(e.args)
        return (c, None) if c is not None else None
    if isinstance(e, Projection):
        inner = group_set(e.target)
        if inner is None or inner[1] is not None:
            return None
        if isinstance(e.body, Attr) and e.body.path in _GROUP_FIELDS:
            return inner[0], _GROUP_FIELDS[e.body.path]
    return None


def membership_atom(e: Expr) -> tuple[Criteria, bool] | None:
    """Recognise a Boolean over the groups matching some criteria: ``(criteria, negated)``.

    * ``user.isMemberOf(C...)``                                   → (C, False)
    * ``Arrays.isEmpty(user.getGroups(C))`` / ``user.getGroups(C).isEmpty()`` → (C, True)
    * ``Arrays.contains(user.getGroups(C).![f], lit)`` / ``....contains(lit)`` → (C + f == lit, False)
    """
    if isinstance(e, MethodCall):
        if e.target == _USER and e.name == "isMemberOf":
            c = group_criteria(e.args)
            return (c, False) if c is not None else None
        if e.name == "isEmpty" and not e.args:
            gs = group_set(e.target)
            return (gs[0], True) if gs is not None else None
        if e.name == "contains" and len(e.args) == 1:
            return _projected_contains(e.target, e.args[0])
    if isinstance(e, Call):
        if e.name == "Arrays.isEmpty" and len(e.args) == 1:
            gs = group_set(e.args[0])
            return (gs[0], True) if gs is not None else None
        if e.name == "Arrays.contains" and len(e.args) == 2:
            return _projected_contains(e.args[0], e.args[1])
    return None


def _projected_contains(target: Expr, needle: Expr) -> tuple[Criteria, bool] | None:
    gs = group_set(target)
    if gs is None or gs[1] is None or not isinstance(needle, Literal):
        return None
    criteria, fld = gs
    return (*criteria, GroupCriterion(fld, (_s(needle.value),), "EXACT")), False


def group_count(e: Expr) -> Criteria | None:
    """``Arrays.size(user.getGroups(C))`` / ``user.getGroups(C).size()`` → C (an Integer-valued term)."""
    if isinstance(e, MethodCall) and e.name == "size" and not e.args:
        gs = group_set(e.target)
        return gs[0] if gs is not None else None
    if isinstance(e, Call) and e.name == "Arrays.size" and len(e.args) == 1:
        gs = group_set(e.args[0])
        return gs[0] if gs is not None else None
    return None


_FLIP = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}


def count_comparison(e: Expr) -> tuple[Criteria, str, int] | None:
    """``<group count> OP n`` (or ``n OP <group count>``) with an integer literal → ``(C, op, n)``, count on the left."""
    if not isinstance(e, BinOp) or e.op not in _FLIP:
        return None
    for count_side, lit_side, op in ((e.left, e.right, e.op), (e.right, e.left, _FLIP[e.op])):
        if isinstance(lit_side, Literal) and isinstance(lit_side.value, int) and not isinstance(lit_side.value, bool):
            c = group_count(count_side)
            if c is not None:
                return c, op, lit_side.value
    return None


# ===================================================================================================
# String predicates over profile attributes (``pred:`` variables in the universe)
# ===================================================================================================

STRING_TRANSFORMS: dict[str, Callable[[str], str]] = {
    "String.toLowerCase": str.lower,
    "String.toUpperCase": str.upper,
    "String.removeSpaces": lambda s: s.replace(" ", ""),
}
_METHOD_TRANSFORMS = {
    "toLowerCase": "String.toLowerCase",
    "toUpperCase": "String.toUpperCase",
    "removeSpaces": "String.removeSpaces",
}
_BARE_TRANSFORMS = {"toLowerCase": "String.toLowerCase", "toUpperCase": "String.toUpperCase"}
_INTERNAL_PROPERTIES = {"status": "user.status", "id": "user.id"}


@dataclass(frozen=True)
class StringTerm:
    """A user profile attribute, optionally wrapped in pure string transforms (innermost first)."""

    path: str
    transforms: tuple[str, ...] = ()

    def apply(self, value: Any) -> str | None:
        if value is None:
            return None
        s = str(value)
        for t in self.transforms:
            s = STRING_TRANSFORMS[t](s)
        return s

    def function(self, outer: str | None = None) -> str:
        """Name of the predicate variable family, e.g. ``String.stringContains∘String.toLowerCase``."""
        parts = ([outer] if outer else []) + list(reversed(self.transforms))
        return "∘".join(parts)


def string_term(e: Expr) -> StringTerm | None:
    """``user.x`` / ``user.profile.x`` / ``user.getInternalProperty("status")`` and their
    ``toLowerCase``/``toUpperCase``/``removeSpaces`` wrappers (static, deprecated bare or method form)."""
    if isinstance(e, Attr):
        return StringTerm(e.normalized) if e.path[0] == "user" and len(e.path) > 1 else None
    if isinstance(e, MethodCall):
        if e.target == _USER and e.name == "getInternalProperty" and len(e.args) == 1:
            arg = e.args[0]
            if isinstance(arg, Literal) and isinstance(arg.value, str) and arg.value in _INTERNAL_PROPERTIES:
                return StringTerm(_INTERNAL_PROPERTIES[arg.value])
            return None
        if e.name in _METHOD_TRANSFORMS and not e.args:
            inner = string_term(e.target)
            return StringTerm(inner.path, (*inner.transforms, _METHOD_TRANSFORMS[e.name])) if inner else None
        return None
    if isinstance(e, Call) and len(e.args) == 1:
        fn = e.name if e.name in STRING_TRANSFORMS else _BARE_TRANSFORMS.get(e.name)
        if fn is not None:
            inner = string_term(e.args[0])
            return StringTerm(inner.path, (*inner.transforms, fn)) if inner else None
    return None


@dataclass(frozen=True)
class PredicateAtom:
    """``function(user.<path>, literal)`` with ``truth(value)`` deciding it for a concrete attribute value."""

    function: str
    path: str
    literal: Any
    truth: Callable[[Any], bool]


_STRING_PREDICATES: dict[str, Callable[[str, str], bool]] = {
    "String.stringContains": lambda s, lit: lit in s,
    "String.startsWith": lambda s, lit: s.startswith(lit),
    "String.endsWith": lambda s, lit: s.endswith(lit),
}
_METHOD_PREDICATES = {
    "contains": "String.stringContains",
    "startsWith": "String.startsWith",
    "endsWith": "String.endsWith",
}


def _string_predicate(function: str, term: StringTerm, lit: str) -> PredicateAtom:
    test = _STRING_PREDICATES[function]

    def truth(v: Any) -> bool:
        if isinstance(v, list | tuple):  # ``.contains`` on an array-valued attribute is membership
            return function == "String.stringContains" and lit in v
        s = term.apply(v)
        return s is not None and test(s, lit)

    return PredicateAtom(term.function(function), term.path, lit, truth)


def _regex_predicate(term: StringTerm, pattern: str) -> PredicateAtom | None:
    try:
        rx = re.compile(pattern)
    except re.error:
        return None
    return PredicateAtom(term.function("matches"), term.path, pattern, lambda v: regex_matches(rx, term.apply(v)))


def equality_predicate(term: StringTerm, lit: str) -> PredicateAtom:
    """``transform(user.x) == "lit"`` for a transformed term (a plain attribute is an ``attr:`` equality instead)."""
    return PredicateAtom(term.function(), term.path, lit, lambda v: term.apply(v) == lit)


def predicate_atom(e: Expr) -> PredicateAtom | None:  # noqa: C901 - flat dispatch
    """Recognise a Boolean string/array predicate on a profile attribute against a literal.

    * ``String.stringContains(term, "lit")`` / ``String.startsWith`` / ``String.endsWith`` and the method forms
      ``term.contains("lit")`` / ``.startsWith`` / ``.endsWith`` (term = attribute, possibly case-folded);
    * ``term matches "regex"`` (full match; an uncompilable regex is not recognised);
    * ``Arrays.contains(user.arr, lit)``, ``Arrays.isEmpty(user.arr)``, ``user.arr.isEmpty()``.
    """
    if isinstance(e, Call):
        if e.name in _STRING_PREDICATES and len(e.args) == 2:
            term = string_term(e.args[0])
            lit = e.args[1]
            if term is not None and isinstance(lit, Literal) and isinstance(lit.value, str):
                return _string_predicate(e.name, term, lit.value)
            return None
        if e.name == "Arrays.contains" and len(e.args) == 2:
            a, b = e.args
            if isinstance(a, Attr) and a.path[0] == "user" and isinstance(b, Literal):
                lit = b.value
                return PredicateAtom(
                    e.name, a.normalized, lit, lambda v, lit=lit: isinstance(v, list | tuple) and lit in v
                )
            return None
        if e.name == "Arrays.isEmpty" and len(e.args) == 1:
            a = e.args[0]
            if isinstance(a, Attr) and a.path[0] == "user":
                return PredicateAtom(
                    e.name,
                    a.normalized,
                    None,
                    lambda v: v is None or (isinstance(v, list | tuple) and len(v) == 0),
                )
            return None
        return None
    if isinstance(e, MethodCall):
        if e.name in _METHOD_PREDICATES and len(e.args) == 1:
            term = string_term(e.target)
            lit = e.args[0]
            if term is not None and isinstance(lit, Literal) and isinstance(lit.value, str):
                return _string_predicate(_METHOD_PREDICATES[e.name], term, lit.value)
            return None
        if e.name == "isEmpty" and not e.args:
            term = string_term(e.target)
            if term is not None:
                return PredicateAtom(
                    term.function("isEmpty"),
                    term.path,
                    None,
                    lambda v: v is None or (isinstance(v, str | list | tuple) and len(v) == 0),
                )
            return None
        if e.name == "matches" and len(e.args) == 1:
            term = string_term(e.target)
            lit = e.args[0]
            if term is not None and isinstance(lit, Literal) and isinstance(lit.value, str):
                return _regex_predicate(term, lit.value)
            return None
        return None
    if isinstance(e, BinOp) and e.op == "matches":
        term = string_term(e.left)
        if term is not None and isinstance(e.right, Literal) and isinstance(e.right.value, str):
            return _regex_predicate(term, e.right.value)
    return None


# ===================================================================================================
# Context atoms tied to structured-condition variables, and Boolean typing
# ===================================================================================================

_PLATFORM_NAMES = {
    "IOS": "IOS",
    "ANDROID": "ANDROID",
    "WINDOWS": "WINDOWS",
    "MACOS": "MACOS",
    "OSX": "MACOS",
    "CHROMEOS": "CHROMEOS",
    "LINUX": "LINUX",
    # MOBILE_OTHER / DESKTOP_OTHER both fall into the model's single OTHER bucket: keep them opaque rather than
    # identify two mutually exclusive atoms.
}
_CONTEXT_BOOLS = {("device", "profile", "managed"): "managed", ("device", "profile", "registered"): "registered"}


def context_bool(e: Expr) -> str | None:
    """Bare ``device.profile.managed`` / ``device.profile.registered`` → ``"managed"`` / ``"registered"``."""
    if isinstance(e, Attr):
        return _CONTEXT_BOOLS.get(e.path)
    return None


def context_equality(e: Expr, lit: Any) -> tuple[str, Any] | None:
    """``<context attribute> == lit`` for the context variables the model already has.

    Returns ``("risk", "HIGH")``, ``("managed", True)``, ``("registered", False)`` or ``("platform", "MACOS")``
    (platform names canonicalised, ``OSX`` → ``MACOS``); ``None`` when there is no exact counterpart.
    """
    if not isinstance(e, Attr):
        return None
    if e.path == ("security", "risk", "level") and isinstance(lit, str):
        return "risk", lit
    kind = _CONTEXT_BOOLS.get(e.path)
    if kind is not None and isinstance(lit, bool):
        return kind, lit
    if e.path == ("device", "profile", "platform") and isinstance(lit, str) and lit in _PLATFORM_NAMES:
        return "platform", _PLATFORM_NAMES[lit]
    return None


_BOOL_OPS = frozenset({"&&", "||", "==", "!=", "<", "<=", ">", ">=", "matches"})
_BOOL_CALLS = frozenset(
    {
        "String.stringContains",
        "String.startsWith",
        "String.endsWith",
        "Arrays.contains",
        "Arrays.isEmpty",
        "hasDirectoryUser",
        "hasWorkdayUser",
    }
)
_BOOL_METHODS = frozenset(
    {
        "isMemberOf",
        "contains",
        "startsWith",
        "endsWith",
        "isEmpty",
        "matches",
        "versionGreaterThan",
        "versionLessThan",
        "withinDays",
        "withinHours",
        "withinMinutes",
        "withinSeconds",
    }
)


def bool_typed(e: Expr) -> bool:
    """Syntactically Boolean-typed: safe to compare with ``true``/``false`` or another Boolean."""
    if isinstance(e, Literal):
        return isinstance(e.value, bool)
    if isinstance(e, UnaryOp):
        return e.op == "!"
    if isinstance(e, BinOp):
        return e.op in _BOOL_OPS
    if isinstance(e, Ternary):
        return bool_typed(e.then) and bool_typed(e.other)
    if isinstance(e, Elvis):
        return bool_typed(e.left) and bool_typed(e.right)
    if isinstance(e, Call):
        return e.name.startswith("isMemberOf") or e.name in _BOOL_CALLS
    if isinstance(e, MethodCall):
        return e.name in _BOOL_METHODS
    return False
