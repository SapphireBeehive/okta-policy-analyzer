"""Concrete evaluator for the Okta EL subset.

Used by the reference interpreter (differential testing) and by the concrete "explain this user" mode.
Evaluation happens against an ``env`` mapping that provides:

* ``attrs``: mapping of normalized attribute path (``user.department``) to a Python value,
* ``group_ids``: set of group ids the user belongs to,
* ``group_names``: set of group names the user belongs to.

Anything the evaluator cannot interpret raises :class:`Unknown`; callers treat the sub-expression
as an opaque predicate (the formal model does the same, so the two stay aligned).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .ast import ArrayLit, Attr, BinOp, Call, Expr, Literal, Ternary, UnaryOp


class EvalError(ValueError):
    pass


class Unknown(EvalError):
    """The expression uses a construct the evaluator does not interpret."""


@dataclass
class Env:
    attrs: Mapping[str, Any] = field(default_factory=dict)
    group_ids: frozenset[str] = frozenset()
    group_names: frozenset[str] = frozenset()

    def attr(self, path: str) -> Any:
        if path in self.attrs:
            return self.attrs[path]
        # unknown attributes evaluate to null (Okta treats missing profile attributes as null)
        if path.startswith("user."):
            return None
        raise Unknown(f"unknown reference {path}")


def evaluate(expr: Expr, env: Env) -> Any:
    """Evaluate ``expr`` in ``env``. Returns a Python value (bool/str/number/list/None)."""
    if isinstance(expr, Literal):
        return expr.value
    if isinstance(expr, Attr):
        return env.attr(expr.normalized)
    if isinstance(expr, ArrayLit):
        return [evaluate(i, env) for i in expr.items]
    if isinstance(expr, UnaryOp):
        v = evaluate(expr.operand, env)
        if expr.op == "!":
            return not _truthy(v)
        if expr.op == "-":
            return -_num(v)
        raise Unknown(f"unary {expr.op}")
    if isinstance(expr, Ternary):
        return evaluate(expr.then, env) if _truthy(evaluate(expr.cond, env)) else evaluate(expr.other, env)
    if isinstance(expr, BinOp):
        return _binop(expr, env)
    if isinstance(expr, Call):
        return _call(expr, env)
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


def _call(expr: Call, env: Env) -> Any:
    name = expr.name
    args = expr.args
    fn = _FUNCTIONS.get(name)
    if fn is None:
        raise Unknown(f"function {name}")
    return fn(env, *[evaluate(a, env) for a in args])


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


def _f_substring_before(env: Env, s: Any, sep: Any) -> str:
    s, sep = _s(s), _s(sep)
    return s.split(sep, 1)[0] if sep in s else ""


def _f_substring_after(env: Env, s: Any, sep: Any) -> str:
    s, sep = _s(s), _s(sep)
    return s.split(sep, 1)[1] if sep in s else ""


def _f_substring(env: Env, s: Any, start: Any, end: Any) -> str:
    return _s(s)[int(_num(start)) : int(_num(end))]


def _f_replace(env: Env, s: Any, a: Any, b: Any) -> str:
    return _s(s).replace(_s(a), _s(b))


def _f_remove_spaces(env: Env, s: Any) -> str:
    return _s(s).replace(" ", "")


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
    try:
        rx = re.compile(_s(pattern))
    except re.error as e:
        raise EvalError(f"bad regex {pattern!r}: {e}") from e
    return any(rx.search(n) for n in env.group_names)


def _f_is_member_of_all_groups(env: Env, gids: Any) -> bool:
    return all(_s(g) in env.group_ids for g in _as_list(gids))


def _f_convert_to_int(env: Env, s: Any) -> int:
    return int(_s(s))


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
    "String.removeSpaces": _f_remove_spaces,
    "String.join": _f_join,
    "String.stringSwitch": _f_string_switch,
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
    "Convert.toString": _f_convert_to_string,
}

SUPPORTED_FUNCTIONS: frozenset[str] = frozenset(_FUNCTIONS)
