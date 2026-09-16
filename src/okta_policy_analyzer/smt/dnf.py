"""Projection and prime-implicant enumeration: turn a formula into a readable "who / when" description.

Given a formula F over WHO and CONTEXT variables, ``project`` eliminates the variables we do not want to talk
about (∃ctx. F) with z3's quantifier elimination, and ``prime_implicants`` enumerates a complete DNF of minimal
cubes (partial assignments) of the result. Each cube is a conjunction of literals ``var == value``; dropping any
literal would make it stop implying the formula. Enumeration is all-SAT with blocking clauses; a bound keeps
pathological cases finite and the result says whether it is complete.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import z3


@dataclass(frozen=True)
class Lit:
    var: z3.ExprRef
    value: Any  # bool for Bool vars, int for Int vars, frozenset[int] for a merged set of enum values
    positive: bool = True  # False means var != value / var ∉ set

    def expr(self) -> z3.BoolRef:
        if z3.is_bool(self.var):
            e = self.var if self.value else z3.Not(self.var)
            return e if self.positive else z3.Not(e)
        if isinstance(self.value, frozenset):
            e = z3.Or(*[self.var == v for v in sorted(self.value)])
        else:
            e = self.var == self.value
        return e if self.positive else z3.Not(e)


@dataclass
class Cube:
    lits: list[Lit]

    def expr(self) -> z3.BoolRef:
        return z3.And(*[lit.expr() for lit in self.lits]) if self.lits else z3.BoolVal(True)

    def __len__(self) -> int:
        return len(self.lits)


@dataclass
class DNF:
    cubes: list[Cube] = field(default_factory=list)
    complete: bool = True  # False when the enumeration bound was hit
    trivially_true: bool = False
    unsat: bool = False
    coarse: bool = False  # description over a reduced vocabulary (sound over-approximation of the exact set)
    fine_count: int = 0  # number of exact cubes found before falling back

    def expr(self) -> z3.BoolRef:
        if self.unsat:
            return z3.BoolVal(False)
        if self.trivially_true or not self.cubes:
            return z3.BoolVal(True)
        return z3.Or(*[c.expr() for c in self.cubes])


def project(
    formula: z3.BoolRef, eliminate: Sequence[z3.ExprRef], axioms: Sequence[z3.BoolRef] = ()
) -> z3.BoolRef:
    """∃ eliminate. (axioms ∧ formula), quantifier-free."""
    body = z3.And(*axioms, formula) if axioms else formula
    names = var_names(formula) | (axiom_var_names(axioms) if axioms else set())
    elim = [v for v in eliminate if v.decl().name() in names]
    if not elim:
        return z3.simplify(body)
    q = z3.Exists(elim, body)
    for tactic in ("qe2", "qe", "qe_lite"):
        try:
            goal = z3.Tactic(tactic)(q)
            expr = goal.as_expr()
            if not _has_quantifier(expr):
                return z3.simplify(expr)
        except z3.Z3Exception:
            continue
    return q  # give up: callers must handle a quantified result (they use a solver, which still works)


def var_names(expr: z3.ExprRef) -> set[str]:
    """Names of all uninterpreted constants occurring in ``expr`` (one traversal)."""
    names: set[str] = set()
    seen: set[int] = set()
    stack = [expr]
    while stack:
        e = stack.pop()
        if e.get_id() in seen:
            continue
        seen.add(e.get_id())
        if z3.is_quantifier(e):
            stack.append(e.body())
            continue
        if z3.is_const(e) and e.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            names.add(e.decl().name())
        elif z3.is_app(e):
            stack.extend(e.children())
    return names


_AXIOM_NAMES: dict[tuple[int, ...], set[str]] = {}


def axiom_var_names(axioms: Sequence[z3.BoolRef]) -> set[str]:
    """Cached variable names of an axiom list (axiom lists are reused across many queries)."""
    key = tuple(a.get_id() for a in axioms)
    if key not in _AXIOM_NAMES:
        if len(_AXIOM_NAMES) > 64:
            _AXIOM_NAMES.clear()
        _AXIOM_NAMES[key] = set().union(*(var_names(a) for a in axioms)) if axioms else set()
    return _AXIOM_NAMES[key]


def _has_quantifier(expr: z3.ExprRef) -> bool:
    seen: set[int] = set()
    stack = [expr]
    while stack:
        e = stack.pop()
        if e.get_id() in seen:
            continue
        seen.add(e.get_id())
        if z3.is_quantifier(e):
            return True
        if z3.is_app(e):
            stack.extend(e.children())
    return False


def prime_implicants(
    formula: z3.BoolRef,
    variables: Sequence[z3.ExprRef],
    axioms: Sequence[z3.BoolRef] = (),
    *,
    limit: int = 64,
) -> DNF:
    """Complete DNF of prime implicants of ``formula`` (under ``axioms``) over ``variables``.

    Only variables that occur in the formula (or the axioms) are used in cubes; the rest are don't-cares.
    ``axioms`` are background constraints (domain axioms): implicants are checked relative to them, i.e. a cube c
    is accepted when ``axioms ∧ c ⊨ formula``.
    """
    ax = z3.And(*axioms) if axioms else z3.BoolVal(True)
    checker = z3.Solver()
    checker.add(ax)
    checker.add(z3.Not(formula))
    enum = z3.Solver()
    enum.add(ax)
    enum.add(formula)
    names = var_names(formula) | (axiom_var_names(axioms) if axioms else set())
    relevant = [v for v in variables if v.decl().name() in names]
    # Literals are dropped in list order during minimisation: put derived facts (attributes, predicates,
    # specific users) first so that cubes are preferably expressed in terms of groups and context.
    relevant.sort(key=_drop_priority)
    result = DNF()
    if enum.check() != z3.sat:
        result.unsat = True
        return result
    # does the formula hold under the axioms alone?
    if checker.check() == z3.unsat:
        result.trivially_true = True
        return result
    count = 0
    while enum.check() == z3.sat:
        if count >= limit:
            result.complete = False
            break
        model = enum.model()
        cube = _model_cube(model, relevant)
        cube = _minimise(cube, checker)
        result.cubes.append(Cube(cube))
        enum.add(z3.Not(Cube(cube).expr()))
        count += 1
    result.cubes.sort(key=lambda c: (len(c.lits), [str(lit.var) for lit in c.lits]))
    if result.complete:
        result.cubes = _irredundant(result.cubes, ax)
    return result


def _drop_priority(var: z3.ExprRef) -> tuple[int, str]:
    name = str(var)
    for rank, prefix in enumerate(("pred:", "attr:", "user_is[", "user_type", "opaque:")):
        if name.startswith(prefix):
            return (rank, name)
    return (10, name)


def _irredundant(cubes: list[Cube], ax: z3.BoolRef) -> list[Cube]:
    """Drop cubes whose models are already covered by the remaining cubes (prefer keeping shorter cubes)."""
    keep = list(cubes)
    exprs = [c.expr() for c in keep]
    s = z3.Solver()
    s.add(ax)
    i = len(keep) - 1
    while i >= 0 and len(keep) > 1:
        others = exprs[:i] + exprs[i + 1 :]
        s.push()
        s.add(exprs[i], z3.Not(z3.Or(*others)))
        covered = s.check() == z3.unsat
        s.pop()
        if covered:
            del keep[i]
            del exprs[i]
        i -= 1
    return keep


def _model_cube(model: z3.ModelRef, variables: Sequence[z3.ExprRef]) -> list[Lit]:
    lits: list[Lit] = []
    for v in variables:
        val = model.eval(v, model_completion=True)
        if z3.is_bool(v):
            lits.append(Lit(v, z3.is_true(val)))
        else:
            lits.append(Lit(v, val.as_long()))
    return lits


def _minimise(cube: list[Lit], checker: z3.Solver) -> list[Lit]:
    """Drop literals while the cube still implies the formula (checker holds axioms ∧ ¬formula).

    Uses assumption-based incremental checking with the literal expressions built once, so a cube of n
    literals costs n incremental checks and no re-encoding.
    """
    lits = list(cube)
    exprs = [lit.expr() for lit in lits]
    i = 0
    while i < len(lits):
        trial = exprs[:i] + exprs[i + 1 :]
        if checker.check(*trial) == z3.unsat:
            del lits[i]
            del exprs[i]
        else:
            i += 1
    return lits


def merge_enum_values(cubes: list[Cube]) -> list[Cube]:
    """Presentation: merge cubes that differ only in the value of one integer (enum) variable.

    ``platform == IOS ∧ z`` and ``platform == ANDROID ∧ z`` become ``platform ∈ {ANDROID, IOS} ∧ z`` (a
    frozenset-valued literal). Repeated until no more merges apply. Logically equivalent to the input.
    """
    changed = True
    while changed:
        changed = False
        result: list[Cube] = []
        used: set[int] = set()
        for i, a in enumerate(cubes):
            if i in used:
                continue
            merged = a
            for j in range(i + 1, len(cubes)):
                if j in used:
                    continue
                m = _merge_pair(merged, cubes[j])
                if m is not None:
                    merged = m
                    used.add(j)
                    changed = True
            result.append(merged)
        cubes = result
    return cubes


def _merge_pair(a: Cube, b: Cube) -> Cube | None:
    if len(a.lits) != len(b.lits):
        return None
    diff = [(x, y) for x, y in zip(a.lits, b.lits, strict=True) if x != y]
    if len(diff) != 1:
        return None
    x, y = diff[0]
    if not (x.var.eq(y.var) and not z3.is_bool(x.var) and x.positive and y.positive):
        return None
    vx = x.value if isinstance(x.value, frozenset) else frozenset({x.value})
    vy = y.value if isinstance(y.value, frozenset) else frozenset({y.value})
    new = Lit(x.var, vx | vy, True)
    return Cube([new if lit == x else lit for lit in a.lits])


def describe_cube(cube: Cube, namer) -> str:  # noqa: ANN001 - callable(var, value, positive) -> str
    if not cube.lits:
        return "anyone / any context"
    return " ∧ ".join(namer(lit.var, lit.value, lit.positive) for lit in cube.lits)


def describe_dnf(dnf: DNF, namer, *, bullet: str = "• ") -> list[str]:  # noqa: ANN001
    if dnf.unsat:
        return [f"{bullet}nobody (unsatisfiable)"]
    if dnf.trivially_true:
        return [f"{bullet}everyone, in every context"]
    lines = [bullet + describe_cube(c, namer) for c in merge_enum_values(dnf.cubes)]
    if dnf.coarse:
        lines.append(
            f"{bullet}(coarse description over the rule's own groups; the exact enumeration exceeded the bound after {dnf.fine_count} cubes)"
        )
    if not dnf.complete:
        lines.append(f"{bullet}… (enumeration bound reached; the list above is incomplete)")
    return lines
