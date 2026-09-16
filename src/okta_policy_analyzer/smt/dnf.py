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
    value: Any  # bool for Bool vars, int for Int vars
    positive: bool = True  # False means var != value (only used for Int vars in explanations)

    def expr(self) -> z3.BoolRef:
        if z3.is_bool(self.var):
            e = self.var if self.value else z3.Not(self.var)
            return e if self.positive else z3.Not(e)
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
    elim = [v for v in eliminate if _occurs(v, body)]
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


def _occurs(var: z3.ExprRef, expr: z3.ExprRef) -> bool:
    name = var.decl().name()
    seen: set[int] = set()
    stack = [expr]
    while stack:
        e = stack.pop()
        if e.get_id() in seen:
            continue
        seen.add(e.get_id())
        if z3.is_const(e) and e.decl().name() == name:
            return True
        if z3.is_app(e):
            stack.extend(e.children())
        elif z3.is_quantifier(e):
            stack.append(e.body())
    return False


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
    relevant = [v for v in variables if _occurs(v, formula) or _occurs(v, ax)]
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
    i = len(keep) - 1
    while i >= 0 and len(keep) > 1:
        others = keep[:i] + keep[i + 1 :]
        s = z3.Solver()
        s.add(ax, keep[i].expr(), z3.Not(z3.Or(*[c.expr() for c in others])))
        if s.check() == z3.unsat:
            keep = others
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
    """Drop literals while the cube still implies the formula (checker holds axioms ∧ ¬formula)."""
    lits = list(cube)
    i = 0
    while i < len(lits):
        trial = lits[:i] + lits[i + 1 :]
        checker.push()
        checker.add(*[lit.expr() for lit in trial])
        implies = checker.check() == z3.unsat
        checker.pop()
        if implies:
            lits = trial
        else:
            i += 1
    return lits


def describe_cube(cube: Cube, namer) -> str:  # noqa: ANN001 - callable(var, value, positive) -> str
    if not cube.lits:
        return "anyone / any context"
    return " ∧ ".join(namer(lit.var, lit.value, lit.positive) for lit in cube.lits)


def describe_dnf(dnf: DNF, namer, *, bullet: str = "• ") -> list[str]:  # noqa: ANN001
    if dnf.unsat:
        return [f"{bullet}nobody (unsatisfiable)"]
    if dnf.trivially_true:
        return [f"{bullet}everyone, in every context"]
    lines = [bullet + describe_cube(c, namer) for c in dnf.cubes]
    if not dnf.complete:
        lines.append(f"{bullet}… (enumeration bound reached; the list above is incomplete)")
    return lines
