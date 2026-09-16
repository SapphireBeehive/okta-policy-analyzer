from __future__ import annotations

import z3

from okta_policy_analyzer.smt.dnf import prime_implicants, project


def test_prime_implicants_complete_and_minimal() -> None:
    a, b, c, d = z3.Bools("a b c d")
    f = z3.Or(z3.And(a, b), z3.And(a, c), z3.And(z3.Not(a), d))
    dnf = prime_implicants(f, [a, b, c, d])
    assert dnf.complete and not dnf.unsat and not dnf.trivially_true
    cubes = {frozenset((str(lit.var), lit.value) for lit in cube.lits) for cube in dnf.cubes}
    assert cubes == {
        frozenset({("a", True), ("b", True)}),
        frozenset({("a", True), ("c", True)}),
        frozenset({("a", False), ("d", True)}),
    }
    # DNF is equivalent to the formula
    s = z3.Solver()
    s.add(dnf.expr() != f)
    assert s.check() == z3.unsat


def test_axioms_shrink_cubes() -> None:
    a, b = z3.Bools("a b")
    dnf = prime_implicants(z3.And(a, b), [a, b], axioms=[z3.Implies(a, b)])
    assert [[(str(lit.var), lit.value) for lit in c.lits] for c in dnf.cubes] == [[("a", True)]]


def test_projection_eliminates_context() -> None:
    g1, g2, z = z3.Bools("g1 g2 z")
    risk = z3.Int("risk")
    f = z3.And(z3.Or(g1, g2), z3.Not(z), risk == 1)
    p = project(f, [z, risk], axioms=[risk >= 0, risk <= 2])
    s = z3.Solver()
    s.add(p != z3.Or(g1, g2))
    assert s.check() == z3.unsat


def test_unsat_and_trivial() -> None:
    a = z3.Bool("a")
    assert prime_implicants(z3.And(a, z3.Not(a)), [a]).unsat
    assert prime_implicants(z3.Or(a, z3.Not(a)), [a]).trivially_true


def test_bound_is_reported() -> None:
    xs = z3.Bools(" ".join(f"x{i}" for i in range(8)))
    # exactly-one over 8 variables has 8 prime implicants of size 8; bound at 3
    f = z3.PbEq([(x, 1) for x in xs], 1)
    dnf = prime_implicants(f, xs, limit=3)
    assert not dnf.complete and len(dnf.cubes) == 3
