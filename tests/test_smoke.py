import z3

import okta_policy_analyzer


def test_version_and_solver_available() -> None:
    assert okta_policy_analyzer.__version__
    s = z3.Solver()
    a = z3.Bool("a")
    s.add(a, z3.Not(a))
    assert s.check() == z3.unsat
