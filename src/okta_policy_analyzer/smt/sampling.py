"""Turn z3 models into concrete Worlds and sample random worlds consistent with the domain axioms."""

from __future__ import annotations

import random
from collections.abc import Sequence

import z3

from ..interpreter import World
from ..model import DevicePlatform, RiskLevel
from .universe import NULL, Universe, Witness


def world_from_witness(u: Universe, w: Witness) -> World:
    attrs = {}
    for path, text in w.attributes.items():
        lits = u.attr_literals[path]
        if text == "<other>":
            attrs[path] = "<other>"
        else:
            idx = [repr(x) for x in lits].index(text)
            val = lits[idx]
            attrs[path] = None if val == NULL else val
    return World(
        groups=set(w.groups_in),
        user_id=w.user,
        user_type=None if w.user_type in (None, "OTHER") else w.user_type,
        attrs=attrs,
        zones=set(w.zones_in),
        registered=bool(w.registered),
        managed=bool(w.managed),
        platform=DevicePlatform(w.platform) if w.platform else DevicePlatform.OTHER,
        assurances=set(w.assurances),
        risk=RiskLevel(w.risk) if w.risk else RiskLevel.LOW,
        auth_type=w.auth_type or "WEB",
        idp=w.idp or "OKTA",
        opaque=dict(w.opaque),
        predicates=dict(w.predicates),
    )


def world_from_model(u: Universe, model: z3.ModelRef) -> World:
    return world_from_witness(u, u.witness(model, full=True))


def sample_models(
    u: Universe, axioms: Sequence[z3.BoolRef], n: int, *, seed: int = 0, extra: Sequence[z3.BoolRef] = ()
) -> list[z3.ModelRef]:
    """Sample ``n`` models of the axioms by asserting random literals on a random subset of variables.

    Random literals that make the problem unsatisfiable are dropped one at a time, so every sample is a genuine
    model of the axioms. Samples are biased towards diversity (each variable is pinned with probability 1/2).
    """
    rng = random.Random(seed)
    variables = u.all_vars()
    models: list[z3.ModelRef] = []
    base = z3.Solver()
    base.add(*axioms)
    base.add(*extra)
    for _ in range(n):
        pins: list[z3.BoolRef] = []
        for v in variables:
            if rng.random() < 0.5:
                continue
            if z3.is_bool(v):
                pins.append(v if rng.random() < 0.5 else z3.Not(v))
            else:
                hi = _int_domain_size(u, v)
                pins.append(v == rng.randrange(hi))
        rng.shuffle(pins)
        base.push()
        base.add(*pins)
        while base.check() != z3.sat and pins:
            base.pop()
            pins.pop()
            base.push()
            base.add(*pins)
        assert base.check() == z3.sat
        models.append(base.model())
        base.pop()
    return models


def _int_domain_size(u: Universe, v: z3.ExprRef) -> int:
    name = str(v)
    if name == "user_type":
        return len(u.user_type_ids) + 1
    if name == "dev_platform":
        from .universe import PLATFORMS

        return len(PLATFORMS)
    if name == "risk":
        return 3
    if name == "auth_type":
        return 3
    if name == "idp":
        return len(u.idp_ids) + 2
    if name.startswith("attr:"):
        return len(u.attr_literals[name[5:]]) + 1
    return 2
