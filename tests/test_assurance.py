from __future__ import annotations

from okta_policy_analyzer.assurance import Catalogue, Strength, classify_rule, paths_for, satisfying_methods
from okta_policy_analyzer.model import (
    Constraint,
    ConstraintSet,
    FactorMode,
    Requirement,
    Tenant,
    VerificationMethod,
)


def _poss(**kw) -> Constraint:
    return Constraint(kind="POSSESSION", **kw)


def _know(**kw) -> Constraint:
    return Constraint(kind="KNOWLEDGE", **kw)


def test_catalogue_respects_tenant_inventory(acme: Tenant) -> None:
    cat = Catalogue.for_tenant(acme)
    ids = {s.id for s in cat.specs}
    assert "phone_number/voice" not in ids  # inactive method
    assert "google_otp/otp" not in ids  # inactive authenticator
    assert {
        "okta_password/password",
        "okta_verify/signed_nonce",
        "webauthn/webauthn",
        "phone_number/sms",
    } <= ids
    empty = Tenant()
    assert len(Catalogue.for_tenant(empty).specs) > 10  # falls back to the full table with a warning
    assert Catalogue.for_tenant(empty).warnings


def test_phishing_resistant_constraint(acme: Tenant) -> None:
    cat = Catalogue.for_tenant(acme)
    pr = satisfying_methods(_poss(phishing_resistant=Requirement.REQUIRED), cat)
    assert {s.id for s in pr} == {"okta_verify/signed_nonce", "webauthn/webauthn"}
    hw = satisfying_methods(_poss(hardware_protection=Requirement.REQUIRED), cat)
    assert {s.id for s in hw} == {"okta_verify/signed_nonce", "webauthn/webauthn", "okta_verify/push"}
    db = satisfying_methods(_poss(device_bound=Requirement.REQUIRED), cat)
    assert "phone_number/sms" not in {s.id for s in db} and "okta_verify/totp" in {s.id for s in db}
    types = satisfying_methods(_poss(types=["PHONE", "EMAIL"]), cat)
    assert {s.id for s in types} == {"phone_number/sms", "okta_email/email"}
    methods = satisfying_methods(_poss(methods=["PUSH"]), cat)
    assert {s.id for s in methods} == {"okta_verify/push"}
    specific = satisfying_methods(
        _poss(authentication_methods=[("okta_verify", "totp"), ("webauthn", None)]), cat
    )
    assert {s.id for s in specific} == {"okta_verify/totp", "webauthn/webauthn"}
    excluded = satisfying_methods(
        _poss(
            excluded_authentication_methods=[("phone_number", None), ("okta_email", "email")], required=False
        ),
        cat,
    )
    assert "phone_number/sms" not in {s.id for s in excluded} and "okta_verify/push" in {
        s.id for s in excluded
    }


def test_two_fa_paths_need_two_factor_types(acme: Tenant) -> None:
    cat = Catalogue.for_tenant(acme)
    paths = paths_for(VerificationMethod(factor_mode=FactorMode.TWO_FA), cat)
    for p in paths:
        assert p.factor_count >= 2
        kinds = {m.factor_type for m in p.methods}
        # either knowledge+possession, or a single user-verifying possession factor
        assert kinds == {"KNOWLEDGE", "POSSESSION"} or (len(p.methods) == 1 and p.uses_user_verification)
    assert not any({m.key for m in p.methods} == {"okta_password", "security_question"} for p in paths)
    assert any(len(p.methods) == 1 and p.methods[0].id == "webauthn/webauthn" for p in paths)
    assert not any(len(p.methods) == 1 and p.methods[0].id == "okta_verify/totp" for p in paths)


def test_password_plus_phishing_resistant(acme: Tenant) -> None:
    cat = Catalogue.for_tenant(acme)
    vm = VerificationMethod(
        factor_mode=FactorMode.TWO_FA,
        constraints=[
            ConstraintSet(
                knowledge=_know(types=["PASSWORD"]), possession=_poss(phishing_resistant=Requirement.REQUIRED)
            )
        ],
    )
    paths = paths_for(vm, cat)
    assert paths and all(p.uses_password for p in paths)
    assert all(p.phishing_resistant for p in paths)
    assert {m.id for p in paths for m in p.possession} == {"okta_verify/signed_nonce", "webauthn/webauthn"}
    # knowledge required => no single-factor UV shortcut
    assert all(len(p.methods) == 2 for p in paths)


def test_one_fa_paths_and_strengths(acme: Tenant) -> None:
    cat = Catalogue.for_tenant(acme)
    any1 = paths_for(VerificationMethod(factor_mode=FactorMode.ONE_FA), cat)
    assert min(p.strength for p in any1) == Strength.ONE_FA_KNOWLEDGE
    pw = paths_for(
        VerificationMethod(
            factor_mode=FactorMode.ONE_FA, constraints=[ConstraintSet(knowledge=_know(types=["PASSWORD"]))]
        ),
        cat,
    )
    assert [p.methods[0].id for p in pw] == ["okta_password/password"]
    pwless = paths_for(
        VerificationMethod(
            factor_mode=FactorMode.ONE_FA,
            constraints=[ConstraintSet(possession=_poss(phishing_resistant=Requirement.REQUIRED))],
        ),
        cat,
    )
    assert {p.strength for p in pwless} == {Strength.ONE_FA_PHISHING_RESISTANT}
    uv = paths_for(
        VerificationMethod(
            factor_mode=FactorMode.ONE_FA,
            constraints=[ConstraintSet(possession=_poss(user_verification=Requirement.REQUIRED))],
        ),
        cat,
    )
    assert all(p.uses_user_verification for p in uv) and all(p.factor_count == 2 for p in uv)


def test_constraint_sets_are_or_ed(acme: Tenant) -> None:
    cat = Catalogue.for_tenant(acme)
    vm = VerificationMethod(
        factor_mode=FactorMode.TWO_FA,
        constraints=[
            ConstraintSet(possession=_poss(methods=["SMS"])),
            ConstraintSet(possession=_poss(methods=["WEBAUTHN"])),
        ],
    )
    poss_ids = {m.id for p in paths_for(vm, cat) for m in p.possession}
    assert poss_ids == {"phone_number/sms", "webauthn/webauthn"}


def test_classify_rules_in_fixture(acme: Tenant) -> None:
    cat = Catalogue.for_tenant(acme)
    rules = {r.id: r for p in acme.access_policies for r in p.rules}
    assert classify_rule(rules["rul_admin_deny_contractors"], cat).weakest == Strength.DENY
    assert classify_rule(rules["rul_admin_pr"], cat).weakest == Strength.TWO_FA_PHISHING_RESISTANT
    assert (
        classify_rule(rules["rul_std_finance_hw"], cat).weakest == Strength.TWO_FA_PHISHING_RESISTANT_HARDWARE
    )
    assert classify_rule(rules["rul_admin_corp"], cat).weakest == Strength.TWO_FA
    assert classify_rule(rules["rul_weak_default"], cat).weakest == Strength.ONE_FA_KNOWLEDGE
    ra = classify_rule(rules["rul_std_managed"], cat)
    assert ra.weakest == Strength.TWO_FA_PHISHING_RESISTANT and ra.passwordless_possible


def test_no_path_when_required_authenticator_disabled(acme: Tenant) -> None:
    cat = Catalogue.for_tenant(acme)
    cat.specs = [s for s in cat.specs if s.key not in ("webauthn", "okta_verify")]
    rules = {r.id: r for p in acme.access_policies for r in p.rules}
    assert classify_rule(rules["rul_admin_pr"], cat).weakest == Strength.NO_PATH
