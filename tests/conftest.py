from __future__ import annotations

import pytest

from okta_policy_analyzer.loader import load_tenant
from okta_policy_analyzer.model import Tenant
from okta_policy_analyzer.okta.snapshot import Snapshot

from .fixtures.acme import build_acme


@pytest.fixture(scope="session")
def acme_snapshot() -> Snapshot:
    return build_acme()


@pytest.fixture(scope="session")
def acme() -> Tenant:
    return load_tenant(build_acme())
