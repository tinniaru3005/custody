import pytest

from custody.demo.acme_warden import build_incident
from custody.guard import ACME_POLICY
from custody.warden import Warden

OPERATOR = "priya@acme-robotics.example"


@pytest.fixture
def warden(provider, tenant):
    return Warden.for_tenant(provider, tenant, policy=ACME_POLICY, operator=OPERATOR)


@pytest.fixture
def incident(warden):
    """The Acme incident scenario, recorded through the normal agent runtime."""
    return build_incident(warden.recorder)


def by_key(nodes, key):
    return next(n for n in nodes if n.key == key)
