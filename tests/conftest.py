"""Shared fixtures.

Tests run against a real FalkorDB:
- if CUSTODY_TEST_FALKORDB_HOST is set, that server is used;
- otherwise an embedded FalkorDB (falkordblite) is started for the session.
Each test gets its own tenant graph, dropped afterwards.
"""
from __future__ import annotations

import os
import uuid

import pytest

from custody.db import GraphProvider
from custody.graph.repository import GraphRepository
from custody.recorder.service import Recorder


@pytest.fixture(scope="session")
def falkordb_client(tmp_path_factory):
    host = os.environ.get("CUSTODY_TEST_FALKORDB_HOST")
    if host:
        from falkordb import FalkorDB

        client = FalkorDB(host=host, port=int(os.environ.get("CUSTODY_TEST_FALKORDB_PORT", 6379)))
    else:
        try:
            from redislite.falkordb_client import FalkorDB as Embedded
        except ImportError:
            pytest.skip("no FalkorDB available: set CUSTODY_TEST_FALKORDB_HOST or "
                        "pip install falkordblite")
        client = Embedded(str(tmp_path_factory.mktemp("falkordb") / "test.db"))
    yield client


@pytest.fixture
def provider(falkordb_client):
    return GraphProvider(falkordb_client, prefix="custody-test")


@pytest.fixture
def tenant(provider):
    name = f"t-{uuid.uuid4().hex[:10]}"
    yield name
    provider.drop(name)


@pytest.fixture
def graph(provider, tenant):
    return provider.graph(tenant)


@pytest.fixture
def repo(graph):
    return GraphRepository(graph)


@pytest.fixture
def recorder(repo):
    return Recorder(repo)
