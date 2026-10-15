import pytest

from custody.guard import ACME_POLICY, Guard
from custody.runtime import AgentRuntime, Vault


@pytest.fixture
def guard(recorder):
    return Guard(recorder, ACME_POLICY)


@pytest.fixture
def runtime(recorder, guard):
    return AgentRuntime(recorder, guard, vault=Vault({"secret/aws/deploy-key": "AKIAORIGINAL0000KEY"}))


class Flow:
    """Small builder for Guard test scenarios using the Recorder directly."""

    def __init__(self, r, agent="ops", session="s1"):
        self.r, self.agent, self.session = r, agent, session

    def user(self, text, user="sam@acme-robotics.example"):
        return self.r.record_user_input(text, user=user, agent=self.agent, session_id=self.session)

    def web(self, text, url="https://vendor.example/page"):
        return self.r.record_web_content(text, url=url, agent=self.agent, session_id=self.session)

    def secret(self, value="AKIASECRETVALUE0001KEY", path="secret/aws/deploy-key"):
        return self.r.record_vault_secret(value, path=path, agent=self.agent, session_id=self.session)

    def out(self, text, ctx, attribution="inherit", **kw):
        return self.r.record_llm_output(text, agent=self.agent, session_id=self.session,
                                        derived_from=[c.id if hasattr(c, "id") else c for c in ctx],
                                        attribution=attribution, **kw)

    def action(self, tool, dest, payload, sink_dest=None, kind="email", workspace=None,
               declared_external=True):
        return self.r.record_action(
            tool, agent=self.agent, session_id=self.session, destination=[dest.id],
            payload=[payload.id] if payload is not None else [],
            sink_destination=sink_dest if sink_dest is not None else dest.value,
            sink_kind=kind, sink_workspace=workspace, sink_external=declared_external)


@pytest.fixture
def flow(recorder):
    return Flow(recorder)
