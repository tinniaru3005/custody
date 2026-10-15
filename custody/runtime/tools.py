"""Tools the agent runtime can call. Every tool with side effects goes through the Guard.

Execution is simulated: deliveries land in an in-memory ``Outbox`` so tests and demos can
assert exactly what left the system.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections.abc import Callable

from custody.graph.model import fingerprint


@dataclass
class Delivery:
    action_id: str
    tool: str
    sink_kind: str
    destination: str
    workspace: Optional[str]
    payload: str
    payload_fingerprint: str


@dataclass
class Outbox:
    deliveries: List[Delivery] = field(default_factory=list)

    def deliver(self, d: Delivery) -> Delivery:
        self.deliveries.append(d)
        return d

    def to(self, destination: str) -> List[Delivery]:
        return [d for d in self.deliveries if d.destination == destination]

    def __len__(self) -> int:
        return len(self.deliveries)


# sink_for(destination_literal) -> (sink kind, sink destination, workspace)
SinkFn = Callable[[str], Tuple[str, str, Optional[str]]]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    roles: Tuple[str, ...]           # argument roles the tool takes, e.g. destination, payload
    sink_for: Optional[SinkFn]       # None: tool has no sink

    def execute(self, outbox: Outbox, action_id: str, args: Dict[str, str]) -> Delivery:
        dest = args.get("destination", "")
        kind, sink_dest, ws = self.sink_for(dest) if self.sink_for else ("none", dest, None)
        payload = args.get("payload", "")
        return outbox.deliver(Delivery(action_id=action_id, tool=self.name, sink_kind=kind,
                                       destination=sink_dest, workspace=ws, payload=payload,
                                       payload_fingerprint=fingerprint(payload)))


def default_tools(slack_workspace: str = "acme-robotics",
                  ticket_system: str = "acme-jira") -> Dict[str, ToolSpec]:
    return {
        "send_email": ToolSpec("send_email", ("destination", "payload"),
                               lambda d: ("email", d, None)),
        "post_slack": ToolSpec("post_slack", ("destination", "payload"),
                               lambda d: ("slack", d, slack_workspace)),
        "upload_backup": ToolSpec("upload_backup", ("destination", "payload"),
                                  lambda d: ("backup", d, None)),
        "http_post": ToolSpec("http_post", ("destination", "payload"),
                              lambda d: ("http", d, None)),
        "update_ticket": ToolSpec("update_ticket", ("destination", "payload"),
                                  lambda d: ("ticket", d, ticket_system)),
    }
