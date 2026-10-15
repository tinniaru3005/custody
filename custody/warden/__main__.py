"""Warden command line.

    python -m custody.warden serve   --tenant acme [--transport stdio|streamable-http|sse]
                                     [--host 127.0.0.1 --port 8765] [--seed-demo]
    python -m custody.warden agent   --tenant acme "That vendor page was malicious. Clean it up."
                                     [--planner auto|anthropic|playbook] [--mcp-url URL] [--seed-demo]
    python -m custody.warden approve --tenant acme <action_id> --approver priya@acme-robotics.example
    python -m custody.warden seed    --tenant acme        # load the Acme incident scenario

Connection settings come from CUSTODY_* env vars (see .env.example), e.g.
CUSTODY_FALKORDB_EMBEDDED_PATH=.data/custody.db for an embedded FalkorDB.
Logs go to stderr (stdout is the MCP stdio channel).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from custody.config import get_settings
from custody.db import GraphProvider, connect
from custody.warden.service import Warden


def _provider() -> GraphProvider:
    s = get_settings()
    return GraphProvider(connect(s), s.graph_prefix, s.max_trace_depth)


def _policy(name, tenant: str, seed_demo: bool):
    """--policy NAME (a registered tenant policy, e.g. 'acme', or 'default'); with
    --seed-demo and no --policy the Acme policy is used because the scenario is Acme's."""
    from custody.guard.policy import _TENANT_POLICIES, DEFAULT_POLICY, policy_for_tenant

    if name == "default":
        return DEFAULT_POLICY
    if name:
        if name not in _TENANT_POLICIES:
            raise SystemExit(f"unknown policy {name!r}; known: default, "
                             + ", ".join(sorted(_TENANT_POLICIES)))
        return _TENANT_POLICIES[name]
    if seed_demo and tenant not in _TENANT_POLICIES:
        return _TENANT_POLICIES["acme"]
    return policy_for_tenant(tenant)


def _seed_if_empty(warden: Warden) -> bool:
    from custody.demo.acme_warden import build_incident

    if warden.repo.counts().get("node:Action", 0):
        return False
    build_incident(warden.recorder)
    return True


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(prog="python -m custody.warden")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("serve", help="run the Warden MCP server")
    sp.add_argument("--tenant", required=True)
    sp.add_argument("--policy", help="Guard policy name (default: the tenant's own)")
    sp.add_argument("--operator", default="security-operator",
                    help="human identity recorded for begin_investigation")
    sp.add_argument("--transport", default="stdio", choices=["stdio", "streamable-http", "sse"])
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8765)
    sp.add_argument("--seed-demo", action="store_true",
                    help="load the Acme incident scenario if the tenant has no actions yet")

    ag = sub.add_parser("agent", help="run the LLM-driven Warden agent")
    ag.add_argument("request")
    ag.add_argument("--tenant", required=True)
    ag.add_argument("--policy", help="Guard policy name (default: the tenant's own)")
    ag.add_argument("--operator", default="security-operator")
    ag.add_argument("--planner", default="auto", choices=["auto", "anthropic", "playbook"])
    ag.add_argument("--mcp-url", help="connect to a running Warden MCP server instead")
    ag.add_argument("--seed-demo", action="store_true")
    ag.add_argument("--json", action="store_true", help="print the full report as JSON")

    pr = sub.add_parser("approve", help="human approval of a proposed disclosure")
    pr.add_argument("action_id")
    pr.add_argument("--tenant", required=True)
    pr.add_argument("--policy", help="Guard policy name (default: the tenant's own)")
    pr.add_argument("--approver", required=True)
    pr.add_argument("--reason")
    pr.add_argument("--send", action="store_true", help="send right after approval")

    sd = sub.add_parser("seed", help="load the Acme incident scenario")
    sd.add_argument("--tenant", required=True)
    sd.add_argument("--reset", action="store_true", help="drop the tenant graph first")

    a = ap.parse_args(argv)
    provider = _provider()

    if a.cmd == "seed":
        if a.reset:
            provider.drop(a.tenant)
        w = Warden.for_tenant(provider, a.tenant)
        print("seeded" if _seed_if_empty(w) else "tenant already has actions; use --reset")
        return 0

    if a.cmd == "serve":
        from custody.warden.mcp_server import build_server

        w = Warden.for_tenant(provider, a.tenant, operator=a.operator,
                              policy=_policy(a.policy, a.tenant, a.seed_demo))
        if a.seed_demo and _seed_if_empty(w):
            logging.getLogger("custody.warden").info("seeded Acme incident scenario")
        server = build_server(w)
        if a.transport == "stdio":
            server.run("stdio")
        else:
            server.run(a.transport, host=a.host, port=a.port)
        return 0

    if a.cmd == "agent":
        from custody.warden.agent import (AnthropicPlanner, PlaybookPlanner, default_planner,
                                          run_warden, run_warden_remote)

        planner = {"auto": default_planner, "anthropic": AnthropicPlanner,
                   "playbook": PlaybookPlanner}[a.planner]()
        if a.mcp_url:
            report = asyncio.run(run_warden_remote(a.mcp_url, a.request, planner))
        else:
            w = Warden.for_tenant(provider, a.tenant, operator=a.operator,
                                  policy=_policy(a.policy, a.tenant, a.seed_demo))
            if a.seed_demo:
                _seed_if_empty(w)
            report = asyncio.run(run_warden(w, a.request, planner))
        if a.json:
            print(report.model_dump_json(indent=2))
        else:
            print(f"[planner: {report.planner}] tools: {' → '.join(report.tools_used)}\n")
            print(report.final_text)
        return 0

    if a.cmd == "approve":
        w = Warden.for_tenant(provider, a.tenant, operator=a.approver,
                              policy=_policy(a.policy, a.tenant, False))
        d = w.approve_disclosure(a.action_id, approver=a.approver, reason=a.reason)
        out = {"action_id": a.action_id, "decision": d.decision.value, "status": d.action_status}
        if a.send:
            out["send"] = w.send_approved_disclosure(a.action_id).model_dump()
        print(json.dumps(out, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
