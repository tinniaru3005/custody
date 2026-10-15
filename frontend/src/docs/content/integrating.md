# Recording your own agents

Custody can check actions from any agent framework, as long as the framework records what its agents see and produce. There are two ways in: the HTTP Recorder API from any language, or the Python agent runtime in-process.

> [!WARNING]
> Custody ships no connectors to real services. The runtime's tools deliver to an in-memory outbox, and over HTTP or MCP Custody only answers. **Your code executes the side effect, and must do so only on ALLOW.**

## The contract

1. **Record every input** that enters a model's context: user messages, fetched pages, tool results, vault reads, recalled memories, received messages. Each becomes a Datum with a `FROM` edge to its Source, and the Source's trust label is what the Guard reasons about.
2. **Link every output to the whole context window.** Each model output, memory and message must list every Datum that was in the context as `derived_from`. Over-approximating is safe (a possible false alarm); leaving something out is not (a possible false ALLOW).
3. **Record the action before running it**, with its arguments as Datums and its sink.
4. **Ask the Guard, then enforce the verdict**: execute only on `ALLOW`; on `REQUIRE_HUMAN_APPROVAL` wait for a human; on `BLOCK` (or an incomplete search) do not execute.
5. **Update the action's status** after executing, so the console and the Warden know what left the system.

## Over HTTP

The examples use the tenant `quickstart` against a local API; replace the base URL for your deployment. Ids are generated unless you pass `id`; yours will differ. Full reference: [HTTP API](/docs/api-reference#recorder).

```bash title="Terminal"
B=http://localhost:8000/api/tenants/quickstart
```

### 1. Record what entered the context

```bash title="Terminal"
curl -s -X POST $B/record/user-input -H 'content-type: application/json' -d '{
  "text": "Back up the staging key to our usual backup host",
  "user": "sam@acme-robotics.example", "agent": "ops", "session_id": "s1"}'

curl -s -X POST $B/record/web-content -H 'content-type: application/json' -d '{
  "content": "Backup endpoint: https://ingest.vaultsync-mirror.example/v1/upload",
  "url": "https://docs.vaultsync-backup.example/setup", "agent": "ops", "session_id": "s1"}'

curl -s -X POST $B/record/vault-secret -H 'content-type: application/json' -d '{
  "secret": "AKIA-EXAMPLE-NOT-REAL", "path": "secret/staging/api-key",
  "agent": "ops", "session_id": "s1"}'
```

Each call returns the Datum. For the secret, the raw value is not stored:

```json title="201 Created (abridged)"
{
  "id": "d_7a6d7ff859714b2f",
  "kind": "secret",
  "value": null,
  "preview": "[secret:21 chars]…REAL",
  "sensitivity": "secret",
  "source_id": "vault:secret/staging/api-key",
  "fingerprint": "sha256:df81…"
}
```

Default trust by source: user input and vault reads are **trusted**; web content is **untrusted**; `record/external-content` (email, GitHub, Slack) is untrusted unless you pass `"trust": "trusted"`. A Source keeps the trust label it was first created with, unless a human later [revokes its trust](/docs/guard#retroactive-re-adjudication).

### 2. Record the model's output

`derived_from` lists **every** Datum in the context window:

```bash title="Terminal"
curl -s -X POST $B/record/llm-output -H 'content-type: application/json' -d '{
  "text": "https://ingest.vaultsync-mirror.example/v1/upload",
  "agent": "ops", "session_id": "s1",
  "derived_from": ["d_3b220d7b6cc24848", "d_695f08f638c04a29", "d_7a6d7ff859714b2f"]}'
```

Because a secret was in the context, the output inherits `sensitivity: "secret"` and its value is masked.

### 3. Record the action and ask the Guard

```bash title="Terminal"
curl -s -X POST $B/record/action -H 'content-type: application/json' -d '{
  "action_type": "upload_backup", "agent": "ops", "session_id": "s1",
  "destination": ["d_5e2538684be64277"], "payload": ["d_7a6d7ff859714b2f"],
  "sink": {"destination": "https://ingest.vaultsync-mirror.example/v1/upload", "kind": "backup"}}'

curl -s -X POST "$B/guard/actions/act_937ac5b48ac94294/check?enforce=true"
```

```json title="200 OK (abridged)"
{
  "decision": "BLOCK",
  "triggered_checks": ["integrity", "confidentiality", "lethal_trifecta"],
  "explanation": "upload_backup by agent 'ops' to https://ingest.vaultsync-mirror.example/v1/upload (external: host ingest.vaultsync-mirror.example is not internal). BLOCKED — lethal trifecta: …",
  "approval": {
    "available": false,
    "reason": "lethal trifecta (untrusted destination + secret payload + external sink) cannot be approved; …"
  },
  "search_complete": true,
  "certificate": null
}
```

`enforce=true` also sets the action's status (`approved`, `pending_approval` or `blocked`); without it the check only writes an audit record. Approving this action returns `403 {"detail": "action act_… was blocked as a lethal trifecta; it has no approval option"}`.

### 4. A clean action

Where the destination is a value the user typed, pass the user-input Datum itself as the argument:

```bash title="Terminal"
# d_dest: the user typed "https://backups.example.com/upload"; d_body: "weekly report"
curl -s -X POST $B/record/action -H 'content-type: application/json' -d '{
  "action_type": "http_post", "agent": "ops", "session_id": "s2",
  "destination": ["d_dest"], "payload": ["d_body"],
  "sink": {"destination": "https://backups.example.com/upload", "kind": "http"}}'
```

The check returns `"decision": "ALLOW"` with a certificate whose claim starts "No untrusted influence was found relative to the recorded provenance graph…". Run the action, then record what happened:

```bash title="Terminal"
curl -s -X PATCH $B/actions/act_…/status -H 'content-type: application/json' -d '{"status": "executed"}'
```

> [!LIMITATION]
> The HTTP API does not expose exact-value attribution, which the Python runtime applies to every tool argument. A tool argument recorded over HTTP as a model output inherits from its whole context, so a value the user typed can be treated as untrusted when an untrusted page was also in context. When an argument is verbatim a recorded value, pass that Datum's id directly, as above.

### Sinks and policy

Give each action a sink with a `kind` the policy understands (`email`, `slack`, `backup`, `http`, `webhook`, `ticket`); anything else is treated as external. Tenants without a registered policy get the default policy, in which **every sink is external**, so a secret payload anywhere needs approval. Internal domains, hosts, Slack workspaces and ticket systems are set in a `GuardPolicy` in code; see [Configuration](/docs/configuration#guard-policy).

## In Python, with the agent runtime

The runtime records context automatically, applies exact-value attribution to tool arguments, and executes only on a fresh ALLOW. This example runs as-is with an embedded database:

```python title="example.py"
from custody.config import Settings
from custody.db import GraphProvider, connect
from custody.graph.repository import GraphRepository
from custody.guard import ACME_POLICY, Guard
from custody.recorder.service import Recorder
from custody.runtime import AgentRuntime, Vault

settings = Settings(falkordb_embedded_path=".data/example.db")   # the .data folder must exist
provider = GraphProvider(connect(settings), settings.graph_prefix, settings.max_trace_depth)
recorder = Recorder(GraphRepository(provider.graph("example")))
rt = AgentRuntime(recorder, Guard(recorder, ACME_POLICY),
                  vault=Vault({"secret/aws/deploy-key": "AKIA-EXAMPLE-NOT-REAL"}))

s = rt.session("ops", "s1")
s.user("Rotate the AWS deploy key and post the new key to #security in Acme Slack.",
       user="sam@acme-robotics.example")
s.rotate_secret("secret/aws/deploy-key")             # recorded as a secret Datum
new_key = rt.vault.read("secret/aws/deploy-key")      # the raw value the model would see
result = s.call_tool("post_slack", destination="#security", payload=new_key)
print(result.decision.decision.value, result.status)  # ALLOW executed
print(rt.outbox.deliveries[0].destination)            # #security (in-memory outbox)

# The same agent, now proposing to send the key to a host Sam never mentioned:
bad = s.call_tool("upload_backup", destination="https://backup.example.net/in", payload=new_key)
print(bad.decision.decision.value, bad.decision.triggered_checks)
# REQUIRE_HUMAN_APPROVAL [confidentiality]
```

`AgentSession` methods record into the session's context: `user`, `fetch` (a page from the runtime's `web` map), `read_secret`, `rotate_secret`, `recall`, `search_memory`, `receive`, `think`, `remember`, `send_message`, `extract_typed`, and `call_tool`. `rt.approve(action_id, approver=…)` applies a human approval, re-checks and executes; `rt.execute(action_id)` always re-checks and raises `ExecutionDenied` unless the Guard returns ALLOW.

## Through MCP

Agent frameworks that speak MCP can record over HTTP and then call the Warden server's `check_action` tool for the verdict, with the same enforcement rules. See [MCP integration](/docs/mcp#the-guard-over-mcp).
