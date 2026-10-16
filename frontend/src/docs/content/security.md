# Security model

What Custody defends against, what it assumes, and where it stops. Read this before relying on a verdict.

## The threat

An attacker controls the content of untrusted sources (web pages, inbound email, GitHub issues, shared Slack channels) and can make a model write anything into memory or into tool arguments. The goal is to get an agent, possibly a different one in a later session, to send data somewhere it should not go or to perform an irreversible action with attacker-chosen parameters.

## In scope

- **Explicit data flow that the runtime records**: user messages, web pages, email, vault reads, model outputs, memories, recalls and inter-agent messages, across any number of sessions and agents.
- **Untrusted destinations** (integrity), **secret payloads to external sinks** (confidentiality), and the combination of both (the lethal trifecta), checked before every outbound or irreversible action.
- **Sink classification by tenant policy**, failing closed: unknown sink kinds, unparseable destinations and look-alike domains are external.
- **Laundering through memory and messages**: one traversal follows data through saves, recalls and messages with no depth bound, and an incomplete search never yields ALLOW.
- **The Warden as a target**: its tool results may contain attacker text; its actions pass the Guard, it cannot approve anything, and loosening remediations always wait for a human.

## Assumptions

> [!WARNING]
> **The recording is complete.** Each output must be linked to every Datum that was in its context. The Python runtime does this automatically; an integration over HTTP or MCP must do it itself. If a context item is left out, a dangerous path can be missing from the graph and the Guard can return ALLOW. Every answer, including an ALLOW certificate, is relative to the recorded graph and the current trust labels; it never shows that an action is safe.

- **Trust labels are correct.** `trusted` and `untrusted` on Sources are policy inputs set by whoever records them (users and the vault are trusted by default, web and external content untrusted). Custody does not infer them. Certificates list every root with its label so a reviewer can audit the assumption, and a label found to be wrong can be revoked, which re-runs the Guard on downstream actions ([retroactive re-adjudication](/docs/guard#retroactive-re-adjudication)).
- **Approvers are humans authenticated outside Custody.** The Guard's approve, reject and endorse refuse empty names, names starting with `system:` and non-human approver kinds (the Warden's wrappers also refuse `warden`), but Custody has no login, so it cannot tell who typed a name.
- **Only trusted integrators can write approvals directly.** The Recorder endpoints `POST …/record/approval` and `PATCH …/actions/{id}/status` write approvals and statuses without those guardrails (or the lethal-trifecta and `INDETERMINATE` refusals). Public-demo mode blocks them; otherwise keep them away from agents.
- **The caller enforces the verdict.** The in-process runtime executes only on ALLOW. Over HTTP and MCP, Custody only answers.

## Out of scope

- **Implicit flows.** If untrusted content convinces a model to _choose_ between values a trusted source supplied (say `#security` over `#general`, both typed by the user), the graph sees a trusted value and the Guard trusts it. Exact-value attribution relies on this boundary on purpose: without it, label creep would make every value untrusted within a few turns.
- **Timing and other side channels.**
- **Influence that never passes through the recorder**, such as a model's training data or a tool that fetches content without recording it.
- **Precision.** The recording rule over-approximates: every output derives from everything in its context, so a value can be flagged although the untrusted or secret input did not shape it (for example, an agent summary written while a key was in context is treated as secret). Custody prefers false alarms to missed paths; exact-value attribution narrows this only for values that a trusted Datum supplied verbatim.
- **Authentication, authorisation and multi-tenant access control** for the API and console.
- **Executing side effects.** Custody ships no connectors to real services; the runtime delivers to an in-memory outbox.

## Failure behaviour

| Situation                                                                       | Result                                                                                                                            |
| ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Provenance search hits its node, time or depth limit, or a query fails          | `INDETERMINATE` → never ALLOW; BLOCK if a lethal trifecta cannot be ruled out                                                     |
| Sink kind unknown, destination unparseable, tenant without a policy             | sink treated as external                                                                                                          |
| Action type unknown to the policy                                               | treated as outbound, irreversible and high risk                                                                                   |
| Graph changes during a check                                                    | the ALLOW certificate is withheld (the verdict stands)                                                                            |
| `GRAPH.COPY` refused by the server                                              | Warden simulations run on a read-only proxy of the live graph and say so                                                          |
| Secret-egress endorsement applies but the confidentiality search was incomplete | an internal error (HTTP 500) instead of a verdict; never ALLOW (known defect: the endorsement does not check search completeness) |
| Forward search for a trust revocation incomplete                                | the re-adjudication report is refused, but the revocation stays                                                                   |

Fail-closed behaviour has a cost: on very large ancestries a check that cannot finish within its 2 s budget holds or blocks an action that may be fine. See [Benchmarks](/docs/benchmarks#scaling-and-a-falsified-target).

## What is real in the demo

> [!REAL]
> The provenance recording, the FalkorDB graph, every Guard verdict, explanation and certificate, the Warden's graph queries, algorithms and sandboxes, and the approvals and rejections written to the graph.

> [!SIMULATED]
> Acme Robotics and its people; the vendor page, Slack, email, the vault and the attacker's upload server (in-process, no network); the simulated days; the scripted agent outputs; and "sending", which delivers to an in-memory outbox.

## Running it safely

- Do not expose a normal-mode deployment without your own authentication in front of it. Anyone who can reach it can approve actions under any name, or write approvals and action statuses through the Recorder endpoints.
- For a public link, use [public-demo mode](/docs/deployment#public-demo-mode) on its own database. It refuses every write except the demo reset, but it is not abuse protection.
- Keep `ANTHROPIC_API_KEY` off public deployments.
- Secrets are masked in the graph (`preview` and a SHA-256 fingerprint only), but other recorded content is stored as given. Treat the graph as sensitive.
