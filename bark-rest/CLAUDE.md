# bark-rest OpenAPI documentation

Rules for writing utoipa OpenAPI annotations (`summary` and `description`
fields) in `bark-rest/src/`.

For terminology, formatting, and general writing conventions, see
`contrib/agents/skills/documentation.md`.

## Architecture notes

- The daemon (`bark/src/daemon.rs`) runs alongside the REST server in barkd.
  They share the same `Arc<Wallet>` and therefore the same exit state.
- The daemon auto-progresses exits at the cadence defined by `SLOW_INTERVAL`
  in `bark/src/daemon.rs`.
- The daemon does **not** auto-claim—`claim` must be called via the API.
- `ExitProgressResponse.done` becomes `true` when all exits reach the
  `Claimable` state (i.e. `has_pending_exits()` returns `false`).

## Summaries

Summaries appear as page titles and sidebar entries in Mintlify. Keep them
short and descriptive—typically 2–5 words. They should read as imperative
phrases (e.g. "Get exit status", "Board a specific amount").

## Descriptions

- **Self-contained**: Each endpoint's description should stand on its own.
  Repeat information rather than cross-referencing other endpoints (e.g.
  "same detail as the single VTXO endpoint"). A developer reading one page
  should not need to visit another to understand what the endpoint returns.
- **Accurate**: Read the source code before writing a description. Understand
  what the endpoint actually does, what it triggers, and what side effects
  follow. Do not describe the endpoint in isolation if its action causes
  automated follow-up behaviour (e.g. the daemon progressing exits).
- **Concise**: Cover what the endpoint does and what the developer needs to
  know to use it. Do not repeat information that is already well-covered in
  another endpoint's description unless self-containment requires it.
- **Daemon awareness**: Where the daemon automates behaviour (e.g. exit
  progression), say so and reference the interval constant (e.g.
  `SLOW_INTERVAL`) rather than hardcoding a duration that may go stale.

## Regenerating the OpenAPI spec

Before pushing any changes that touch `bark-rest/src/`, regenerate the OpenAPI
spec and client:

```bash
just generate-bark-rest-client
```

This dumps `bark-rest/openapi.json` and regenerates the `bark-rest-client`
crate from it. CI will fail if either is out of sync with the code. Always
stage the regenerated files alongside your source changes.
