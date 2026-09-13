# VisLineage

[![CI](https://github.com/LatticeAG/vislineage/actions/workflows/ci.yml/badge.svg)](https://github.com/LatticeAG/vislineage/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-22%2B-blue.svg)](package.json)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)
[![Protocol](https://img.shields.io/badge/protocol-vislineage%2F1-blue.svg)](#what-it-is)

**VisLineage** is the LatticeAG export-scoped lineage joiner. It imports
LangSmith, Langfuse, and Braintrust export files, preserves source-scoped
identities verbatim, joins steps across providers only on explicit delegation
evidence, computes bounded lineage paths, and produces proof bundles that
verify fully offline against an independently supplied trust package.
Everything is local: the durable store is SQLite, evidence is canonical JSON
under domain-separated SHA-256, and verification is pure.

> A VisLineage path means exactly this: **"these records were exported, these
> delegation claims were made, and this evidence verifies under these pins."**
> It does not establish causal completeness outside the disclosed exports,
> does not verify real-world behavior, does not enforce policy, and does not
> grant execution authority. Evidence labels are explicit: paths are
> `CLAIMED`, disclosure is `NORMALIZED_ONLY`, semantics are `NOT_VERIFIED`,
> and `current_authority` is always `UNKNOWN`.

## What it is

- **Import profiles** — `langsmith-runs/1`, `langfuse-observations/1`,
  `braintrust-spans/1`. Native containment (LangSmith `parent_run_id`,
  Langfuse `parentObservationId`, Braintrust `span_parents`) is preserved as
  native-parent evidence and is *never* treated as cross-source delegation.
- **Delegation joins** — a `DELEGATES` edge requires an exact, unique
  offer/accept pair: matching delegation id, child source, child agent,
  scope digest, and a parent bound by `(source, record, hash)`. Reused
  delegation ids suppress all candidate edges and surface
  `DELEGATION_REUSED`.
- **No inference** — timestamps, display names, shared native trace labels,
  and ordering never create edges. Conflicts, cycles, and ambiguous parents
  are retained as explicit gap evidence, not silently resolved.
- **Bounded paths** — `path.get` returns the action's ancestor subgraph
  within `max_depth`/`max_nodes`, with `PATH_LIMIT` errors rather than
  truncation.
- **Trust** — Ed25519 origin/audit chains evaluated against scoped key pins
  and head pins from a caller-supplied TrustPackage. Small-order keys,
  noncanonical `S`, and bundle-provided keys earn nothing. Origin and audit
  verdicts are independent dimensions.
- **Export-only** — no provider URL fetching, no token minting, no action
  dispatch, no Treaty operations, no live subscriptions, no remote SQL.

## Layout

- `packages/core` — strict JSON parser (duplicate members, noncanonical
  numbers, UTF-8, depth/size caps), JCS canonicalization, domain-separated
  hashing, Ed25519 strictness, closed-object schemas, the three import
  normalizers, the deterministic reducer, bounded path computation,
  scoped-pin trust evaluation, bundle build + offline verify.
- `packages/sqlite` — `WorkspaceService`: the 11-method RPC surface,
  durable stage/commit/cancel transactions, revision pinning, idempotency,
  append-only signed audit chain, artifact store, recovery-pin
  reconciliation, backup/restore/prune/migrate/doctor/key-rotate.
- `packages/cli` — the `vislineage` command frontend (`--json`, spec exit
  codes) and the authenticated `serve` HTTP surface.
- `python/vislineage` — the independent offline verifier: strict parser,
  canonicalizer, Ed25519, reduction, trust evaluation, exit codes.
- `schemas/` — the machine-readable JSON Schema registry (`generate.mjs`
  regenerates it).
- `tests/` — the TV-V-01 … TV-V-42 conformance vectors, RPC contract
  round-trips, and operational/security gate tests.

## Develop

```sh
npm ci && npm test              # TypeScript build + conformance/gate suite
python3 -m pytest python/tests -q   # Python verifier parity suite
node schemas/generate.mjs       # regenerate the schema registry
```

Quick start:

```sh
export VISLINEAGE_AUDIT_SEED=<64 lowercase hex chars>
export VISLINEAGE_ADMIN_TOKEN=<bearer token>
vislineage init --workspace vlw_… --db ./state/lineage.sqlite --key-env VISLINEAGE_AUDIT_SEED
vislineage source add --id vls_… --profile langsmith-runs/1 --namespace acme --project agent
vislineage trace create --id vlt_…
vislineage import stage --id vli_… --source vls_… --trace vlt_… --file export.jsonl
vislineage import commit --id vli_… --expected-revision 0
vislineage path --trace vlt_… --revision 1 --source vls_… --record <record>
vislineage export --trace vlt_… --revision 1 --source vls_… --record <record> --out bundle.json
vislineage verify --bundle bundle.json --trust trust.json   # or: python3 -m vislineage verify …
```

The CLI lifecycle (`init` → `source add` → `trace create` →
`import stage`/`commit` → `path` → `export` → `verify`) runs entirely
against local files; `doctor --deep --json` reports store and chain health.

## Protocol

`vislineage/1`, schema `1`, implementation `0.1.0`. Canonical form is
RFC 8785-style JCS; evidence digests are `H(tag ‖ 0x00 ‖ JCS(value))` under
the `VL-*/1` domain tags. Fixture seeds (`hex 11/22/33/44` repeated) are
test-only and rejected by production config.
