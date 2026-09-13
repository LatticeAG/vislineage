// Generates the machine-readable schema registry (§13) as JSON Schema
// draft 2020-12 documents. Bounds mirror packages/core/src/schema.ts exactly.
// Run: node schemas/generate.mjs  (writes into schemas/, then diff/commit).
import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const dir = path.dirname(fileURLToPath(import.meta.url));

const id = (prefix) => ({ type: "string", pattern: `^${prefix}_[-_0-9A-Za-z]{21}$` });
const HASH = { type: "string", pattern: "^[0-9a-f]{64}$" };
const COUNTER = { type: "string", pattern: "^(0|[1-9][0-9]*)$" };
const TEXT = {
  type: "string",
  minLength: 1,
  maxLength: 256,
  pattern: "^[^\\u0000-\\u001f\\u007f]+$",
  description: "Text: 1-256 Unicode scalars, <=1024 UTF-8 bytes, no C0/DEL controls",
};
const B64URL = { type: "string", pattern: "^[A-Za-z0-9_-]+$" };
const SIG = { ...B64URL, description: "Ed25519 signature, 64 bytes, base64url" };
const PUB = { ...B64URL, description: "Ed25519 public key, 32 bytes, base64url" };
const V1 = { const: 1 };

const AGENT = {
  type: "object",
  additionalProperties: false,
  required: ["namespace", "subject", "principal"],
  properties: {
    namespace: { type: "string", pattern: "^[a-z][a-z0-9.-]{0,63}$" },
    subject: TEXT,
    principal: { anyOf: [TEXT, { type: "null" }] },
  },
};
const POLICY = {
  type: "object",
  additionalProperties: false,
  required: ["digest", "version", "decision"],
  properties: {
    digest: HASH,
    version: TEXT,
    decision: { enum: ["ALLOW", "REVIEW", "DENY", "UNKNOWN"] },
  },
};
const NATIVE_PARENT = {
  type: "object",
  additionalProperties: false,
  required: ["kind", "value"],
  properties: { kind: { enum: ["record", "span"] }, value: TEXT },
};
const STEP_REF = {
  type: "object",
  additionalProperties: false,
  required: ["source", "record", "hash"],
  properties: { source: id("vls"), record: TEXT, hash: HASH },
};
const OFFER = {
  type: "object",
  additionalProperties: false,
  required: ["id", "child_source", "child_agent", "scope"],
  properties: { id: id("vld"), child_source: id("vls"), child_agent: AGENT, scope: HASH },
};
const ACCEPT = {
  type: "object",
  additionalProperties: false,
  required: ["id", "parent", "scope"],
  properties: { id: id("vld"), parent: STEP_REF, scope: HASH },
};
const ATTACHMENT_REF = {
  type: "object",
  additionalProperties: false,
  required: ["digest", "format", "bytes"],
  properties: { digest: HASH, format: TEXT, bytes: COUNTER },
};
const PROFILE = {
  enum: ["langsmith-runs/1", "langfuse-observations/1", "braintrust-spans/1"],
};
const STEP_BODY = {
  type: "object",
  additionalProperties: false,
  required: [
    "v", "workspace", "trace", "source", "profile", "record", "native_trace",
    "native_span", "parents", "agent", "policy", "offers", "accept", "attachments",
  ],
  properties: {
    v: V1,
    workspace: id("vlw"),
    trace: id("vlt"),
    source: id("vls"),
    profile: PROFILE,
    record: TEXT,
    native_trace: TEXT,
    native_span: TEXT,
    parents: { type: "array", maxItems: 16, uniqueItems: true, items: NATIVE_PARENT },
    agent: { anyOf: [AGENT, { type: "null" }] },
    policy: { anyOf: [POLICY, { type: "null" }] },
    offers: { type: "array", maxItems: 32, items: OFFER },
    accept: { anyOf: [ACCEPT, { type: "null" }] },
    attachments: { type: "array", maxItems: 16, items: ATTACHMENT_REF },
  },
};
const STEP = {
  type: "object",
  additionalProperties: false,
  required: ["body", "hash"],
  properties: { body: STEP_BODY, hash: HASH },
};
const ORIGIN_BODY = {
  type: "object",
  additionalProperties: false,
  required: ["v", "workspace", "source", "stream", "seq", "prev", "step", "key"],
  properties: {
    v: V1,
    workspace: id("vlw"),
    source: id("vls"),
    stream: TEXT,
    seq: COUNTER,
    prev: HASH,
    step: HASH,
    key: id("vlk"),
  },
};
const ORIGIN = {
  type: "object",
  additionalProperties: false,
  required: ["body", "hash", "signature"],
  properties: { body: ORIGIN_BODY, hash: HASH, signature: SIG },
};
const SOURCE = {
  type: "object",
  additionalProperties: false,
  required: ["id", "profile", "namespace", "project"],
  properties: { id: id("vls"), profile: PROFILE, namespace: TEXT, project: TEXT },
};
const AUDIT_DATA = {
  type: "object",
  required: ["kind"],
  properties: {
    kind: {
      enum: [
        "WorkspaceCreated", "SourceRegistered", "TraceCreated", "ImportStaged",
        "ImportCommitted", "ImportCancelled", "RetentionPruned", "KeyRotated",
      ],
    },
  },
  description:
    "Closed tagged union on `kind` — see packages/core/src/schema.ts auditData() " +
    "for each variant's exact member set",
};
const AUDIT_BODY = {
  type: "object",
  additionalProperties: false,
  required: ["v", "workspace", "seq", "prev", "request", "key", "data"],
  properties: {
    v: V1,
    workspace: id("vlw"),
    seq: COUNTER,
    prev: HASH,
    request: id("vlq"),
    key: id("vlk"),
    data: AUDIT_DATA,
  },
};
const AUDIT = {
  type: "object",
  additionalProperties: false,
  required: ["body", "hash", "signature"],
  properties: { body: AUDIT_BODY, hash: HASH, signature: SIG },
};
const EDGE_BODY = {
  type: "object",
  additionalProperties: false,
  required: ["v", "trace", "parent", "child", "kind", "delegation", "scope"],
  properties: {
    v: V1,
    trace: id("vlt"),
    parent: HASH,
    child: HASH,
    kind: { enum: ["NATIVE_PARENT", "DELEGATES"] },
    delegation: { anyOf: [id("vld"), { type: "null" }] },
    scope: { anyOf: [HASH, { type: "null" }] },
  },
};
const EDGE = {
  type: "object",
  additionalProperties: false,
  required: ["body", "hash"],
  properties: { body: EDGE_BODY, hash: HASH },
};
const GAP = {
  type: "object",
  additionalProperties: false,
  required: ["code", "subject", "related"],
  properties: {
    code: {
      enum: [
        "PARENT_MISSING", "PARENT_AMBIGUOUS", "OFFER_MISSING", "ACCEPT_MISSING",
        "DELEGATION_MISMATCH", "PARENT_HASH_MISMATCH", "DELEGATION_REUSED",
        "SOURCE_CONFLICT", "CYCLE", "ORIGIN_GAP", "ORIGIN_FORK",
      ],
    },
    subject: HASH,
    related: { type: "array", items: HASH },
  },
};
const ARTIFACT = {
  type: "object",
  additionalProperties: false,
  required: ["digest", "format", "bytes", "content"],
  properties: { digest: HASH, format: TEXT, bytes: COUNTER, content: B64URL },
};
const PATH_REQUEST = {
  type: "object",
  additionalProperties: false,
  required: ["trace", "revision", "action", "max_depth", "max_nodes"],
  properties: {
    trace: id("vlt"),
    revision: COUNTER,
    action: {
      type: "object",
      additionalProperties: false,
      required: ["source", "record"],
      properties: { source: id("vls"), record: TEXT },
    },
    max_depth: { type: "integer", minimum: 1, maximum: 256 },
    max_nodes: { type: "integer", minimum: 1, maximum: 4096 },
  },
};
const PATH_RESULT = {
  type: "object",
  additionalProperties: false,
  required: [
    "trace", "revision", "graph", "action", "steps", "origins", "edges",
    "gaps", "structural", "evidence", "disclosure",
  ],
  properties: {
    trace: id("vlt"),
    revision: COUNTER,
    graph: HASH,
    action: HASH,
    steps: { type: "array", maxItems: 4096, items: STEP },
    origins: { type: "array", maxItems: 100000, items: ORIGIN },
    edges: { type: "array", maxItems: 16384, items: EDGE },
    gaps: { type: "array", maxItems: 100000, items: GAP },
    structural: { enum: ["COMPLETE_RELATIVE", "INCOMPLETE", "CONFLICTED"] },
    evidence: { const: "CLAIMED" },
    disclosure: { const: "NORMALIZED_ONLY" },
  },
};
const KEY_PIN = {
  type: "object",
  additionalProperties: false,
  required: ["id", "public", "role", "workspace", "source", "stream", "first_seq", "last_seq", "status"],
  properties: {
    id: id("vlk"),
    public: PUB,
    role: { enum: ["origin", "audit"] },
    workspace: id("vlw"),
    source: { anyOf: [id("vls"), { type: "null" }] },
    stream: { anyOf: [TEXT, { type: "null" }] },
    first_seq: COUNTER,
    last_seq: COUNTER,
    status: { enum: ["ACTIVE", "RETIRED", "COMPROMISED"] },
  },
};
const HEAD_PIN = {
  type: "object",
  additionalProperties: false,
  required: ["role", "source", "stream", "seq", "hash"],
  properties: {
    role: { enum: ["origin", "audit"] },
    source: { anyOf: [id("vls"), { type: "null" }] },
    stream: { anyOf: [TEXT, { type: "null" }] },
    seq: COUNTER,
    hash: HASH,
  },
};
const TRUST_PACKAGE = {
  type: "object",
  additionalProperties: false,
  required: ["v", "workspace", "keys", "heads"],
  properties: {
    v: V1,
    workspace: id("vlw"),
    keys: { type: "array", items: KEY_PIN },
    heads: { type: "array", items: HEAD_PIN },
  },
  description:
    "Pin-consistency rules (no duplicate key ids, no key reuse across roles, " +
    "no overlapping seq intervals per scope, no conflicting head pins) are " +
    "normative but not expressible in JSON Schema — see validateTrust().",
};
const INVENTORY_ITEM = {
  type: "object",
  additionalProperties: false,
  required: ["kind", "digest", "bytes"],
  properties: {
    kind: { enum: ["step", "origin", "audit", "attachment"] },
    digest: HASH,
    bytes: COUNTER,
  },
};
const GRAPH_MANIFEST = {
  type: "object",
  additionalProperties: false,
  required: ["v", "workspace", "trace", "steps", "origins", "edges", "gaps"],
  properties: {
    v: V1,
    workspace: id("vlw"),
    trace: id("vlt"),
    steps: { type: "array", maxItems: 100000, items: HASH },
    origins: { type: "array", maxItems: 100000, items: HASH },
    edges: { type: "array", maxItems: 400000, items: HASH },
    gaps: { type: "array", maxItems: 400000, items: GAP },
  },
};
const BUNDLE_BODY = {
  type: "object",
  additionalProperties: false,
  required: [
    "v", "format", "workspace", "trace", "revision", "graph", "path_request",
    "path", "inventory", "attachment_policy", "disclosure", "trust_required",
  ],
  properties: {
    v: V1,
    format: { const: "vislineage-bundle/1" },
    workspace: id("vlw"),
    trace: id("vlt"),
    revision: COUNTER,
    graph: GRAPH_MANIFEST,
    path_request: PATH_REQUEST,
    path: PATH_RESULT,
    inventory: { type: "array", maxItems: 400000, items: INVENTORY_ITEM },
    attachment_policy: { enum: ["INCLUDE", "OMIT"] },
    disclosure: { const: "NORMALIZED_ONLY" },
    trust_required: { const: true },
  },
};
const BUNDLE = {
  type: "object",
  additionalProperties: false,
  required: ["body", "hash", "steps", "origins", "audit", "attachments"],
  properties: {
    body: BUNDLE_BODY,
    hash: HASH,
    steps: { type: "array", maxItems: 100000, items: STEP },
    origins: { type: "array", maxItems: 100000, items: ORIGIN },
    audit: { type: "array", maxItems: 100000, items: AUDIT },
    attachments: { type: "array", maxItems: 100000, items: ARTIFACT },
  },
};
const EXTERNAL_HEAD = {
  type: "object",
  additionalProperties: false,
  required: ["v", "workspace", "seq", "hash"],
  properties: { v: V1, workspace: id("vlw"), seq: COUNTER, hash: HASH },
};
const SUNLIGHT_HANDOFF = {
  type: "object",
  additionalProperties: false,
  required: ["v", "kind", "format", "bundle", "action", "trace", "graph", "disclosure", "semantics"],
  properties: {
    v: V1,
    kind: { const: "action-lineage" },
    format: { const: "vislineage-bundle/1" },
    bundle: HASH,
    action: HASH,
    trace: id("vlt"),
    graph: HASH,
    disclosure: { const: "NORMALIZED_ONLY" },
    semantics: { const: "NOT_VERIFIED" },
  },
};
const VERIFICATION = {
  type: "object",
  additionalProperties: false,
  required: [
    "integrity", "structural", "origin", "audit", "disclosure", "semantics",
    "current_authority", "reasons",
  ],
  properties: {
    integrity: { enum: ["VALID", "INVALID"] },
    structural: { enum: ["COMPLETE_RELATIVE", "INCOMPLETE", "CONFLICTED"] },
    origin: { enum: ["TRUSTED_AT_PIN", "UNSIGNED", "UNTRUSTED", "INCOMPLETE", "CONFLICTED"] },
    audit: { enum: ["TRUSTED_AT_PIN", "UNTRUSTED", "INCOMPLETE"] },
    disclosure: { const: "NORMALIZED_ONLY" },
    semantics: { const: "NOT_VERIFIED" },
    current_authority: { const: "UNKNOWN" },
    reasons: { type: "array", items: { type: "string" } },
  },
};
const RPC_REQUEST = {
  type: "object",
  additionalProperties: false,
  required: ["id", "method", "params"],
  properties: {
    id: id("vlq"),
    method: {
      enum: [
        "source.register", "source.list", "trace.create", "trace.get",
        "import.stage", "import.get", "import.commit", "import.cancel",
        "path.get", "bundle.export", "bundle.verify",
      ],
    },
    params: { type: "object" },
  },
};
const RPC_ERROR = {
  type: "object",
  additionalProperties: false,
  required: ["code", "retryable", "details"],
  properties: {
    code: TEXT,
    retryable: { type: "boolean" },
    details: { type: ["object", "null"] },
  },
};
const BACKUP_MANIFEST = {
  type: "object",
  additionalProperties: false,
  required: ["v", "workspace", "schema", "head", "files"],
  properties: {
    v: V1,
    workspace: id("vlw"),
    schema: { type: "integer", minimum: 1 },
    head: {
      type: "object",
      additionalProperties: false,
      required: ["seq", "hash"],
      properties: { seq: COUNTER, hash: HASH },
    },
    files: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["path", "bytes", "digest"],
        properties: {
          path: { type: "string", minLength: 1, maxLength: 512 },
          bytes: COUNTER,
          digest: HASH,
        },
      },
    },
  },
};
const TRUST_UPDATE = {
  type: "object",
  additionalProperties: false,
  required: ["v", "workspace", "retire", "activate"],
  properties: {
    v: V1,
    workspace: id("vlw"),
    retire: {
      type: "object",
      additionalProperties: false,
      required: ["id", "last_seq"],
      properties: { id: id("vlk"), last_seq: COUNTER },
    },
    activate: {
      type: "object",
      additionalProperties: false,
      required: ["id", "public", "first_seq"],
      properties: { id: id("vlk"), public: PUB, first_seq: COUNTER },
    },
  },
};
const CONFIG = {
  type: "object",
  additionalProperties: false,
  required: [
    "version", "workspace", "database", "artifacts", "audit_key_id", "audit_key_env",
    "bind", "port", "auth", "retention", "limits", "observability", "recovery_pin",
  ],
  properties: {
    version: { const: 1 },
    workspace: id("vlw"),
    database: TEXT,
    artifacts: TEXT,
    audit_key_id: id("vlk"),
    audit_key_env: { type: "string", pattern: "^[A-Z][A-Z0-9_]{0,63}$" },
    bind: TEXT,
    port: { type: "integer", minimum: 1, maximum: 65535 },
    auth: {
      type: "object",
      additionalProperties: false,
      required: ["token_env", "roles"],
      properties: {
        token_env: { type: "string", pattern: "^[A-Z][A-Z0-9_]{0,63}$" },
        roles: { type: "array", minItems: 1, items: { enum: ["read", "write", "admin"] } },
      },
    },
    retention: {
      type: "object",
      additionalProperties: false,
      required: ["stage_ttl_seconds", "history_revisions", "artifacts_days"],
      properties: {
        stage_ttl_seconds: { type: "integer", minimum: 60, maximum: 604800 },
        history_revisions: { type: "integer", minimum: 1, maximum: 10000 },
        artifacts_days: { type: "integer", minimum: 1, maximum: 3650 },
      },
    },
    limits: {
      type: "object",
      additionalProperties: false,
      required: ["stage_rows", "request_bytes", "path_nodes", "bundle_bytes"],
      properties: {
        stage_rows: { type: "integer", minimum: 1, maximum: 1000 },
        request_bytes: { type: "integer", minimum: 4096, maximum: 8388608 },
        path_nodes: { type: "integer", minimum: 1, maximum: 4096 },
        bundle_bytes: { type: "integer", minimum: 4096, maximum: 67108864 },
      },
    },
    observability: {
      type: "object",
      additionalProperties: false,
      required: ["level", "metrics_socket"],
      properties: {
        level: { enum: ["error", "warn", "info"] },
        metrics_socket: TEXT,
      },
    },
    recovery_pin: TEXT,
  },
};

const SCHEMAS = {
  "step.schema.json": STEP,
  "origin.schema.json": ORIGIN,
  "audit.schema.json": AUDIT,
  "edge.schema.json": EDGE,
  "gap.schema.json": GAP,
  "graph-manifest.schema.json": GRAPH_MANIFEST,
  "path-request.schema.json": PATH_REQUEST,
  "path-result.schema.json": PATH_RESULT,
  "bundle.schema.json": BUNDLE,
  "trust-package.schema.json": TRUST_PACKAGE,
  "trust-update.schema.json": TRUST_UPDATE,
  "external-head.schema.json": EXTERNAL_HEAD,
  "sunlight-handoff.schema.json": SUNLIGHT_HANDOFF,
  "verification.schema.json": VERIFICATION,
  "rpc-request.schema.json": RPC_REQUEST,
  "rpc-error.schema.json": RPC_ERROR,
  "backup-manifest.schema.json": BACKUP_MANIFEST,
  "config.schema.json": CONFIG,
};

mkdirSync(dir, { recursive: true });
const index = { registry: "vislineage/1", files: [] };
for (const [name, schema] of Object.entries(SCHEMAS)) {
  const doc = {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: `https://latticeag.dev/schemas/vislineage/${name}`,
    ...schema,
  };
  writeFileSync(path.join(dir, name), JSON.stringify(doc, null, 2) + "\n");
  index.files.push(name);
}
writeFileSync(path.join(dir, "index.json"), JSON.stringify(index, null, 2) + "\n");
console.log(`wrote ${index.files.length + 1} files to ${dir}`);
