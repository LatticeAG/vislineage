/** Normative JSON IDL types for vislineage/1 (spec §3.1+). */

export type Hash = string;
export type Counter = string;
export type WorkspaceId = string;
export type SourceId = string;
export type TraceId = string;
export type ImportId = string;
export type RequestId = string;
export type DelegationId = string;
export type KeyId = string;
export type Signature = string;
export type PublicKey = string;
export type Text = string;
export type Profile = "langsmith-runs/1" | "langfuse-observations/1" | "braintrust-spans/1";
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type VendorRow = { [key: string]: Json };

export type Agent = { namespace: Text; subject: Text; principal: Text | null };
export type SourceRef = { source: SourceId; record: Text };
export type StepRef = { source: SourceId; record: Text; hash: Hash };
export type NativeParent = { kind: "record" | "span"; value: Text };
export type Policy = { digest: Hash; version: Text; decision: "ALLOW" | "REVIEW" | "DENY" | "UNKNOWN" };
export type Offer = { id: DelegationId; child_source: SourceId; child_agent: Agent; scope: Hash };
export type Accept = { id: DelegationId; parent: StepRef; scope: Hash };
export type AttachmentRef = { digest: Hash; format: Text; bytes: Counter };

export type LineageMetadata = {
  v: 1;
  trace_id: TraceId;
  agent: Agent | null;
  policy: Policy | null;
  offers: Offer[];
  accept: Accept | null;
  attachments: AttachmentRef[];
};

export type StepBody = {
  v: 1;
  workspace: WorkspaceId;
  trace: TraceId;
  source: SourceId;
  profile: Profile;
  record: Text;
  native_trace: Text;
  native_span: Text;
  parents: NativeParent[];
  agent: Agent | null;
  policy: Policy | null;
  offers: Offer[];
  accept: Accept | null;
  attachments: AttachmentRef[];
};

export type Step = { body: StepBody; hash: Hash };

export type OriginBody = {
  v: 1;
  workspace: WorkspaceId;
  source: SourceId;
  stream: Text;
  seq: Counter;
  prev: Hash;
  step: Hash;
  key: KeyId;
};
export type Origin = { body: OriginBody; hash: Hash; signature: Signature };

export type Artifact = { digest: Hash; format: Text; bytes: Counter; content: string };
export type Source = { id: SourceId; profile: Profile; namespace: Text; project: Text };
export type Trace = { id: TraceId; revision: Counter; graph: Hash };

export type EdgeKind = "NATIVE_PARENT" | "DELEGATES";
export type EdgeBody = {
  v: 1;
  trace: TraceId;
  parent: Hash;
  child: Hash;
  kind: EdgeKind;
  delegation: DelegationId | null;
  scope: Hash | null;
};
export type Edge = { body: EdgeBody; hash: Hash };

export type GapCode =
  | "PARENT_MISSING"
  | "PARENT_AMBIGUOUS"
  | "OFFER_MISSING"
  | "ACCEPT_MISSING"
  | "DELEGATION_MISMATCH"
  | "PARENT_HASH_MISMATCH"
  | "DELEGATION_REUSED"
  | "SOURCE_CONFLICT"
  | "CYCLE"
  | "ORIGIN_GAP"
  | "ORIGIN_FORK";

export type Gap = { code: GapCode; subject: Hash; related: Hash[] };

export type GraphManifest = {
  v: 1;
  workspace: WorkspaceId;
  trace: TraceId;
  steps: Hash[];
  origins: Hash[];
  edges: Hash[];
  gaps: Gap[];
};

export type PathRequest = {
  trace: TraceId;
  revision: Counter;
  action: SourceRef;
  max_depth: number;
  max_nodes: number;
};

export type PathResult = {
  trace: TraceId;
  revision: Counter;
  graph: Hash;
  action: Hash;
  steps: Step[];
  origins: Origin[];
  edges: Edge[];
  gaps: Gap[];
  structural: "COMPLETE_RELATIVE" | "INCOMPLETE" | "CONFLICTED";
  evidence: "CLAIMED";
  disclosure: "NORMALIZED_ONLY";
};

export type AuditData =
  | { kind: "WorkspaceCreated"; config: Hash }
  | { kind: "SourceRegistered"; source: Source }
  | { kind: "TraceCreated"; trace: TraceId; graph: Hash }
  | { kind: "ImportStaged"; import: ImportId; trace: TraceId; batch: Hash; rows: number }
  | { kind: "ImportCommitted"; import: ImportId; trace: TraceId; revision: Counter; graph: Hash; batch: Hash }
  | { kind: "ImportCancelled"; import: ImportId; reason: "USER" | "EXPIRED" }
  | { kind: "RetentionPruned"; traces: { trace: TraceId; revisions: Counter[] }[]; artifacts: Hash[] }
  | { kind: "KeyRotated"; old: KeyId; next: KeyId; next_public: PublicKey };

export type AuditBody = {
  v: 1;
  workspace: WorkspaceId;
  seq: Counter;
  prev: Hash;
  request: RequestId;
  key: KeyId;
  data: AuditData;
};
export type Audit = { body: AuditBody; hash: Hash; signature: Signature };

export type KeyPin = {
  id: KeyId;
  public: PublicKey;
  role: "origin" | "audit";
  workspace: WorkspaceId;
  source: SourceId | null;
  stream: Text | null;
  first_seq: Counter;
  last_seq: Counter;
  status: "ACTIVE" | "RETIRED" | "COMPROMISED";
};
export type HeadPin = { role: "origin" | "audit"; source: SourceId | null; stream: Text | null; seq: Counter; hash: Hash };
export type TrustPackage = { v: 1; workspace: WorkspaceId; keys: KeyPin[]; heads: HeadPin[] };

export type Verification = {
  integrity: "VALID" | "INVALID";
  structural: "COMPLETE_RELATIVE" | "INCOMPLETE" | "CONFLICTED";
  origin: "TRUSTED_AT_PIN" | "UNSIGNED" | "UNTRUSTED" | "INCOMPLETE" | "CONFLICTED";
  audit: "TRUSTED_AT_PIN" | "UNTRUSTED" | "INCOMPLETE";
  disclosure: "NORMALIZED_ONLY";
  semantics: "NOT_VERIFIED";
  current_authority: "UNKNOWN";
  reasons: Text[];
};

export type InventoryItem = { kind: "step" | "origin" | "audit" | "attachment"; digest: Hash; bytes: Counter };

export type BundleBody = {
  v: 1;
  format: "vislineage-bundle/1";
  workspace: WorkspaceId;
  trace: TraceId;
  revision: Counter;
  graph: GraphManifest;
  path_request: PathRequest;
  path: PathResult;
  inventory: InventoryItem[];
  attachment_policy: "INCLUDE" | "OMIT";
  disclosure: "NORMALIZED_ONLY";
  trust_required: true;
};

export type Bundle = {
  body: BundleBody;
  hash: Hash;
  steps: Step[];
  origins: Origin[];
  audit: Audit[];
  attachments: Artifact[];
};

export type SunlightHandoff = {
  v: 1;
  kind: "action-lineage";
  format: "vislineage-bundle/1";
  bundle: Hash;
  action: Hash;
  trace: TraceId;
  graph: Hash;
  disclosure: "NORMALIZED_ONLY";
  semantics: "NOT_VERIFIED";
};

export type StageRequest = {
  import: ImportId;
  trace: TraceId;
  source: SourceId;
  rows: VendorRow[];
  origins: Origin[];
  artifacts: Artifact[];
};
export type StageResult = { import: ImportId; state: "STAGED"; batch: Hash; rows: number; warnings: Text[] };
export type CommitResult = {
  import: ImportId;
  state: "COMMITTED";
  trace: TraceId;
  revision: Counter;
  graph: Hash;
  added: number;
  duplicates: number;
  conflicts: number;
  audit: Hash;
};
export type ImportState = {
  import: ImportId;
  state: "STAGED" | "COMMITTED" | "CANCELLED";
  batch: Hash;
  commit: CommitResult | null;
  reason: "USER" | "EXPIRED" | null;
};

export type RpcFailure = {
  id: RequestId | null;
  ok: false;
  error: { code: Text; retryable: boolean; details: { field: string | null } };
};

export type ExternalHead = { v: 1; workspace: WorkspaceId; seq: Counter; hash: Hash };

export type BackupManifest = {
  v: 1;
  workspace: WorkspaceId;
  schema: number;
  head: { seq: Counter; hash: Hash };
  files: { path: string; bytes: Counter; digest: Hash }[];
};

export type PrunePlan = { trace: TraceId; graph: Hash; revisions: Counter[]; artifacts: Hash[]; blocked_by_lease: boolean };

export type TrustUpdate = {
  v: 1;
  workspace: WorkspaceId;
  retire: { id: KeyId; last_seq: Counter };
  activate: { id: KeyId; public: PublicKey; first_seq: Counter };
};

export type Config = {
  version: 1;
  workspace: WorkspaceId;
  database: string;
  artifacts: string;
  audit_key_id: KeyId;
  audit_key_env: string;
  bind: string;
  port: number;
  auth: { token_env: string; roles: ("read" | "write" | "admin")[] };
  retention: { stage_ttl_seconds: number; history_revisions: number; artifacts_days: number };
  limits: { stage_rows: number; request_bytes: number; path_nodes: number; bundle_bytes: number };
  observability: { level: "error" | "warn" | "info"; metrics_socket: string };
  recovery_pin: string;
};

export const PROTOCOL = "vislineage/1";
export const SCHEMA_VERSION = 1;
export const IMPLEMENTATION = "0.1.0";

/** The four public fixture seeds production startup must reject (§10.2). */
export const FIXTURE_SEEDS = new Set(["11".repeat(32), "22".repeat(32), "33".repeat(32), "44".repeat(32)]);

export type MaintenanceResult =
  | { command: "init"; workspace: WorkspaceId; schema: 1; audit: Hash }
  | { command: "doctor"; integrity: "OK" | "FAILED"; read_only: boolean; graph_checks: number; reasons: Text[] }
  | { command: "backup"; manifest: BackupManifest; digest: Hash }
  | { command: "restore"; workspace: WorkspaceId; state: "READ_ONLY"; head: { seq: Counter; hash: Hash } }
  | { command: "prune"; applied: boolean; plan: PrunePlan; audit: Hash | null }
  | { command: "key.rotate"; old: KeyId; next: KeyId; audit: Hash; trust_file_digest: Hash }
  | { command: "migrate"; from: number; to: number; state: "PLANNED" | "ACTIVATED"; graphs_checked: number };

export type RequestJournalEntry = {
  v: 1;
  id: RequestId;
  method: string;
  request_hash: Hash;
  state: "PENDING" | "RESPONDED";
  response_hash: Hash | null;
};

export type StagedPayload = { source: SourceId; steps: Step[]; origins: Origin[]; artifacts: Artifact[] };
