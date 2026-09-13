import { VLError } from "./errors.js";
import { isId, type IdPrefix } from "./ids.js";
import { isHash, isPublicKey, isSignature, b64urlDecode } from "./hash.js";
import type {
  Accept,
  Agent,
  Artifact,
  AttachmentRef,
  Audit,
  AuditData,
  Bundle,
  BundleBody,
  Edge,
  EdgeBody,
  Gap,
  GapCode,
  GraphManifest,
  HeadPin,
  InventoryItem,
  KeyPin,
  LineageMetadata,
  NativeParent,
  Offer,
  Origin,
  OriginBody,
  PathRequest,
  PathResult,
  Policy,
  Profile,
  Source,
  Step,
  StepBody,
  StepRef,
  Text,
  TrustPackage,
} from "./types.js";

export function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function bad(field: string, msg: string): never {
  throw new VLError("SCHEMA_INVALID", field, msg);
}

/** Closed-object check: required keys must be present; no unknown members. */
function keys(v: Record<string, unknown>, field: string, required: string[], optional: string[] = []): void {
  const allowed = new Set([...required, ...optional]);
  for (const k of required) if (!(k in v)) bad(`${field}/${k}`, "missing required member");
  for (const k of Object.keys(v)) if (!allowed.has(k)) bad(`${field}/${k}`, "unknown member");
}

const MAX_TEXT_SCALARS = 256;
const MAX_TEXT_BYTES = 1024;

export function isText(v: unknown): v is Text {
  if (typeof v !== "string" || v.length === 0) return false;
  if ([...v].length > MAX_TEXT_SCALARS) return false;
  if (Buffer.byteLength(v, "utf8") > MAX_TEXT_BYTES) return false;
  for (const ch of v) {
    const c = ch.codePointAt(0)!;
    if (c < 0x20 || c === 0x7f) return false;
  }
  return true;
}

export function text(v: unknown, field: string): Text {
  if (!isText(v)) bad(field, "expected Text (1-256 scalars, <=1024 UTF-8 bytes, no C0/DEL)");
  return v;
}

export function hash(v: unknown, field: string): string {
  if (!isHash(v)) bad(field, "expected Hash");
  return v;
}

const COUNTER_RE = /^(0|[1-9][0-9]*)$/;
const COUNTER_MAX = 9223372036854775807n;

export function isCounter(v: unknown): v is string {
  return typeof v === "string" && COUNTER_RE.test(v) && BigInt(v) <= COUNTER_MAX;
}

export function counter(v: unknown, field: string): string {
  if (!isCounter(v)) bad(field, "expected Counter");
  return v;
}

export function typedId(v: unknown, kind: IdPrefix, field: string): string {
  if (typeof v !== "string") bad(field, "expected ID string");
  if (!isId(kind, v)) throw new VLError("ID_INVALID", field, `expected ${kind} ID`);
  return v;
}

const NS_RE = /^[a-z][a-z0-9.-]{0,63}$/;

export function agent(v: unknown, field: string): Agent {
  if (!isObj(v)) bad(field, "expected Agent");
  keys(v, field, ["namespace", "subject", "principal"]);
  if (typeof v.namespace !== "string" || !NS_RE.test(v.namespace)) bad(`${field}/namespace`, "bad agent namespace");
  text(v.subject, `${field}/subject`);
  if (v.principal !== null) text(v.principal, `${field}/principal`);
  return v as unknown as Agent;
}

export function policy(v: unknown, field: string): Policy {
  if (!isObj(v)) bad(field, "expected Policy");
  keys(v, field, ["digest", "version", "decision"]);
  hash(v.digest, `${field}/digest`);
  text(v.version, `${field}/version`);
  if (v.decision !== "ALLOW" && v.decision !== "REVIEW" && v.decision !== "DENY" && v.decision !== "UNKNOWN") {
    bad(`${field}/decision`, "bad decision enum");
  }
  return v as unknown as Policy;
}

export function offer(v: unknown, field: string): Offer {
  if (!isObj(v)) bad(field, "expected Offer");
  keys(v, field, ["id", "child_source", "child_agent", "scope"]);
  typedId(v.id, "delegation", `${field}/id`);
  typedId(v.child_source, "source", `${field}/child_source`);
  agent(v.child_agent, `${field}/child_agent`);
  hash(v.scope, `${field}/scope`);
  return v as unknown as Offer;
}

export function stepRef(v: unknown, field: string): StepRef {
  if (!isObj(v)) bad(field, "expected StepRef");
  keys(v, field, ["source", "record", "hash"]);
  typedId(v.source, "source", `${field}/source`);
  text(v.record, `${field}/record`);
  hash(v.hash, `${field}/hash`);
  return v as unknown as StepRef;
}

export function accept(v: unknown, field: string): Accept {
  if (!isObj(v)) bad(field, "expected Accept");
  keys(v, field, ["id", "parent", "scope"]);
  typedId(v.id, "delegation", `${field}/id`);
  stepRef(v.parent, `${field}/parent`);
  hash(v.scope, `${field}/scope`);
  return v as unknown as Accept;
}

export function attachmentRef(v: unknown, field: string): AttachmentRef {
  if (!isObj(v)) bad(field, "expected AttachmentRef");
  keys(v, field, ["digest", "format", "bytes"]);
  hash(v.digest, `${field}/digest`);
  text(v.format, `${field}/format`);
  counter(v.bytes, `${field}/bytes`);
  return v as unknown as AttachmentRef;
}

export function nativeParent(v: unknown, field: string): NativeParent {
  if (!isObj(v)) bad(field, "expected NativeParent");
  keys(v, field, ["kind", "value"]);
  if (v.kind !== "record" && v.kind !== "span") bad(`${field}/kind`, "bad parent kind");
  text(v.value, `${field}/value`);
  return v as unknown as NativeParent;
}

const PROFILES = new Set<Profile>(["langsmith-runs/1", "langfuse-observations/1", "braintrust-spans/1"]);

export function profile(v: unknown, field: string): Profile {
  if (typeof v !== "string" || !PROFILES.has(v as Profile)) {
    throw new VLError("PROFILE_MISMATCH", field, "unknown profile");
  }
  return v as Profile;
}

export function lineageMetadata(v: unknown, field: string): LineageMetadata {
  if (!isObj(v)) bad(field, "LineageMetadata must be an object");
  keys(v, field, ["v", "trace_id", "agent", "policy", "offers", "accept", "attachments"]);
  if (v.v !== 1) throw new VLError("UNSUPPORTED_VERSION", `${field}/v`, "unsupported LineageMetadata version");
  typedId(v.trace_id, "trace", `${field}/trace_id`);
  if (v.agent !== null) agent(v.agent, `${field}/agent`);
  if (v.policy !== null) policy(v.policy, `${field}/policy`);
  if (!Array.isArray(v.offers)) bad(`${field}/offers`, "expected array");
  v.offers.forEach((o, i) => offer(o, `${field}/offers/${i}`));
  if (v.offers.length > 32) bad(`${field}/offers`, "offer limit");
  const ids = new Set(v.offers.map((o) => (o as Offer).id));
  if (ids.size !== v.offers.length) bad(`${field}/offers`, "duplicate offer ids");
  if (v.accept !== null) accept(v.accept, `${field}/accept`);
  if (!Array.isArray(v.attachments)) bad(`${field}/attachments`, "expected array");
  v.attachments.forEach((a, i) => attachmentRef(a, `${field}/attachments/${i}`));
  if (v.attachments.length > 16) bad(`${field}/attachments`, "attachment limit");
  const attKeys = new Set(v.attachments.map((a) => `${(a as AttachmentRef).format} ${(a as AttachmentRef).digest}`));
  if (attKeys.size !== v.attachments.length) bad(`${field}/attachments`, "duplicate attachment refs");
  return v as unknown as LineageMetadata;
}

export function stepBody(v: unknown, field: string): StepBody {
  if (!isObj(v)) bad(field, "expected StepBody");
  keys(v, field, [
    "v", "workspace", "trace", "source", "profile", "record", "native_trace",
    "native_span", "parents", "agent", "policy", "offers", "accept", "attachments",
  ]);
  if (v.v !== 1) throw new VLError("UNSUPPORTED_VERSION", `${field}/v`, "unsupported StepBody version");
  typedId(v.workspace, "workspace", `${field}/workspace`);
  typedId(v.trace, "trace", `${field}/trace`);
  typedId(v.source, "source", `${field}/source`);
  profile(v.profile, `${field}/profile`);
  text(v.record, `${field}/record`);
  text(v.native_trace, `${field}/native_trace`);
  text(v.native_span, `${field}/native_span`);
  if (!Array.isArray(v.parents)) bad(`${field}/parents`, "expected array");
  if (v.parents.length > 16) bad(`${field}/parents`, "parent limit");
  v.parents.forEach((p, i) => nativeParent(p, `${field}/parents/${i}`));
  const pk = new Set(v.parents.map((p) => `${(p as NativeParent).kind} ${(p as NativeParent).value}`));
  if (pk.size !== v.parents.length) bad(`${field}/parents`, "duplicate parents");
  if (v.agent !== null) agent(v.agent, `${field}/agent`);
  if (v.policy !== null) policy(v.policy, `${field}/policy`);
  if (!Array.isArray(v.offers)) bad(`${field}/offers`, "expected array");
  if (v.offers.length > 32) bad(`${field}/offers`, "offer limit");
  v.offers.forEach((o, i) => offer(o, `${field}/offers/${i}`));
  const oi = new Set(v.offers.map((o) => (o as Offer).id));
  if (oi.size !== v.offers.length) bad(`${field}/offers`, "duplicate offer ids");
  if (v.accept !== null) accept(v.accept, `${field}/accept`);
  if (!Array.isArray(v.attachments)) bad(`${field}/attachments`, "expected array");
  if (v.attachments.length > 16) bad(`${field}/attachments`, "attachment limit");
  v.attachments.forEach((a, i) => attachmentRef(a, `${field}/attachments/${i}`));
  const ak = new Set(v.attachments.map((a) => `${(a as AttachmentRef).format} ${(a as AttachmentRef).digest}`));
  if (ak.size !== v.attachments.length) bad(`${field}/attachments`, "duplicate attachment refs");
  return v as unknown as StepBody;
}

export function step(v: unknown, field: string): Step {
  if (!isObj(v)) bad(field, "expected Step");
  keys(v, field, ["body", "hash"]);
  stepBody(v.body, `${field}/body`);
  hash(v.hash, `${field}/hash`);
  return v as unknown as Step;
}

export function originBody(v: unknown, field: string): OriginBody {
  if (!isObj(v)) bad(field, "expected OriginBody");
  keys(v, field, ["v", "workspace", "source", "stream", "seq", "prev", "step", "key"]);
  if (v.v !== 1) throw new VLError("UNSUPPORTED_VERSION", `${field}/v`, "unsupported OriginBody version");
  typedId(v.workspace, "workspace", `${field}/workspace`);
  typedId(v.source, "source", `${field}/source`);
  text(v.stream, `${field}/stream`);
  counter(v.seq, `${field}/seq`);
  if (BigInt(v.seq as string) < 1n) bad(`${field}/seq`, "stream positions start at 1");
  hash(v.prev, `${field}/prev`);
  hash(v.step, `${field}/step`);
  typedId(v.key, "key", `${field}/key`);
  return v as unknown as OriginBody;
}

export function origin(v: unknown, field: string): Origin {
  if (!isObj(v)) bad(field, "expected Origin");
  keys(v, field, ["body", "hash", "signature"]);
  const b = originBody(v.body, `${field}/body`);
  hash(v.hash, `${field}/hash`);
  if (typeof v.signature !== "string" || !isSignature(v.signature)) {
    bad(`${field}/signature`, "expected 64-byte base64url signature");
  }
  if (b.seq === "1" && b.prev !== "0".repeat(64)) {
    bad(`${field}/body/prev`, "position 1 must carry prev=ZERO");
  }
  if (b.seq !== "1" && b.prev === "0".repeat(64)) {
    bad(`${field}/body/prev`, "position >1 must carry nonzero prev");
  }
  return v as unknown as Origin;
}

export function artifact(v: unknown, field: string): Artifact {
  if (!isObj(v)) bad(field, "expected Artifact");
  keys(v, field, ["digest", "format", "bytes", "content"]);
  hash(v.digest, `${field}/digest`);
  text(v.format, `${field}/format`);
  counter(v.bytes, `${field}/bytes`);
  if (typeof v.content !== "string") bad(`${field}/content`, "expected base64url string");
  return v as unknown as Artifact;
}

/** Decode an artifact's content; enforces canonical b64url + byte count + digest. */
export function artifactBytes(a: Artifact, field: string): Buffer {
  const n = Number(BigInt(a.bytes));
  const raw = b64urlDecode(a.content, n, `${field}/content`);
  return raw;
}

export function source(v: unknown, field: string): Source {
  if (!isObj(v)) bad(field, "expected Source");
  keys(v, field, ["id", "profile", "namespace", "project"]);
  typedId(v.id, "source", `${field}/id`);
  profile(v.profile, `${field}/profile`);
  text(v.namespace, `${field}/namespace`);
  text(v.project, `${field}/project`);
  return v as unknown as Source;
}

export function pathRequest(v: unknown, field: string, nodeCap = 4096, depthCap = 256): PathRequest {
  if (!isObj(v)) bad(field, "expected PathRequest");
  keys(v, field, ["trace", "revision", "action", "max_depth", "max_nodes"]);
  typedId(v.trace, "trace", `${field}/trace`);
  counter(v.revision, `${field}/revision`);
  if (!isObj(v.action)) bad(`${field}/action`, "expected SourceRef");
  keys(v.action, `${field}/action`, ["source", "record"]);
  typedId(v.action.source, "source", `${field}/action/source`);
  text(v.action.record, `${field}/action/record`);
  for (const k of ["max_depth", "max_nodes"] as const) {
    const cap = k === "max_depth" ? depthCap : nodeCap;
    const n = v[k];
    if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 1 || n > cap) {
      bad(`${field}/${k}`, `expected integer 1..${cap}`);
    }
  }
  return v as unknown as PathRequest;
}

export function keyPin(v: unknown, field: string): KeyPin {
  if (!isObj(v)) bad(field, "expected KeyPin");
  keys(v, field, ["id", "public", "role", "workspace", "source", "stream", "first_seq", "last_seq", "status"]);
  typedId(v.id, "key", `${field}/id`);
  if (!isPublicKey(v.public)) bad(`${field}/public`, "expected PublicKey");
  if (v.role !== "origin" && v.role !== "audit") bad(`${field}/role`, "bad role");
  typedId(v.workspace, "workspace", `${field}/workspace`);
  if (v.source !== null) typedId(v.source, "source", `${field}/source`);
  if (v.stream !== null) text(v.stream, `${field}/stream`);
  counter(v.first_seq, `${field}/first_seq`);
  counter(v.last_seq, `${field}/last_seq`);
  if (v.status !== "ACTIVE" && v.status !== "RETIRED" && v.status !== "COMPROMISED") {
    bad(`${field}/status`, "bad status");
  }
  return v as unknown as KeyPin;
}

export function headPin(v: unknown, field: string): HeadPin {
  if (!isObj(v)) bad(field, "expected HeadPin");
  keys(v, field, ["role", "source", "stream", "seq", "hash"]);
  if (v.role !== "origin" && v.role !== "audit") bad(`${field}/role`, "bad role");
  if (v.source !== null) typedId(v.source, "source", `${field}/source`);
  if (v.stream !== null) text(v.stream, `${field}/stream`);
  counter(v.seq, `${field}/seq`);
  hash(v.hash, `${field}/hash`);
  return v as unknown as HeadPin;
}

export function trustPackage(v: unknown, field: string): TrustPackage {
  if (!isObj(v)) bad(field, "expected TrustPackage");
  keys(v, field, ["v", "workspace", "keys", "heads"]);
  if (v.v !== 1) throw new VLError("UNSUPPORTED_VERSION", `${field}/v`, "unsupported TrustPackage version");
  typedId(v.workspace, "workspace", `${field}/workspace`);
  if (!Array.isArray(v.keys)) bad(`${field}/keys`, "expected array");
  v.keys.forEach((k, i) => keyPin(k, `${field}/keys/${i}`));
  if (!Array.isArray(v.heads)) bad(`${field}/heads`, "expected array");
  v.heads.forEach((h, i) => headPin(h, `${field}/heads/${i}`));
  const tp = v as unknown as TrustPackage;
  validateTrust(tp, field);
  return tp;
}

/** §7 pin-consistency rules; violations are TRUST_INVALID. */
export function validateTrust(tp: TrustPackage, field: string): void {
  const badTrust = (f: string, m: string): never => {
    throw new VLError("TRUST_INVALID", f, m);
  };
  const keyIds = new Set<string>();
  const pubsByRole = new Map<string, Set<string>>();
  const intervals = new Map<string, [bigint, bigint][]>();
  for (const k of tp.keys) {
    if (k.workspace !== tp.workspace) badTrust(`${field}/keys`, "key pin workspace mismatch");
    if (keyIds.has(k.id)) badTrust(`${field}/keys`, "duplicate key id");
    keyIds.add(k.id);
    if (BigInt(k.first_seq) < 1n || BigInt(k.first_seq) > BigInt(k.last_seq)) {
      badTrust(`${field}/keys`, "bad sequence interval");
    }
    if (k.role === "origin") {
      if (k.source === null || k.stream === null) badTrust(`${field}/keys`, "origin pin requires source/stream");
    } else if (k.source !== null || k.stream !== null) {
      badTrust(`${field}/keys`, "audit pin requires null source/stream");
    }
    const roles = pubsByRole.get(k.public) ?? new Set<string>();
    roles.add(k.role);
    pubsByRole.set(k.public, roles);
    const scope = `${k.role} ${k.source} ${k.stream}`;
    const list = intervals.get(scope) ?? [];
    for (const [lo, hi] of list) {
      if (BigInt(k.first_seq) <= hi && BigInt(lo) <= BigInt(k.last_seq)) {
        badTrust(`${field}/keys`, "overlapping key intervals");
      }
    }
    list.push([BigInt(k.first_seq), BigInt(k.last_seq)]);
    intervals.set(scope, list);
  }
  for (const [, roles] of pubsByRole) {
    if (roles.size > 1) badTrust(`${field}/keys`, "public key reused across roles");
  }
  const heads = new Map<string, string>();
  for (const h of tp.heads) {
    if (BigInt(h.seq) < 1n) badTrust(`${field}/heads`, "bad head seq");
    if (h.role === "origin") {
      if (h.source === null || h.stream === null) badTrust(`${field}/heads`, "origin head requires source/stream");
    } else if (h.source !== null || h.stream !== null) {
      badTrust(`${field}/heads`, "audit head requires null source/stream");
    }
    const k = `${h.role} ${h.source} ${h.stream} ${h.seq}`;
    const prev = heads.get(k);
    if (prev !== undefined && prev !== h.hash) badTrust(`${field}/heads`, "conflicting head pins");
    heads.set(k, h.hash);
  }
}

export function gap(v: unknown, field: string): Gap {
  if (!isObj(v)) bad(field, "expected Gap");
  keys(v, field, ["code", "subject", "related"]);
  const codes: GapCode[] = [
    "PARENT_MISSING", "PARENT_AMBIGUOUS", "OFFER_MISSING", "ACCEPT_MISSING",
    "DELEGATION_MISMATCH", "PARENT_HASH_MISMATCH", "DELEGATION_REUSED",
    "SOURCE_CONFLICT", "CYCLE", "ORIGIN_GAP", "ORIGIN_FORK",
  ];
  if (!codes.includes(v.code as GapCode)) bad(`${field}/code`, "bad gap code");
  hash(v.subject, `${field}/subject`);
  if (!Array.isArray(v.related)) bad(`${field}/related`, "expected array");
  v.related.forEach((r, i) => hash(r, `${field}/related/${i}`));
  return v as unknown as Gap;
}

export function edgeBody(v: unknown, field: string): EdgeBody {
  if (!isObj(v)) bad(field, "expected EdgeBody");
  keys(v, field, ["v", "trace", "parent", "child", "kind", "delegation", "scope"]);
  if (v.v !== 1) throw new VLError("UNSUPPORTED_VERSION", `${field}/v`, "unsupported EdgeBody version");
  typedId(v.trace, "trace", `${field}/trace`);
  hash(v.parent, `${field}/parent`);
  hash(v.child, `${field}/child`);
  if (v.kind !== "NATIVE_PARENT" && v.kind !== "DELEGATES") bad(`${field}/kind`, "bad edge kind");
  if (v.delegation !== null) typedId(v.delegation, "delegation", `${field}/delegation`);
  if (v.scope !== null) hash(v.scope, `${field}/scope`);
  return v as unknown as EdgeBody;
}

export function edge(v: unknown, field: string): Edge {
  if (!isObj(v)) bad(field, "expected Edge");
  keys(v, field, ["body", "hash"]);
  edgeBody(v.body, `${field}/body`);
  hash(v.hash, `${field}/hash`);
  return v as unknown as Edge;
}

export function graphManifest(v: unknown, field: string): GraphManifest {
  if (!isObj(v)) bad(field, "expected GraphManifest");
  keys(v, field, ["v", "workspace", "trace", "steps", "origins", "edges", "gaps"]);
  if (v.v !== 1) throw new VLError("UNSUPPORTED_VERSION", `${field}/v`, "unsupported manifest version");
  typedId(v.workspace, "workspace", `${field}/workspace`);
  typedId(v.trace, "trace", `${field}/trace`);
  for (const [k, cap] of [["steps", 100000], ["origins", 100000], ["edges", 400000], ["gaps", 400000]] as const) {
    if (!Array.isArray(v[k])) bad(`${field}/${k}`, "expected array");
    if ((v[k] as unknown[]).length > cap) bad(`${field}/${k}`, "array bound exceeded");
  }
  (v.steps as unknown[]).forEach((s, i) => hash(s, `${field}/steps/${i}`));
  (v.origins as unknown[]).forEach((s, i) => hash(s, `${field}/origins/${i}`));
  (v.edges as unknown[]).forEach((s, i) => hash(s, `${field}/edges/${i}`));
  (v.gaps as unknown[]).forEach((g, i) => gap(g, `${field}/gaps/${i}`));
  return v as unknown as GraphManifest;
}

export function pathResult(v: unknown, field: string): PathResult {
  if (!isObj(v)) bad(field, "expected PathResult");
  keys(v, field, [
    "trace", "revision", "graph", "action", "steps", "origins", "edges",
    "gaps", "structural", "evidence", "disclosure",
  ]);
  typedId(v.trace, "trace", `${field}/trace`);
  counter(v.revision, `${field}/revision`);
  hash(v.graph, `${field}/graph`);
  hash(v.action, `${field}/action`);
  if (!Array.isArray(v.steps) || v.steps.length > 4096) bad(`${field}/steps`, "bad steps");
  v.steps.forEach((s, i) => step(s, `${field}/steps/${i}`));
  if (!Array.isArray(v.origins) || v.origins.length > 100000) bad(`${field}/origins`, "bad origins");
  v.origins.forEach((o, i) => origin(o, `${field}/origins/${i}`));
  if (!Array.isArray(v.edges) || v.edges.length > 16384) bad(`${field}/edges`, "bad edges");
  v.edges.forEach((e, i) => edge(e, `${field}/edges/${i}`));
  if (!Array.isArray(v.gaps) || v.gaps.length > 100000) bad(`${field}/gaps`, "bad gaps");
  v.gaps.forEach((g, i) => gap(g, `${field}/gaps/${i}`));
  if (v.structural !== "COMPLETE_RELATIVE" && v.structural !== "INCOMPLETE" && v.structural !== "CONFLICTED") {
    bad(`${field}/structural`, "bad structural verdict");
  }
  if (v.evidence !== "CLAIMED") bad(`${field}/evidence`, "bad evidence label");
  if (v.disclosure !== "NORMALIZED_ONLY") bad(`${field}/disclosure`, "bad disclosure label");
  return v as unknown as PathResult;
}

export function inventoryItem(v: unknown, field: string): InventoryItem {
  if (!isObj(v)) bad(field, "expected InventoryItem");
  keys(v, field, ["kind", "digest", "bytes"]);
  if (v.kind !== "step" && v.kind !== "origin" && v.kind !== "audit" && v.kind !== "attachment") {
    bad(`${field}/kind`, "bad inventory kind");
  }
  hash(v.digest, `${field}/digest`);
  counter(v.bytes, `${field}/bytes`);
  return v as unknown as InventoryItem;
}

export function bundleBody(v: unknown, field: string): BundleBody {
  if (!isObj(v)) bad(field, "expected BundleBody");
  keys(v, field, [
    "v", "format", "workspace", "trace", "revision", "graph", "path_request",
    "path", "inventory", "attachment_policy", "disclosure", "trust_required",
  ]);
  if (v.v !== 1) throw new VLError("UNSUPPORTED_VERSION", `${field}/v`, "unsupported bundle version");
  if (v.format !== "vislineage-bundle/1") bad(`${field}/format`, "bad bundle format");
  typedId(v.workspace, "workspace", `${field}/workspace`);
  typedId(v.trace, "trace", `${field}/trace`);
  counter(v.revision, `${field}/revision`);
  graphManifest(v.graph, `${field}/graph`);
  pathRequest(v.path_request, `${field}/path_request`);
  pathResult(v.path, `${field}/path`);
  if (!Array.isArray(v.inventory) || v.inventory.length > 400000) bad(`${field}/inventory`, "bad inventory");
  v.inventory.forEach((it, i) => inventoryItem(it, `${field}/inventory/${i}`));
  if (v.attachment_policy !== "INCLUDE" && v.attachment_policy !== "OMIT") {
    bad(`${field}/attachment_policy`, "bad attachment policy");
  }
  if (v.disclosure !== "NORMALIZED_ONLY") bad(`${field}/disclosure`, "bad disclosure");
  if (v.trust_required !== true) bad(`${field}/trust_required`, "trust_required must be true");
  return v as unknown as BundleBody;
}

export function bundle(v: unknown, field: string): Bundle {
  if (!isObj(v)) bad(field, "expected Bundle");
  keys(v, field, ["body", "hash", "steps", "origins", "audit", "attachments"]);
  bundleBody(v.body, `${field}/body`);
  hash(v.hash, `${field}/hash`);
  for (const [k, cap] of [["steps", 100000], ["origins", 100000], ["audit", 100000], ["attachments", 100000]] as const) {
    if (!Array.isArray(v[k]) || (v[k] as unknown[]).length > cap) bad(`${field}/${k}`, "bad array bound");
  }
  (v.steps as unknown[]).forEach((s, i) => step(s, `${field}/steps/${i}`));
  (v.origins as unknown[]).forEach((o, i) => origin(o, `${field}/origins/${i}`));
  (v.audit as unknown[]).forEach((a, i) => auditEnvelope(a, `${field}/audit/${i}`));
  (v.attachments as unknown[]).forEach((a, i) => artifact(a, `${field}/attachments/${i}`));
  return v as unknown as Bundle;
}

export function auditData(v: unknown, field: string): AuditData {
  if (!isObj(v)) bad(field, "expected AuditData");
  if (typeof v.kind !== "string") bad(`${field}/kind`, "missing kind");
  switch (v.kind) {
    case "WorkspaceCreated":
      keys(v, field, ["kind", "config"]);
      hash(v.config, `${field}/config`);
      break;
    case "SourceRegistered":
      keys(v, field, ["kind", "source"]);
      source(v.source, `${field}/source`);
      break;
    case "TraceCreated":
      keys(v, field, ["kind", "trace", "graph"]);
      typedId(v.trace, "trace", `${field}/trace`);
      hash(v.graph, `${field}/graph`);
      break;
    case "ImportStaged":
      keys(v, field, ["kind", "import", "trace", "batch", "rows"]);
      typedId(v.import, "import", `${field}/import`);
      typedId(v.trace, "trace", `${field}/trace`);
      hash(v.batch, `${field}/batch`);
      if (typeof v.rows !== "number" || !Number.isSafeInteger(v.rows) || v.rows < 0) bad(`${field}/rows`, "bad rows");
      break;
    case "ImportCommitted":
      keys(v, field, ["kind", "import", "trace", "revision", "graph", "batch"]);
      typedId(v.import, "import", `${field}/import`);
      typedId(v.trace, "trace", `${field}/trace`);
      counter(v.revision, `${field}/revision`);
      hash(v.graph, `${field}/graph`);
      hash(v.batch, `${field}/batch`);
      break;
    case "ImportCancelled":
      keys(v, field, ["kind", "import", "reason"]);
      typedId(v.import, "import", `${field}/import`);
      if (v.reason !== "USER" && v.reason !== "EXPIRED") bad(`${field}/reason`, "bad reason");
      break;
    case "RetentionPruned":
      keys(v, field, ["kind", "traces", "artifacts"]);
      if (!Array.isArray(v.traces)) bad(`${field}/traces`, "expected array");
      v.traces.forEach((t, i) => {
        if (!isObj(t)) bad(`${field}/traces/${i}`, "expected object");
        keys(t, `${field}/traces/${i}`, ["trace", "revisions"]);
        typedId(t.trace, "trace", `${field}/traces/${i}/trace`);
        if (!Array.isArray(t.revisions)) bad(`${field}/traces/${i}/revisions`, "expected array");
        t.revisions.forEach((r, j) => counter(r, `${field}/traces/${i}/revisions/${j}`));
      });
      if (!Array.isArray(v.artifacts)) bad(`${field}/artifacts`, "expected array");
      v.artifacts.forEach((a, i) => hash(a, `${field}/artifacts/${i}`));
      break;
    case "KeyRotated":
      keys(v, field, ["kind", "old", "next", "next_public"]);
      typedId(v.old, "key", `${field}/old`);
      typedId(v.next, "key", `${field}/next`);
      if (!isPublicKey(v.next_public)) bad(`${field}/next_public`, "expected PublicKey");
      break;
    default:
      bad(`${field}/kind`, "unknown audit kind");
  }
  return v as unknown as AuditData;
}

export function auditEnvelope(v: unknown, field: string): Audit {
  if (!isObj(v)) bad(field, "expected Audit");
  keys(v, field, ["body", "hash", "signature"]);
  if (!isObj(v.body)) bad(`${field}/body`, "expected AuditBody");
  keys(v.body, `${field}/body`, ["v", "workspace", "seq", "prev", "request", "key", "data"]);
  if (v.body.v !== 1) throw new VLError("UNSUPPORTED_VERSION", `${field}/body/v`, "unsupported audit version");
  typedId(v.body.workspace, "workspace", `${field}/body/workspace`);
  counter(v.body.seq, `${field}/body/seq`);
  hash(v.body.prev, `${field}/body/prev`);
  typedId(v.body.request, "request", `${field}/body/request`);
  typedId(v.body.key, "key", `${field}/body/key`);
  auditData(v.body.data, `${field}/body/data`);
  hash(v.hash, `${field}/hash`);
  if (typeof v.signature !== "string" || !isSignature(v.signature)) {
    bad(`${field}/signature`, "expected Signature");
  }
  return v as unknown as Audit;
}

export function backupManifest(v: unknown, field: string): import("./types.js").BackupManifest {
  if (!isObj(v)) bad(field, "expected BackupManifest");
  keys(v, field, ["v", "workspace", "schema", "head", "files"]);
  if (v.v !== 1) throw new VLError("UNSUPPORTED_VERSION", `${field}/v`, "unsupported manifest version");
  typedId(v.workspace, "workspace", `${field}/workspace`);
  if (typeof v.schema !== "number" || !Number.isSafeInteger(v.schema) || v.schema < 1) {
    bad(`${field}/schema`, "bad schema version");
  }
  if (!isObj(v.head)) bad(`${field}/head`, "expected head");
  keys(v.head, `${field}/head`, ["seq", "hash"]);
  counter(v.head.seq, `${field}/head/seq`);
  hash(v.head.hash, `${field}/head/hash`);
  if (!Array.isArray(v.files)) bad(`${field}/files`, "expected array");
  v.files.forEach((f, i) => {
    if (!isObj(f)) bad(`${field}/files/${i}`, "expected file entry");
    keys(f, `${field}/files/${i}`, ["path", "bytes", "digest"]);
    if (typeof f.path !== "string" || f.path.length === 0 || f.path.length > 512) {
      bad(`${field}/files/${i}/path`, "bad path");
    }
    counter(f.bytes, `${field}/files/${i}/bytes`);
    hash(f.digest, `${field}/files/${i}/digest`);
  });
  return v as import("./types.js").BackupManifest;
}

export function trustUpdate(v: unknown, field: string): import("./types.js").TrustUpdate {
  if (!isObj(v)) bad(field, "expected TrustUpdate");
  keys(v, field, ["v", "workspace", "retire", "activate"]);
  if (v.v !== 1) throw new VLError("UNSUPPORTED_VERSION", `${field}/v`, "unsupported update version");
  typedId(v.workspace, "workspace", `${field}/workspace`);
  if (!isObj(v.retire)) bad(`${field}/retire`, "expected retire");
  keys(v.retire, `${field}/retire`, ["id", "last_seq"]);
  typedId(v.retire.id, "key", `${field}/retire/id`);
  counter(v.retire.last_seq, `${field}/retire/last_seq`);
  if (!isObj(v.activate)) bad(`${field}/activate`, "expected activate");
  keys(v.activate, `${field}/activate`, ["id", "public", "first_seq"]);
  typedId(v.activate.id, "key", `${field}/activate/id`);
  if (!isPublicKey(v.activate.public)) bad(`${field}/activate/public`, "expected PublicKey");
  counter(v.activate.first_seq, `${field}/activate/first_seq`);
  return v as import("./types.js").TrustUpdate;
}

export function externalHead(v: unknown, field: string): import("./types.js").ExternalHead {
  if (!isObj(v)) bad(field, "expected ExternalHead");
  keys(v, field, ["v", "workspace", "seq", "hash"]);
  if (v.v !== 1) throw new VLError("UNSUPPORTED_VERSION", `${field}/v`, "unsupported head version");
  typedId(v.workspace, "workspace", `${field}/workspace`);
  counter(v.seq, `${field}/seq`);
  hash(v.hash, `${field}/hash`);
  return v as import("./types.js").ExternalHead;
}

export function traceResult(v: unknown, field: string): import("./types.js").Trace {
  if (!isObj(v)) bad(field, "expected Trace");
  keys(v, field, ["id", "revision", "graph"]);
  typedId(v.id, "trace", `${field}/id`);
  counter(v.revision, `${field}/revision`);
  hash(v.graph, `${field}/graph`);
  return v as unknown as import("./types.js").Trace;
}

export function verification(v: unknown, field: string): import("./types.js").Verification {
  if (!isObj(v)) bad(field, "expected Verification");
  keys(v, field, [
    "integrity", "structural", "origin", "audit", "disclosure",
    "semantics", "current_authority", "reasons",
  ]);
  if (v.integrity !== "VALID" && v.integrity !== "INVALID") bad(`${field}/integrity`, "bad verdict");
  if (
    v.structural !== "COMPLETE_RELATIVE" &&
    v.structural !== "INCOMPLETE" &&
    v.structural !== "CONFLICTED"
  ) {
    bad(`${field}/structural`, "bad verdict");
  }
  if (!["TRUSTED_AT_PIN", "UNSIGNED", "UNTRUSTED", "INCOMPLETE", "CONFLICTED"].includes(v.origin as string)) {
    bad(`${field}/origin`, "bad verdict");
  }
  if (!["TRUSTED_AT_PIN", "UNTRUSTED", "INCOMPLETE"].includes(v.audit as string)) {
    bad(`${field}/audit`, "bad verdict");
  }
  if (v.disclosure !== "NORMALIZED_ONLY") bad(`${field}/disclosure`, "bad disclosure");
  if (v.semantics !== "NOT_VERIFIED") bad(`${field}/semantics`, "bad semantics label");
  if (v.current_authority !== "UNKNOWN") bad(`${field}/current_authority`, "bad authority label");
  if (!Array.isArray(v.reasons)) bad(`${field}/reasons`, "expected array");
  v.reasons.forEach((r, i) => text(r, `${field}/reasons/${i}`));
  return v as unknown as import("./types.js").Verification;
}

export function stageResult(v: unknown, field: string): import("./types.js").StageResult {
  if (!isObj(v)) bad(field, "expected StageResult");
  keys(v, field, ["import", "state", "batch", "rows", "warnings"]);
  typedId(v.import, "import", `${field}/import`);
  if (v.state !== "STAGED") bad(`${field}/state`, "bad state");
  hash(v.batch, `${field}/batch`);
  if (typeof v.rows !== "number" || !Number.isSafeInteger(v.rows) || v.rows < 0) {
    bad(`${field}/rows`, "bad rows");
  }
  if (!Array.isArray(v.warnings)) bad(`${field}/warnings`, "expected array");
  v.warnings.forEach((w, i) => text(w, `${field}/warnings/${i}`));
  return v as unknown as import("./types.js").StageResult;
}

export function commitResult(v: unknown, field: string): import("./types.js").CommitResult {
  if (!isObj(v)) bad(field, "expected CommitResult");
  keys(v, field, ["import", "state", "trace", "revision", "graph", "added", "duplicates", "conflicts", "audit"]);
  typedId(v.import, "import", `${field}/import`);
  if (v.state !== "COMMITTED") bad(`${field}/state`, "bad state");
  typedId(v.trace, "trace", `${field}/trace`);
  counter(v.revision, `${field}/revision`);
  hash(v.graph, `${field}/graph`);
  for (const k of ["added", "duplicates", "conflicts"] as const) {
    if (typeof v[k] !== "number" || !Number.isSafeInteger(v[k] as number) || (v[k] as number) < 0) {
      bad(`${field}/${k}`, "bad count");
    }
  }
  hash(v.audit, `${field}/audit`);
  return v as unknown as import("./types.js").CommitResult;
}

export function importState(v: unknown, field: string): import("./types.js").ImportState {
  if (!isObj(v)) bad(field, "expected ImportState");
  keys(v, field, ["import", "state", "batch", "commit", "reason"]);
  typedId(v.import, "import", `${field}/import`);
  if (v.state !== "STAGED" && v.state !== "COMMITTED" && v.state !== "CANCELLED") {
    bad(`${field}/state`, "bad state");
  }
  hash(v.batch, `${field}/batch`);
  if (v.commit !== null) commitResult(v.commit, `${field}/commit`);
  if (v.reason !== null && v.reason !== "USER" && v.reason !== "EXPIRED") {
    bad(`${field}/reason`, "bad reason");
  }
  return v as unknown as import("./types.js").ImportState;
}

export function sunlightHandoff(v: unknown, field: string): import("./types.js").SunlightHandoff {
  if (!isObj(v)) bad(field, "expected SunlightHandoff");
  keys(v, field, ["v", "kind", "format", "bundle", "action", "trace", "graph", "disclosure", "semantics"]);
  if (v.v !== 1) throw new VLError("UNSUPPORTED_VERSION", `${field}/v`, "unsupported handoff version");
  if (v.kind !== "action-lineage") bad(`${field}/kind`, "bad kind");
  if (v.format !== "vislineage-bundle/1") bad(`${field}/format`, "bad format");
  hash(v.bundle, `${field}/bundle`);
  hash(v.action, `${field}/action`);
  typedId(v.trace, "trace", `${field}/trace`);
  hash(v.graph, `${field}/graph`);
  if (v.disclosure !== "NORMALIZED_ONLY") bad(`${field}/disclosure`, "bad disclosure");
  if (v.semantics !== "NOT_VERIFIED") bad(`${field}/semantics`, "bad semantics");
  return v as unknown as import("./types.js").SunlightHandoff;
}

export function sourceListResult(v: unknown, field: string): { sources: Source[] } {
  if (!isObj(v)) bad(field, "expected source list");
  keys(v, field, ["sources"]);
  if (!Array.isArray(v.sources)) bad(`${field}/sources`, "expected array");
  v.sources.forEach((s, i) => source(s, `${field}/sources/${i}`));
  return v as unknown as { sources: Source[] };
}
