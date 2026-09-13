import { D, H } from "./hash.js";
import { J } from "./jcs.js";
import { VLError } from "./errors.js";
import type {
  Artifact,
  Audit,
  Bundle,
  BundleBody,
  GraphManifest,
  InventoryItem,
  Origin,
  PathRequest,
  PathResult,
  Step,
  SunlightHandoff,
} from "./types.js";

/** Inventory digest for a JSON envelope: H(J(envelope)) with JCS byte count. */
export function envelopeItem(kind: InventoryItem["kind"], obj: unknown): InventoryItem {
  const b = J(obj);
  return { kind, digest: H(b), bytes: String(b.length) };
}

export interface BundleParts {
  workspace: string;
  trace: string;
  revision: string;
  graph: GraphManifest;
  pathRequest: PathRequest;
  path: PathResult;
  steps: Step[];
  origins: Origin[];
  audit: Audit[];
  /** attachment bytes available for INCLUDE */
  artifacts: Artifact[];
  /** all attachment refs referenced by bundled steps (for OMIT inventory) */
  attachmentRefs: { digest: string; format: string; bytes: string }[];
  attachmentPolicy: "INCLUDE" | "OMIT";
  /** serialized cap for BUNDLE_LIMIT pre-check */
  bundleBytes: number;
}

/**
 * Construct a proof bundle (§8). Throws ARTIFACT_UNAVAILABLE for INCLUDE when
 * referenced bytes are missing, BUNDLE_LIMIT when the serialized size would
 * exceed the configured cap.
 */
export function buildBundle(p: BundleParts): { bundle: Bundle; sunlight: SunlightHandoff } {
  const steps = [...p.steps].sort((a, b) => (a.hash < b.hash ? -1 : 1));
  const origins = [...p.origins].sort((a, b) => Buffer.compare(J(a), J(b)));
  const audit = [...p.audit].sort((a, b) => (BigInt(a.body.seq) < BigInt(b.body.seq) ? -1 : 1));
  const attachments = [...p.artifacts].sort((a, b) => (a.digest < b.digest ? -1 : 1));

  const items: InventoryItem[] = [
    ...steps.map((s) => envelopeItem("step", s)),
    ...origins.map((o) => envelopeItem("origin", o)),
    ...audit.map((a) => envelopeItem("audit", a)),
  ];
  // attachment inventory entries commit raw content, not the Artifact JSON
  const seenAtt = new Set<string>();
  for (const r of p.attachmentRefs) {
    if (seenAtt.has(r.digest)) continue;
    seenAtt.add(r.digest);
    items.push({ kind: "attachment", digest: r.digest, bytes: r.bytes });
  }
  items.sort((a, b) => (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : a.digest < b.digest ? -1 : 1));

  const body: BundleBody = {
    v: 1,
    format: "vislineage-bundle/1",
    workspace: p.workspace,
    trace: p.trace,
    revision: p.revision,
    graph: p.graph,
    path_request: p.pathRequest,
    path: p.path,
    inventory: items,
    attachment_policy: p.attachmentPolicy,
    disclosure: "NORMALIZED_ONLY",
    trust_required: true,
  };
  const bundle: Bundle = {
    body,
    hash: D("VL-BUNDLE/1", body),
    steps,
    origins,
    audit,
    attachments: p.attachmentPolicy === "INCLUDE" ? attachments : [],
  };
  const size = J(bundle).length;
  if (size > p.bundleBytes) throw new VLError("BUNDLE_LIMIT", null, "bundle exceeds cap");
  const sunlight: SunlightHandoff = {
    v: 1,
    kind: "action-lineage",
    format: "vislineage-bundle/1",
    bundle: bundle.hash,
    action: p.path.action,
    trace: p.trace,
    graph: p.path.graph,
    disclosure: "NORMALIZED_ONLY",
    semantics: "NOT_VERIFIED",
  };
  return { bundle, sunlight };
}
