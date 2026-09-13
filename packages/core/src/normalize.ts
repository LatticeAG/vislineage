import { VLError } from "./errors.js";
import { D } from "./hash.js";
import { J } from "./jcs.js";
import { isObj, lineageMetadata, text } from "./schema.js";
import type {
  LineageMetadata,
  NativeParent,
  Profile,
  Source,
  Step,
  StepBody,
  VendorRow,
} from "./types.js";

export interface NormContext {
  workspace: string;
  trace: string;
  source: Source;
}

function prof(field: string, msg: string): never {
  throw new VLError("PROFILE_MISMATCH", field, msg);
}

function reqText(row: Record<string, unknown>, name: string, field: string): string {
  const v = row[name];
  if (typeof v !== "string" || v.length === 0) prof(`${field}/${name}`, "required provider field missing/empty");
  return text(v, `${field}/${name}`);
}

/** Sorted-copy helpers: parents by JCS bytes of (kind,value); offers by id; attachments by JCS of (format,digest). */
function sortParents(ps: NativeParent[]): NativeParent[] {
  return [...ps].sort((a, b) => Buffer.compare(J([a.kind, a.value]), J([b.kind, b.value])));
}

interface RawMeta {
  agent: StepBody["agent"];
  policy: StepBody["policy"];
  offers: StepBody["offers"];
  accept: StepBody["accept"];
  attachments: StepBody["attachments"];
}

function extractMetadata(row: Record<string, unknown>, profile: Profile, ctx: NormContext, field: string): { meta: RawMeta; absent: boolean } {
  const container = profile === "langsmith-runs/1" ? row["extra"] : row["metadata"];
  let inner: unknown = undefined;
  if (container !== undefined && container !== null) {
    if (isObj(container)) {
      if (profile === "langsmith-runs/1") {
        const md = container["metadata"];
        if (md !== undefined && md !== null && isObj(md)) inner = md["vislineage"];
      } else {
        inner = container["vislineage"];
      }
    }
    // non-object metadata containers contribute no lineage
  }
  if (inner === undefined) {
    return { meta: { agent: null, policy: null, offers: [], accept: null, attachments: [] }, absent: true };
  }
  const lm = lineageMetadata(inner, `${field}/${profile === "langsmith-runs/1" ? "extra/metadata/vislineage" : "metadata/vislineage"}`);
  if (lm.trace_id !== ctx.trace) {
    throw new VLError("TRACE_MISMATCH", `${field}/metadata/vislineage/trace_id`, "metadata trace_id differs from target trace");
  }
  const offers = [...lm.offers].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const attachments = [...lm.attachments].sort((a, b) =>
    Buffer.compare(J([a.format, a.digest]), J([b.format, b.digest])),
  );
  return {
    meta: { agent: lm.agent, policy: lm.policy, offers, accept: lm.accept, attachments },
    absent: false,
  };
}

/**
 * normalize(profile,row,context): strict profile mapping → Step.
 * Throws VLError(PROFILE_MISMATCH | SCHEMA_INVALID | TRACE_MISMATCH).
 */
export function normalize(profileName: Profile, row: unknown, ctx: NormContext, field = "/row"): { step: Step; warnings: string[] } {
  if (!isObj(row)) prof(field, "row is not an object");
  let record: string;
  let nativeTrace: string;
  let nativeSpan: string;
  const parents: NativeParent[] = [];
  switch (profileName) {
    case "langsmith-runs/1": {
      record = reqText(row, "id", field);
      nativeTrace = reqText(row, "trace_id", field);
      nativeSpan = record;
      const p = row["parent_run_id"];
      if (p !== null && p !== undefined) {
        if (typeof p !== "string" || p.length === 0) prof(`${field}/parent_run_id`, "empty parent");
        parents.push({ kind: "record", value: text(p, `${field}/parent_run_id`) });
      }
      break;
    }
    case "langfuse-observations/1": {
      record = reqText(row, "id", field);
      nativeTrace = reqText(row, "traceId", field);
      nativeSpan = record;
      const p = row["parentObservationId"];
      if (p !== null && p !== undefined) {
        if (typeof p !== "string" || p.length === 0) prof(`${field}/parentObservationId`, "empty parent");
        parents.push({ kind: "record", value: text(p, `${field}/parentObservationId`) });
      }
      break;
    }
    case "braintrust-spans/1": {
      record = reqText(row, "id", field);
      nativeSpan = reqText(row, "span_id", field);
      nativeTrace = reqText(row, "root_span_id", field);
      const sp = row["span_parents"];
      if (!Array.isArray(sp)) prof(`${field}/span_parents`, "required provider field missing/wrong type");
      for (const [i, p] of sp.entries()) {
        if (typeof p !== "string" || p.length === 0) prof(`${field}/span_parents/${i}`, "empty parent");
        parents.push({ kind: "span", value: text(p, `${field}/span_parents/${i}`) });
      }
      break;
    }
  }
  if (parents.length > 16) throw new VLError("SCHEMA_INVALID", `${field}/parents`, "parent limit");
  const { meta, absent } = extractMetadata(row, profileName, ctx, field);
  const body: StepBody = {
    v: 1,
    workspace: ctx.workspace,
    trace: ctx.trace,
    source: ctx.source.id,
    profile: profileName,
    record,
    native_trace: nativeTrace,
    native_span: nativeSpan,
    parents: sortParents(parents),
    agent: meta.agent,
    policy: meta.policy,
    offers: meta.offers,
    accept: meta.accept,
    attachments: meta.attachments,
  };
  const step: Step = { body, hash: D("VL-STEP/1", body) };
  return { step, warnings: absent ? ["METADATA_ABSENT"] : [] };
}
