/** VisLineage protocol error codes (vislineage/1). */

export const RETRYABLE = new Set(["RATE_LIMIT", "BUSY", "STORAGE_UNAVAILABLE"]);

const HTTP_STATUS: Record<string, number> = {
  JSON_INVALID: 400,
  SCHEMA_INVALID: 400,
  PROFILE_MISMATCH: 400,
  METHOD_UNKNOWN: 400,
  ID_INVALID: 400,
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  SOURCE_CONFLICT: 409,
  TRACE_MISMATCH: 409,
  IDEMPOTENCY_CONFLICT: 409,
  IMPORT_STATE: 409,
  REVISION_CONFLICT: 409,
  ACTION_CONFLICT: 409,
  IMPORT_CONFLICT: 409,
  ARTIFACT_FORMAT_CONFLICT: 409,
  REVISION_PRUNED: 410,
  ARTIFACT_UNAVAILABLE: 410,
  BODY_LIMIT: 413,
  ROW_LIMIT: 413,
  PATH_LIMIT: 413,
  BUNDLE_LIMIT: 413,
  TRACE_LIMIT: 413,
  HASH_MISMATCH: 422,
  ARTIFACT_UNREFERENCED: 422,
  ORIGIN_UNREFERENCED: 422,
  TRUST_INVALID: 422,
  UNSUPPORTED_VERSION: 422,
  RATE_LIMIT: 429,
  BUSY: 503,
  STORAGE_UNAVAILABLE: 503,
  READ_ONLY: 503,
};

/** Error codes that carry a JSON-pointer-ish details.field when known. */
const FIELDED = new Set([
  "JSON_INVALID",
  "SCHEMA_INVALID",
  "PROFILE_MISMATCH",
  "ID_INVALID",
  "METHOD_UNKNOWN",
]);

export class VLError extends Error {
  readonly code: string;
  readonly field: string | null;
  constructor(code: string, field: string | null = null, message?: string) {
    super(message ?? code);
    this.name = "VLError";
    this.code = code;
    this.field = field;
  }
  get retryable(): boolean {
    return RETRYABLE.has(this.code);
  }
  get status(): number {
    return HTTP_STATUS[this.code] ?? 500;
  }
  get details(): { field: string | null } {
    return { field: FIELDED.has(this.code) ? this.field : null };
  }
}

export function errcode(e: unknown): string {
  if (e instanceof VLError) return e.code;
  throw e;
}
