import type { PathResult, Step, Verification } from "@latticeag/vislineage-core";

/** Human-readable path table per §2.2. */
export function renderPath(p: PathResult): string {
  const byHash = new Map(p.steps.map((s) => [s.hash, s]));
  const incoming = new Map<string, string[]>();
  for (const e of p.edges) {
    const l = incoming.get(e.body.child) ?? [];
    l.push(e.body.kind);
    incoming.set(e.body.child, l);
  }
  const lines: string[] = [];
  const short = (h: string): string => h.slice(0, 12);
  lines.push("STEP          RECORD                 AGENT         POLICY    EDGES            EVIDENCE");
  for (const s of p.steps) {
    const rec = `${s.body.source.slice(4, 12)}:${s.body.record}`;
    const agent = s.body.agent ? `${s.body.agent.namespace}/${s.body.agent.subject}` : "-";
    const policy = s.body.policy ? s.body.policy.decision : "UNKNOWN";
    const kinds = (incoming.get(s.hash) ?? []).join("+") || "-";
    const attested = p.origins.some((o) => o.body.step === s.hash);
    const evidence = attested ? "SIGNED" : "CLAIMED";
    lines.push(
      `${short(s.hash)}  ${rec.padEnd(22)} ${agent.padEnd(13)} ${policy.padEnd(9)} ${kinds.padEnd(16)} ${evidence}`,
    );
  }
  void byHash;
  const missing = p.gaps.filter((g) => g.code !== "ORIGIN_FORK" && g.code !== "ORIGIN_GAP").length +
    p.gaps.filter((g) => g.code === "ORIGIN_GAP").length;
  const forks = p.gaps.filter((g) => g.code === "ORIGIN_FORK").length;
  lines.push(
    `trace ${p.trace} revision ${p.revision} graph ${short(p.graph)} — ${missing} missing reference(s), ${forks} fork(s), relative to disclosed exports [${p.structural}/${p.evidence}]`,
  );
  return lines.join("\n");
}

export function renderVerification(v: Verification): string {
  return [
    `integrity: ${v.integrity}`,
    `structural: ${v.structural}`,
    `origin: ${v.origin}`,
    `audit: ${v.audit}`,
    `disclosure: ${v.disclosure} (normalized metadata only — no raw provider payloads)`,
    `semantics: ${v.semantics} (structural evidence, never real-world truth)`,
    `current_authority: ${v.current_authority} (no live authority)`,
    v.reasons.length ? `reasons: ${v.reasons.join(", ")}` : "reasons: none",
  ].join("\n");
}
