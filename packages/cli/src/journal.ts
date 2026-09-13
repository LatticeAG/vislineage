import * as fs from "node:fs";
import * as path from "node:path";
import { D, H, J, type RequestJournalEntry } from "@latticeag/vislineage-core";

/**
 * Canonical JSONL request journal at state/requests.jsonl (§10.3). Entries
 * carry hashes only — never raw request rows or secrets.
 */
export class Journal {
  private file: string;
  constructor(stateDir: string) {
    this.file = path.join(stateDir, "requests.jsonl");
    fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  }
  private append(entry: RequestJournalEntry): void {
    const fd = fs.openSync(this.file, "a", 0o600);
    try {
      fs.writeSync(fd, Buffer.concat([J(entry), Buffer.from("\n")]));
    } finally {
      fs.closeSync(fd);
    }
    try {
      fs.chmodSync(this.file, 0o600);
    } catch {
      /* best effort */
    }
  }
  pending(id: string, method: string, params: unknown): void {
    this.append({
      v: 1,
      id,
      method,
      request_hash: D("VL-REQUEST/1", { method, params }),
      state: "PENDING",
      response_hash: null,
    });
  }
  responded(id: string, method: string, params: unknown, response: unknown): void {
    this.append({
      v: 1,
      id,
      method,
      request_hash: D("VL-REQUEST/1", { method, params }),
      state: "RESPONDED",
      response_hash: H(J(response)),
    });
  }
}
