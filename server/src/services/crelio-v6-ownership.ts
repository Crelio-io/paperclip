import { eq } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import {
  crelioV6IssueBindings,
  crelioV6ProjectPolicies,
  issues,
} from "@paperclipai/db";

type DbLike = Pick<Db, "select">;

export async function loadCrelioV6IssueBinding(dbOrTx: DbLike, issueId: string) {
  return dbOrTx
    .select()
    .from(crelioV6IssueBindings)
    .where(eq(crelioV6IssueBindings.issueId, issueId))
    .then((rows: Array<typeof crelioV6IssueBindings.$inferSelect>) => rows[0] ?? null);
}

export async function loadCrelioV6ProjectPolicyForIssue(dbOrTx: DbLike, issueId: string) {
  const row = await dbOrTx
    .select({ projectId: issues.projectId })
    .from(issues)
    .where(eq(issues.id, issueId))
    .then((rows: Array<{ projectId: string | null }>) => rows[0] ?? null);
  if (!row?.projectId) return null;
  return dbOrTx
    .select()
    .from(crelioV6ProjectPolicies)
    .where(eq(crelioV6ProjectPolicies.projectId, row.projectId))
    .then((rows: Array<typeof crelioV6ProjectPolicies.$inferSelect>) => rows[0] ?? null);
}

/**
 * Low-level ownership guard for stock background services.  This module must not
 * import heartbeat or issue services: recovery code imports it specifically to
 * avoid a crelio-v6 -> heartbeat -> recovery -> crelio-v6 dependency cycle.
 */
export async function isCrelioV6ExecutionFrozenIssue(dbOrTx: DbLike, issueId: string) {
  const [binding, policy] = await Promise.all([
    loadCrelioV6IssueBinding(dbOrTx, issueId),
    loadCrelioV6ProjectPolicyForIssue(dbOrTx, issueId),
  ]);
  if (!policy || policy.schemaFloor < 6) return null;
  return { binding, policy, legacy: !binding };
}
