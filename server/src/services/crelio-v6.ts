import { createHash, randomUUID } from "node:crypto";
import { and, asc, eq, gt, inArray, isNull, lte, or, sql } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import {
  agentWakeupRequests,
  agents,
  approvals,
  assets,
  boardApiKeys,
  crelioV6ApprovalSubjects,
  crelioV6CompletionReceipts,
  crelioV6ControllerGrants,
  crelioV6IssueBindings,
  crelioV6JournalEvents,
  crelioV6JournalHeads,
  crelioV6LegacyFreezes,
  crelioV6LifecycleAuthorizations,
  crelioV6ProjectPolicies,
  crelioV6SnapshotSessions,
  executionWorkspaces,
  heartbeatRuns,
  issueApprovals,
  issueAttachments,
  issueComments,
  issueExecutionDecisions,
  issueTreeHolds,
  issues,
  projects,
  workspaceOperations,
} from "@paperclipai/db";
import { conflict, forbidden, notFound, unprocessable } from "../errors.js";
import type { AuthorizationActor } from "./authorization.js";
import {
  applyIssueExecutionPolicyTransition,
  normalizeIssueExecutionPolicy,
} from "./issue-execution-policy.js";
import { issueService } from "./issues.js";
import { finalizeSummarySlotsForTerminalIssue } from "./summary-slot-finalization.js";
import { budgetService } from "./budgets.js";
import { heartbeatService } from "./heartbeat.js";
import { issueTreeControlService } from "./issue-tree-control.js";
import {
  isCrelioV6ExecutionFrozenIssue,
  loadCrelioV6IssueBinding,
  loadCrelioV6ProjectPolicyForIssue,
} from "./crelio-v6-ownership.js";

export {
  isCrelioV6ExecutionFrozenIssue,
  loadCrelioV6IssueBinding,
  loadCrelioV6ProjectPolicyForIssue,
} from "./crelio-v6-ownership.js";

export const CRELIO_V6_SCHEMA = 6;
export const CRELIO_V6_CONTROLLER_OWNER = "crelio_controller";
export const CRELIO_V6_MAX_COMMENT_CHARS = 2_000;
export const CRELIO_V6_EVENT_LIMIT_MAX = 1_000;
export const CRELIO_V6_SNAPSHOT_PAGE_LIMIT_MAX = 500;
export const CRELIO_V6_SNAPSHOT_TTL_MS = 5 * 60 * 1000;
export const CRELIO_V6_PHASES = [
  "strategy_intake",
  "seo_research",
  "research_decision",
  "content_brief",
  "brief_decision",
  "draft",
  "editorial_review",
  "visual_production",
  "visual_review",
  "final_assembly",
  "final_package_review",
  "final_handoff",
] as const;

export const CRELIO_V6_CONTROLLER_OPERATIONS = [
  "generation.activate",
  "generation.fence",
  "controller_key.probe",
  "controller_key.activate",
  "issue.create",
  "issue.activate",
  "issue.reopen",
  "issue.close_root",
  "issue.hold",
  "issue.attach",
  "provider.receipt.install",
  "workspace.close",
  "approval.subject.install",
  "approval.subject.finalize",
  "events.read",
  "snapshot.read",
  "budget.read",
  "diagnostics.read",
] as const;

export type CrelioV6ControllerOperation = (typeof CRELIO_V6_CONTROLLER_OPERATIONS)[number];

type DbLike = any;

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => stableStringify(entry)).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
    .join(",")}}`;
}

export function crelioV6Sha256(value: unknown): string {
  const bytes = typeof value === "string" ? value : stableStringify(value);
  return createHash("sha256").update(bytes).digest("hex");
}

const CRELIO_V6_RUNTIME_CONTRACT_KEYS = [
  "engine",
  "model",
  "modelReasoningEffort",
  "timeoutSec",
  "graceSec",
  "outputInactivityTimeoutMs",
] as const;

function normalizeCrelioV6RuntimeContract(
  value: unknown,
  field: string,
  exactKeys: boolean,
) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw conflict(`${field} is missing or malformed`);
  }
  const record = value as Record<string, unknown>;
  if (
    exactKeys &&
    (Object.keys(record).length !== CRELIO_V6_RUNTIME_CONTRACT_KEYS.length ||
      CRELIO_V6_RUNTIME_CONTRACT_KEYS.some((key) => !(key in record)))
  ) {
    throw conflict(`${field} must contain only the canonical V6 runtime fields`);
  }
  const normalized = {
    engine: record.engine,
    model: record.model,
    modelReasoningEffort: record.modelReasoningEffort,
    timeoutSec: record.timeoutSec,
    graceSec: record.graceSec,
    outputInactivityTimeoutMs: record.outputInactivityTimeoutMs,
  };
  if (
    normalized.engine !== "cli" ||
    typeof normalized.model !== "string" ||
    !normalized.model ||
    !["minimal", "low", "medium", "high", "xhigh"].includes(
      String(normalized.modelReasoningEffort),
    ) ||
    normalized.timeoutSec !== 2700 ||
    normalized.graceSec !== 20 ||
    normalized.outputInactivityTimeoutMs !== 1_200_000
  ) {
    throw conflict(`${field} is outside the qualified V6 runtime contract`);
  }
  return normalized;
}

export function assertCrelioV6RuntimeContract(
  expected: unknown,
  effectiveAdapterConfig: unknown,
) {
  const declared = normalizeCrelioV6RuntimeContract(
    expected,
    "V6 declared runtime contract",
    true,
  );
  const observed = normalizeCrelioV6RuntimeContract(
    effectiveAdapterConfig,
    "V6 effective adapter configuration",
    false,
  );
  if (stableStringify(declared) !== stableStringify(observed)) {
    throw conflict("V6 effective adapter configuration diverges from its declared contract");
  }
  return observed;
}

function isSha256(value: string) {
  return /^[a-f0-9]{64}$/.test(value);
}

function requireSha256(value: string, field: string) {
  if (!isSha256(value)) throw unprocessable(`${field} must be a lowercase SHA-256 hex digest`);
}

function requireGeneration(value: string) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) {
    throw unprocessable("Invalid V6 generation");
  }
}

function requireFencingGeneration(value: number) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw unprocessable("Controller fencing generation must be a positive safe integer");
  }
}

function sanitizedRunUsage(value: unknown): Record<string, number | string> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const out: Record<string, number | string> = {};
  for (const key of [
    "rawInputTokens",
    "rawCachedInputTokens",
    "rawOutputTokens",
    "inputTokens",
    "cachedInputTokens",
    "outputTokens",
    "totalCostUsd",
    "costUsd",
  ]) {
    const candidate = record[key];
    if (typeof candidate === "number" && Number.isFinite(candidate) && candidate >= 0) out[key] = candidate;
  }
  for (const key of ["billingType", "biller", "costStatus"]) {
    const candidate = record[key];
    if (typeof candidate === "string" && candidate.length <= 120) out[key] = candidate;
  }
  return Object.keys(out).length > 0 ? out : null;
}

function actorIsBoardSessionAdmin(actor: AuthorizationActor) {
  return actor.type === "board" && actor.source === "session" && actor.isInstanceAdmin === true && Boolean(actor.userId);
}

export async function appendCrelioV6Journal(
  tx: DbLike,
  input: {
    projectId: string;
    generation: string;
    entityKind: string;
    entityId: string;
    entityVersion: number;
    mutationKind: string;
    reductionPayload: Record<string, unknown>;
    sourceTransactionId?: string;
  },
) {
  await tx.insert(crelioV6JournalHeads).values({ projectId: input.projectId }).onConflictDoNothing();
  await tx.execute(sql`select project_id from crelio_v6_journal_heads where project_id = ${input.projectId} for update`);
  const head = await tx
    .update(crelioV6JournalHeads)
    .set({
      lastCommittedSequence: sql`${crelioV6JournalHeads.lastCommittedSequence} + 1`,
      optimisticVersion: sql`${crelioV6JournalHeads.optimisticVersion} + 1`,
      updatedAt: new Date(),
    })
    .where(eq(crelioV6JournalHeads.projectId, input.projectId))
    .returning({ sequence: crelioV6JournalHeads.lastCommittedSequence })
    .then((rows: Array<{ sequence: number }>) => rows[0]);

  await tx.insert(crelioV6JournalEvents).values({
    projectId: input.projectId,
    sequence: head.sequence,
    generation: input.generation,
    entityKind: input.entityKind,
    entityId: input.entityId,
    entityVersion: input.entityVersion,
    mutationKind: input.mutationKind,
    reductionPayload: input.reductionPayload,
    sourceTransactionId: input.sourceTransactionId ?? randomUUID(),
  });
  return head.sequence;
}

async function loadProjectPolicy(dbOrTx: DbLike, projectId: string) {
  return dbOrTx
    .select()
    .from(crelioV6ProjectPolicies)
    .where(eq(crelioV6ProjectPolicies.projectId, projectId))
    .then((rows: Array<typeof crelioV6ProjectPolicies.$inferSelect>) => rows[0] ?? null);
}

export async function appendCrelioV6TreeHoldJournal(
  tx: DbLike,
  rootIssueId: string,
  hold: {
    id: string;
    mode: string;
    status: string;
    reason: string | null;
    updatedAt: Date;
  },
) {
  const binding = await loadCrelioV6IssueBinding(tx, rootIssueId);
  if (!binding || binding.rootIssueId !== rootIssueId) return null;
  return appendCrelioV6Journal(tx, {
    projectId: binding.projectId,
    generation: binding.generation,
    entityKind: "issue_tree_hold",
    entityId: hold.id,
    entityVersion: Math.max(1, Math.trunc(hold.updatedAt.getTime())),
    mutationKind: "tree_hold.created",
    reductionPayload: {
      rootIssueId,
      mode: hold.mode,
      status: hold.status,
      reasonSha256: crelioV6Sha256(hold.reason ?? ""),
    },
  });
}

export async function assertCrelioV6ControllerGrant(
  dbOrTx: DbLike,
  input: {
    actor: AuthorizationActor;
    projectId: string;
    generation: string;
    operation: CrelioV6ControllerOperation;
    fencingGeneration: number;
    targetAgentId?: string | null;
  },
) {
  requireGeneration(input.generation);
  requireFencingGeneration(input.fencingGeneration);
  if (input.actor.type !== "board" || input.actor.source !== "board_key" || !input.actor.userId || !input.actor.keyId) {
    throw forbidden("The V6 lifecycle requires the dedicated controller board API key");
  }

  const now = new Date();
  const [policy, key, grant] = await Promise.all([
    loadProjectPolicy(dbOrTx, input.projectId),
    dbOrTx
      .select()
      .from(boardApiKeys)
      .where(eq(boardApiKeys.id, input.actor.keyId))
      .then((rows: Array<typeof boardApiKeys.$inferSelect>) => rows[0] ?? null),
    dbOrTx
      .select()
      .from(crelioV6ControllerGrants)
      .where(and(
        eq(crelioV6ControllerGrants.projectId, input.projectId),
        eq(crelioV6ControllerGrants.generation, input.generation),
        eq(crelioV6ControllerGrants.boardUserId, input.actor.userId),
        eq(crelioV6ControllerGrants.boardApiKeyId, input.actor.keyId),
        isNull(crelioV6ControllerGrants.revokedAt),
        lte(crelioV6ControllerGrants.validFrom, now),
        or(isNull(crelioV6ControllerGrants.validUntil), gt(crelioV6ControllerGrants.validUntil, now)),
      ))
      .then((rows: Array<typeof crelioV6ControllerGrants.$inferSelect>) => rows[0] ?? null),
  ]);

  if (!policy || policy.activeGeneration !== input.generation || policy.schemaFloor < CRELIO_V6_SCHEMA) {
    throw conflict("The requested V6 generation is not active for this project");
  }
  if (
    policy.controllerUserId !== input.actor.userId ||
    policy.activeFencingGeneration !== input.fencingGeneration
  ) {
    throw forbidden("Controller identity or fencing generation does not match the active V6 policy");
  }
  if (!key || key.userId !== input.actor.userId || key.revokedAt || (key.expiresAt && key.expiresAt <= now)) {
    throw forbidden("The V6 controller API key is revoked, expired, or does not match its principal");
  }
  if (!grant || !grant.allowedOperations.includes(input.operation)) {
    throw forbidden("The controller key is not granted this V6 operation");
  }
  if (policy.controllerApiKeyId !== input.actor.keyId) {
    const predecessor = grant.rotationPredecessorId
      ? await dbOrTx.select().from(crelioV6ControllerGrants)
          .where(eq(crelioV6ControllerGrants.id, grant.rotationPredecessorId))
          .then((rows: Array<typeof crelioV6ControllerGrants.$inferSelect>) => rows[0] ?? null)
      : null;
    if (
      !predecessor ||
      predecessor.boardApiKeyId !== policy.controllerApiKeyId ||
      predecessor.boardUserId !== policy.controllerUserId ||
      predecessor.projectId !== input.projectId ||
      predecessor.generation !== input.generation ||
      predecessor.revokedAt ||
      grant.rotationGeneration !== predecessor.rotationGeneration + 1 ||
      stableStringify([...grant.allowedOperations].sort()) !== stableStringify([...predecessor.allowedOperations].sort()) ||
      stableStringify([...grant.allowedAgentIds].sort()) !== stableStringify([...predecessor.allowedAgentIds].sort()) ||
      grant.scopeSha256 !== predecessor.scopeSha256 ||
      !["controller_key.probe", "controller_key.activate"].includes(input.operation)
    ) {
      throw forbidden("Controller key is not the active key or its exact prepared rotation successor");
    }
  }
  if (input.targetAgentId && !grant.allowedAgentIds.includes(input.targetAgentId)) {
    throw forbidden("The requested agent is outside the V6 controller grant");
  }
  return { policy, grant, key };
}

export function crelioV6Service(db: Db) {
  const issuesSvc = issueService(db);
  const budgetsSvc = budgetService(db);
  const heartbeatSvc = heartbeatService(db);
  const treeControlSvc = issueTreeControlService(db);

  async function buildLegacyInventory(dbOrTx: DbLike, projectId: string) {
    const project = await dbOrTx.select().from(projects).where(eq(projects.id, projectId))
      .then((rows: Array<typeof projects.$inferSelect>) => rows[0] ?? null);
    if (!project) throw notFound("Project not found");
    const rows = await dbOrTx.select({
      id: issues.id,
      identifier: issues.identifier,
      parentId: issues.parentId,
      status: issues.status,
      assigneeAgentId: issues.assigneeAgentId,
      assigneeUserId: issues.assigneeUserId,
      checkoutRunId: issues.checkoutRunId,
      executionRunId: issues.executionRunId,
      monitorNextCheckAt: issues.monitorNextCheckAt,
      bindingIssueId: crelioV6IssueBindings.issueId,
    }).from(issues)
      .leftJoin(crelioV6IssueBindings, eq(crelioV6IssueBindings.issueId, issues.id))
      .where(eq(issues.projectId, projectId))
      .orderBy(asc(issues.createdAt), asc(issues.id));
    const legacyRows = rows.filter((row: any) => !row.bindingIssueId);
    const byId = new Map(legacyRows.map((row: any) => [row.id, row]));
    const nonterminal = legacyRows.filter((row: any) => !["done", "cancelled"].includes(row.status));
    const issueIds = nonterminal.map((row: any) => row.id);
    const rootIds = [...new Set(nonterminal.map((row: any) => {
      let current = row;
      const visited = new Set<string>();
      while (current.parentId && byId.has(current.parentId) && !visited.has(current.parentId)) {
        visited.add(current.id);
        current = byId.get(current.parentId)!;
      }
      return current.id;
    }))].sort();
    const runIds: string[] = Array.from(new Set<string>(
      nonterminal.flatMap((row: any) => [row.checkoutRunId, row.executionRunId])
        .filter((value: unknown): value is string => typeof value === "string"),
    ));
    const runs = issueIds.length === 0 ? [] : await dbOrTx.select({
      id: heartbeatRuns.id,
      status: heartbeatRuns.status,
      issueId: sql<string | null>`${heartbeatRuns.contextSnapshot} ->> 'issueId'`,
      scheduledRetryAt: heartbeatRuns.scheduledRetryAt,
    }).from(heartbeatRuns).where(and(
      eq(heartbeatRuns.companyId, project.companyId),
      or(
        inArray(sql<string | null>`${heartbeatRuns.contextSnapshot} ->> 'issueId'`, issueIds),
        ...(runIds.length ? [inArray(heartbeatRuns.id, runIds)] : []),
      )!,
    )).orderBy(asc(heartbeatRuns.createdAt), asc(heartbeatRuns.id));
    const wakes = issueIds.length === 0 ? [] : await dbOrTx.select({
      id: agentWakeupRequests.id,
      status: agentWakeupRequests.status,
      runId: agentWakeupRequests.runId,
      issueId: sql<string | null>`coalesce(${agentWakeupRequests.payload} ->> 'issueId', ${agentWakeupRequests.payload} ->> 'taskId', ${agentWakeupRequests.payload} -> '_paperclipWakeContext' ->> 'issueId')`,
    }).from(agentWakeupRequests).where(and(
      eq(agentWakeupRequests.companyId, project.companyId),
      inArray(
        sql<string | null>`coalesce(${agentWakeupRequests.payload} ->> 'issueId', ${agentWakeupRequests.payload} ->> 'taskId', ${agentWakeupRequests.payload} -> '_paperclipWakeContext' ->> 'issueId')`,
        issueIds,
      ),
    )).orderBy(asc(agentWakeupRequests.requestedAt), asc(agentWakeupRequests.id));
    return {
      schema: CRELIO_V6_SCHEMA,
      projectId,
      companyId: project.companyId,
      roots: rootIds,
      issues: nonterminal.map((row: any) => ({
        id: row.id,
        identifier: row.identifier,
        parentId: row.parentId,
        status: row.status,
        assigneeAgentId: row.assigneeAgentId,
        assigneeUserId: row.assigneeUserId,
        checkoutRunId: row.checkoutRunId,
        executionRunId: row.executionRunId,
        monitorScheduled: Boolean(row.monitorNextCheckAt),
      })),
      runs: runs.map((row: any) => ({
        id: row.id,
        issueId: row.issueId,
        status: row.status,
        scheduledRetry: Boolean(row.scheduledRetryAt),
      })),
      wakes: wakes.map((row: any) => ({
        id: row.id,
        issueId: row.issueId,
        status: row.status,
        runId: row.runId,
      })),
    };
  }

  async function inspectLegacyInventory(input: {
    actor: AuthorizationActor;
    projectId: string;
  }) {
    if (!actorIsBoardSessionAdmin(input.actor)) {
      throw forbidden("Legacy inventory inspection requires an instance-admin board session");
    }
    const inventory = await buildLegacyInventory(db, input.projectId);
    return { inventory, inventorySha256: crelioV6Sha256(inventory) };
  }

  async function freezeLegacyInventory(input: {
    actor: AuthorizationActor;
    projectId: string;
    generation: string;
    expectedInventorySha256: string;
  }) {
    if (!actorIsBoardSessionAdmin(input.actor)) {
      throw forbidden("Legacy freeze requires an instance-admin board session");
    }
    requireGeneration(input.generation);
    requireSha256(input.expectedInventorySha256, "expectedInventorySha256");
    let freeze = await db.select().from(crelioV6LegacyFreezes).where(and(
      eq(crelioV6LegacyFreezes.projectId, input.projectId),
      eq(crelioV6LegacyFreezes.generation, input.generation),
    )).then((rows) => rows[0] ?? null);
    if (!freeze) {
      freeze = await db.transaction(async (tx) => {
        await tx.execute(sql`select id from projects where id = ${input.projectId} for update`);
        const replay = await tx.select().from(crelioV6LegacyFreezes).where(and(
          eq(crelioV6LegacyFreezes.projectId, input.projectId),
          eq(crelioV6LegacyFreezes.generation, input.generation),
        )).then((rows) => rows[0] ?? null);
        if (replay) return replay;
        const inventory = await buildLegacyInventory(tx, input.projectId);
        const inventorySha256 = crelioV6Sha256(inventory);
        if (inventorySha256 !== input.expectedInventorySha256) {
          throw conflict("Legacy inventory changed after preview");
        }
        return tx.insert(crelioV6LegacyFreezes).values({
          projectId: input.projectId,
          companyId: String(inventory.companyId),
          generation: input.generation,
          inventorySha256,
          inventory,
        }).returning().then((rows) => rows[0]);
      });
    }
    if (freeze.inventorySha256 !== input.expectedInventorySha256) {
      throw conflict("Legacy freeze replay has a different inventory hash");
    }
    if (freeze.status === "completed" && freeze.result) {
      return { inventory: freeze.inventory, inventorySha256: freeze.inventorySha256, result: freeze.result, replayed: true };
    }
    const inventory = freeze.inventory as Record<string, any>;
    const roots = Array.isArray(inventory.roots) ? inventory.roots.filter((value): value is string => typeof value === "string") : [];
    const issueRows = Array.isArray(inventory.issues) ? inventory.issues : [];
    const issueIds = issueRows.map((row: any) => row?.id).filter((value: unknown): value is string => typeof value === "string");
    const reason = `[crelio-v6-legacy-freeze:${input.generation}] Frozen at the exclusive V6 boundary.`;
    for (const rootId of roots) {
      const existingHold = await db.select().from(issueTreeHolds).where(and(
        eq(issueTreeHolds.companyId, freeze.companyId),
        eq(issueTreeHolds.rootIssueId, rootId),
        eq(issueTreeHolds.status, "active"),
        eq(issueTreeHolds.mode, "pause"),
        eq(issueTreeHolds.reason, reason),
      )).then((rows) => rows[0] ?? null);
      const preview = await treeControlSvc.preview(freeze.companyId, rootId, {
        mode: "pause",
        releasePolicy: { strategy: "manual", note: "Exclusive V6 legacy freeze" },
      });
      if (!existingHold) {
        await treeControlSvc.createHold(freeze.companyId, rootId, {
          mode: "pause",
          reason,
          releasePolicy: { strategy: "manual", note: "Exclusive V6 legacy freeze" },
          actor: {
            actorType: "user",
            actorId: input.actor.userId!,
            userId: input.actor.userId!,
          },
        });
      }
      for (const run of preview.activeRuns) await heartbeatSvc.cancelRun(run.id);
      await treeControlSvc.cancelUnclaimedWakeupsForTree(
        freeze.companyId,
        rootId,
        "Cancelled by the exclusive V6 legacy freeze",
      );
    }
    if (issueIds.length > 0) {
      await db.update(issues).set({
        assigneeAgentId: null,
        assigneeUserId: null,
        checkoutRunId: null,
        executionRunId: null,
        executionAgentNameKey: null,
        executionLockedAt: null,
        monitorNextCheckAt: null,
        monitorWakeRequestedAt: null,
        updatedAt: new Date(),
      }).where(inArray(issues.id, issueIds));
      await db.update(heartbeatRuns).set({
        scheduledRetryAt: null,
        scheduledRetryReason: null,
        updatedAt: new Date(),
      }).where(inArray(sql<string | null>`${heartbeatRuns.contextSnapshot} ->> 'issueId'`, issueIds));
    }
    const after = await buildLegacyInventory(db, input.projectId);
    const activeRunsAfter = after.runs.filter((row: any) => ["queued", "running"].includes(row.status)).length;
    const queuedWakesAfter = after.wakes.filter((row: any) => ["queued", "deferred_issue_execution"].includes(row.status)).length;
    const assignedIssuesAfter = after.issues.filter((row: any) => row.assigneeAgentId || row.assigneeUserId).length;
    const scheduledRetriesAfter = after.runs.filter((row: any) => row.scheduledRetry).length;
    const activeHeldRoots = roots.length === 0 ? [] : await db.select({ rootIssueId: issueTreeHolds.rootIssueId })
      .from(issueTreeHolds).where(and(
        eq(issueTreeHolds.companyId, freeze.companyId),
        inArray(issueTreeHolds.rootIssueId, roots),
        eq(issueTreeHolds.mode, "pause"),
        eq(issueTreeHolds.status, "active"),
        eq(issueTreeHolds.reason, reason),
      ));
    const heldRoots = new Set(activeHeldRoots.map((row) => row.rootIssueId));
    const result = {
      active_runs_after: activeRunsAfter,
      assigned_issues_after: assignedIssuesAfter,
      queued_wakes_after: queuedWakesAfter,
      scheduled_retries_after: scheduledRetriesAfter,
      releasable_execution_paths_after: roots.filter((rootId) => !heldRoots.has(rootId)).length,
      held_root_ids: [...heldRoots].sort(),
      completed_at: new Date().toISOString(),
    };
    if (Object.entries(result).some(([key, value]) => key.endsWith("_after") && value !== 0)) {
      throw conflict("Legacy freeze read-back still has an executable path", { result });
    }
    const completed = await db.transaction(async (tx) => {
      const updated = await tx.update(crelioV6LegacyFreezes).set({
        status: "completed",
        result,
        completedAt: new Date(),
        updatedAt: new Date(),
      }).where(and(
        eq(crelioV6LegacyFreezes.id, freeze.id),
        eq(crelioV6LegacyFreezes.status, "started"),
      )).returning().then((rows) => rows[0] ?? null);
      const record = updated ?? await tx.select().from(crelioV6LegacyFreezes)
        .where(eq(crelioV6LegacyFreezes.id, freeze.id)).then((rows) => rows[0]);
      if (!record.result || record.inventorySha256 !== input.expectedInventorySha256) {
        throw conflict("Legacy freeze completion lost an idempotency race");
      }
      if (updated) {
        await appendCrelioV6Journal(tx, {
          projectId: input.projectId,
          generation: input.generation,
          entityKind: "legacy_freeze",
          entityId: record.id,
          entityVersion: 1,
          mutationKind: "legacy.frozen",
          reductionPayload: {
            inventorySha256: record.inventorySha256,
            ...record.result,
          },
        });
      }
      return record;
    });
    return { inventory: completed.inventory, inventorySha256: completed.inventorySha256, result: completed.result, replayed: false };
  }

  async function reconcileCre32Terminal(input: {
    actor: AuthorizationActor;
    projectId: string;
    generation: string;
    issueIdentifier: "CRE-32";
    integratedCommit: string;
    mainHead: string;
    archivalSubjectSha256: string;
  }) {
    if (!actorIsBoardSessionAdmin(input.actor)) {
      throw forbidden("CRE-32 terminal reconciliation requires an instance-admin board session");
    }
    requireGeneration(input.generation);
    requireSha256(input.archivalSubjectSha256, "archivalSubjectSha256");
    const project = await db.select().from(projects).where(eq(projects.id, input.projectId))
      .then((rows) => rows[0] ?? null);
    if (!project) throw notFound("Project not found");
    const projectIssues = await db.select({
      id: issues.id,
      identifier: issues.identifier,
      parentId: issues.parentId,
      status: issues.status,
      assigneeAgentId: issues.assigneeAgentId,
      assigneeUserId: issues.assigneeUserId,
      checkoutRunId: issues.checkoutRunId,
      executionRunId: issues.executionRunId,
      executionLockedAt: issues.executionLockedAt,
      monitorNextCheckAt: issues.monitorNextCheckAt,
    }).from(issues).where(eq(issues.projectId, input.projectId));
    const root = projectIssues.find((row) => row.identifier === input.issueIdentifier);
    if (!root) throw notFound("CRE-32 was not found in the selected project");
    const treeIds = new Set<string>([root.id]);
    let changed = true;
    while (changed) {
      changed = false;
      for (const row of projectIssues) {
        if (row.parentId && treeIds.has(row.parentId) && !treeIds.has(row.id)) {
          treeIds.add(row.id);
          changed = true;
        }
      }
    }
    const tree = projectIssues.filter((row) => treeIds.has(row.id));
    const nonterminal = tree.filter((row) => !["done", "cancelled"].includes(row.status));
    if (nonterminal.length > 0) {
      throw conflict("CRE-32 tree is not terminal", {
        identifiers: nonterminal.map((row) => row.identifier).sort(),
      });
    }
    const staleExecution = tree.filter((row) =>
      row.assigneeAgentId || row.assigneeUserId || row.checkoutRunId || row.executionRunId
      || row.executionLockedAt || row.monitorNextCheckAt,
    );
    if (staleExecution.length > 0) {
      throw conflict("CRE-32 still has assignment, lock, or monitor state", {
        identifiers: staleExecution.map((row) => row.identifier).sort(),
      });
    }
    const runRows = await db.select({ id: heartbeatRuns.id, status: heartbeatRuns.status })
      .from(heartbeatRuns).where(and(
        eq(heartbeatRuns.companyId, project.companyId),
        inArray(sql<string | null>`${heartbeatRuns.contextSnapshot} ->> 'issueId'`, [...treeIds]),
      ));
    if (runRows.some((row) => ["queued", "running"].includes(row.status))) {
      throw conflict("CRE-32 still has an active heartbeat run");
    }
    const wakeRows = await db.select({ id: agentWakeupRequests.id, status: agentWakeupRequests.status })
      .from(agentWakeupRequests).where(and(
        eq(agentWakeupRequests.companyId, project.companyId),
        inArray(
          sql<string | null>`coalesce(${agentWakeupRequests.payload} ->> 'issueId', ${agentWakeupRequests.payload} ->> 'taskId', ${agentWakeupRequests.payload} -> '_paperclipWakeContext' ->> 'issueId')`,
          [...treeIds],
        ),
      ));
    if (wakeRows.some((row) => ["queued", "deferred_issue_execution", "running"].includes(row.status))) {
      throw conflict("CRE-32 still has a runnable wake");
    }
    const matchingMetadata = (value: unknown) => {
      if (!value || typeof value !== "object" || Array.isArray(value)) return false;
      const metadata = value as Record<string, unknown>;
      return metadata.operation === "crelio_v6_cre32_terminal_reconciliation"
        && metadata.generation === input.generation
        && metadata.integratedCommit === input.integratedCommit
        && metadata.mainHead === input.mainHead
        && metadata.archivalSubjectSha256 === input.archivalSubjectSha256;
    };
    const holds = await db.select().from(issueTreeHolds).where(and(
      eq(issueTreeHolds.companyId, project.companyId),
      eq(issueTreeHolds.rootIssueId, root.id),
      eq(issueTreeHolds.mode, "pause"),
    )).orderBy(asc(issueTreeHolds.createdAt), asc(issueTreeHolds.id));
    const activeHolds = holds.filter((hold) => hold.status === "active");
    const prior = holds.filter((hold) => hold.status === "released" && matchingMetadata(hold.releaseMetadata));
    if (activeHolds.length === 0 && prior.length === 0) {
      throw conflict("CRE-32 has no stale controller hold bound to this reconciliation");
    }
    if (activeHolds.length > 1) {
      throw conflict("CRE-32 has multiple active pause holds; ownership is ambiguous");
    }
    let releasedHoldId = prior.at(-1)?.id ?? null;
    let replayed = activeHolds.length === 0;
    if (activeHolds.length === 1) {
      const released = await treeControlSvc.releaseHold(project.companyId, root.id, activeHolds[0].id, {
        reason: "CRE-32 is terminal and its checksummed integration is present on main; archive the stale controller hold.",
        metadata: {
          operation: "crelio_v6_cre32_terminal_reconciliation",
          generation: input.generation,
          integratedCommit: input.integratedCommit,
          mainHead: input.mainHead,
          archivalSubjectSha256: input.archivalSubjectSha256,
        },
        actor: {
          actorType: "user",
          actorId: input.actor.userId!,
          userId: input.actor.userId!,
        },
      });
      releasedHoldId = released.id;
      replayed = false;
    }
    return {
      schema: CRELIO_V6_SCHEMA,
      projectId: input.projectId,
      generation: input.generation,
      issueId: root.id,
      issueIdentifier: root.identifier,
      treeIssueCount: tree.length,
      terminalIssueCount: tree.length,
      activeRunCount: 0,
      runnableWakeCount: 0,
      releasedHoldId,
      integratedCommit: input.integratedCommit,
      mainHead: input.mainHead,
      archivalSubjectSha256: input.archivalSubjectSha256,
      replayed,
    };
  }

  async function readBudgetOverview(input: {
    actor: AuthorizationActor;
    projectId: string;
    generation: string;
    fencingGeneration: number;
  }) {
    const { policy } = await assertCrelioV6ControllerGrant(db, {
      actor: input.actor,
      projectId: input.projectId,
      generation: input.generation,
      operation: "budget.read",
      fencingGeneration: input.fencingGeneration,
    });
    const overview = await budgetsSvc.overview(policy.companyId);
    if (overview.companyId !== policy.companyId) {
      throw conflict("V6 budget overview company scope diverged");
    }
    return overview;
  }

  async function readDiagnostics(input: {
    actor: AuthorizationActor;
    projectId: string;
    generation: string;
    fencingGeneration: number;
  }) {
    const { policy, grant, key } = await assertCrelioV6ControllerGrant(db, {
      actor: input.actor,
      projectId: input.projectId,
      generation: input.generation,
      operation: "diagnostics.read",
      fencingGeneration: input.fencingGeneration,
    });
    const [journal, bindingCounts, runCounts, wakeCounts, activeHoldCount, freeze] = await Promise.all([
      db.select().from(crelioV6JournalHeads)
        .where(eq(crelioV6JournalHeads.projectId, input.projectId))
        .then((rows) => rows[0] ?? null),
      db.select({
        total: sql<number>`count(*)::integer`,
        active: sql<number>`count(*) filter (where ${crelioV6IssueBindings.lifecycleState} not in ('done','cancelled','abandoned','human_rejected'))::integer`,
      }).from(crelioV6IssueBindings).where(and(
        eq(crelioV6IssueBindings.projectId, input.projectId),
        eq(crelioV6IssueBindings.generation, input.generation),
      )).then((rows) => rows[0] ?? { total: 0, active: 0 }),
      db.select({
        active: sql<number>`count(*) filter (where ${heartbeatRuns.status} in ('queued','running'))::integer`,
      }).from(heartbeatRuns)
        .innerJoin(
          crelioV6IssueBindings,
          sql`${crelioV6IssueBindings.issueId} = case
            when nullif(${heartbeatRuns.contextSnapshot} ->> 'issueId', '')
              ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
            then nullif(${heartbeatRuns.contextSnapshot} ->> 'issueId', '')::uuid
            else null
          end`,
        )
        .where(and(
          eq(crelioV6IssueBindings.projectId, input.projectId),
          eq(crelioV6IssueBindings.generation, input.generation),
        )).then((rows) => rows[0] ?? { active: 0 }),
      db.select({
        runnable: sql<number>`count(*) filter (where ${agentWakeupRequests.status} in ('queued','claimed','deferred_issue_execution'))::integer`,
      }).from(agentWakeupRequests)
        .innerJoin(
          crelioV6IssueBindings,
          sql`${crelioV6IssueBindings.issueId} = case
            when nullif(coalesce(${agentWakeupRequests.payload} ->> 'issueId', ${agentWakeupRequests.payload} ->> 'taskId', ${agentWakeupRequests.payload} -> '_paperclipWakeContext' ->> 'issueId'), '')
              ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
            then nullif(coalesce(${agentWakeupRequests.payload} ->> 'issueId', ${agentWakeupRequests.payload} ->> 'taskId', ${agentWakeupRequests.payload} -> '_paperclipWakeContext' ->> 'issueId'), '')::uuid
            else null
          end`,
        )
        .where(and(
          eq(crelioV6IssueBindings.projectId, input.projectId),
          eq(crelioV6IssueBindings.generation, input.generation),
        )).then((rows) => rows[0] ?? { runnable: 0 }),
      db.select({ count: sql<number>`count(distinct ${issueTreeHolds.id})::integer` }).from(issueTreeHolds)
        .innerJoin(crelioV6IssueBindings, eq(crelioV6IssueBindings.rootIssueId, issueTreeHolds.rootIssueId))
        .where(and(
          eq(crelioV6IssueBindings.projectId, input.projectId),
          eq(crelioV6IssueBindings.generation, input.generation),
          isNull(issueTreeHolds.releasedAt),
        )).then((rows) => Number(rows[0]?.count ?? 0)),
      db.select().from(crelioV6LegacyFreezes).where(and(
        eq(crelioV6LegacyFreezes.projectId, input.projectId),
        eq(crelioV6LegacyFreezes.generation, input.generation),
      )).then((rows) => rows[0] ?? null),
    ]);
    return {
      schema: CRELIO_V6_SCHEMA,
      projectId: input.projectId,
      generation: input.generation,
      policy: {
        schemaFloor: policy.schemaFloor,
        activeGeneration: policy.activeGeneration,
        activeFencingGeneration: policy.activeFencingGeneration,
        activationReceiptSha256: policy.activationReceiptSha256,
        instructionContractSha256: policy.instructionContractSha256,
        budgetPolicySha256: policy.budgetPolicySha256,
        controllerUserId: policy.controllerUserId,
        controllerApiKeyId: policy.controllerApiKeyId,
      },
      controllerGrant: {
        boardUserId: grant.boardUserId,
        boardApiKeyId: grant.boardApiKeyId,
        allowedOperations: [...grant.allowedOperations].sort(),
        allowedAgentIds: [...grant.allowedAgentIds].sort(),
        scopeSha256: grant.scopeSha256,
        validFrom: grant.validFrom,
        validUntil: grant.validUntil,
        revokedAt: grant.revokedAt,
      },
      controllerKey: {
        id: key.id,
        userId: key.userId,
        expiresAt: key.expiresAt,
        revokedAt: key.revokedAt,
      },
      journal: {
        lastSequence: Number(journal?.lastCommittedSequence ?? 0),
        earliestRetainedSequence: Number(journal?.firstRetainedSequence ?? 1),
        retentionWatermark: Number(journal?.retentionWatermark ?? 0),
      },
      counts: {
        boundIssues: Number(bindingCounts.total),
        activeBindings: Number(bindingCounts.active),
        activeRuns: Number(runCounts.active),
        runnableWakes: Number(wakeCounts.runnable),
        activeTreeHolds: activeHoldCount,
      },
      legacyFreeze: freeze ? {
        inventorySha256: freeze.inventorySha256,
        frozenAt: freeze.completedAt,
        result: freeze.result,
      } : null,
    };
  }

  async function prepareGeneration(input: {
    actor: AuthorizationActor;
    projectId: string;
    generation: string;
    controllerUserId: string;
    controllerApiKeyId: string;
    allowedAgentIds: string[];
    allowedOperations: CrelioV6ControllerOperation[];
    fencingGeneration: number;
    expectedVersion: number;
    manifestSha256: string;
    legacyFreezeInventorySha256: string;
    instructionContractSha256: string;
    budgetPolicySha256: string;
    scopeSha256: string;
  }) {
    if (!actorIsBoardSessionAdmin(input.actor)) {
      throw forbidden("Preparing a V6 generation requires an authenticated instance-admin board session");
    }
    requireGeneration(input.generation);
    requireFencingGeneration(input.fencingGeneration);
    for (const [value, field] of [
      [input.manifestSha256, "manifestSha256"],
      [input.legacyFreezeInventorySha256, "legacyFreezeInventorySha256"],
      [input.instructionContractSha256, "instructionContractSha256"],
      [input.budgetPolicySha256, "budgetPolicySha256"],
      [input.scopeSha256, "scopeSha256"],
    ] as const) requireSha256(value, field);
    if (input.allowedAgentIds.length !== 5 || new Set(input.allowedAgentIds).size !== 5) {
      throw unprocessable("V6 requires exactly five distinct allowlisted agent IDs");
    }
    if (new Set(input.allowedOperations).size !== input.allowedOperations.length) {
      throw unprocessable("V6 controller operations must be unique");
    }
    if (
      stableStringify([...input.allowedOperations].sort()) !==
      stableStringify([...CRELIO_V6_CONTROLLER_OPERATIONS].sort())
    ) {
      throw unprocessable("V6 controller grant must contain the exact qualified operation set");
    }

    return db.transaction(async (tx) => {
      const project = await tx
        .select()
        .from(projects)
        .where(eq(projects.id, input.projectId))
        .then((rows) => rows[0] ?? null);
      if (!project) throw notFound("Project not found");
      const [key, agentRows] = await Promise.all([
        tx.select().from(boardApiKeys).where(eq(boardApiKeys.id, input.controllerApiKeyId)).then((rows) => rows[0] ?? null),
        tx.select({ id: agents.id, companyId: agents.companyId }).from(agents).where(inArray(agents.id, input.allowedAgentIds)),
      ]);
      if (!key || key.userId !== input.controllerUserId || key.revokedAt || key.expiresAt) {
        throw unprocessable("Controller key must belong to the controller user, be active, and be non-expiring");
      }
      if (agentRows.length !== 5 || agentRows.some((agent) => agent.companyId !== project.companyId)) {
        throw unprocessable("Every V6 agent target must exist in the project company");
      }

      await tx.execute(sql`select project_id from crelio_v6_project_policies where project_id = ${input.projectId} for update`);
      const existing = await loadProjectPolicy(tx, input.projectId);
      const currentVersion = existing?.optimisticVersion ?? 0;
      if (currentVersion !== input.expectedVersion) {
        throw conflict("Stale V6 project policy version", { expected: input.expectedVersion, actual: currentVersion });
      }

      const now = new Date();
      const nextVersion = currentVersion + 1;
      await tx
        .insert(crelioV6ProjectPolicies)
        .values({
          projectId: project.id,
          companyId: project.companyId,
          schemaFloor: existing?.schemaFloor ?? 0,
          preparedGeneration: input.generation,
          activeGeneration: existing?.activeGeneration ?? null,
          preparedControllerUserId: input.controllerUserId,
          preparedControllerApiKeyId: input.controllerApiKeyId,
          controllerUserId: existing?.controllerUserId ?? null,
          controllerApiKeyId: existing?.controllerApiKeyId ?? null,
          preparedFencingGeneration: input.fencingGeneration,
          activeFencingGeneration: existing?.activeFencingGeneration ?? 0,
          policyVersion: 1,
          optimisticVersion: nextVersion,
          preparedManifestSha256: input.manifestSha256,
          preparedLegacyFreezeInventorySha256: input.legacyFreezeInventorySha256,
          preparedInstructionContractSha256: input.instructionContractSha256,
          preparedBudgetPolicySha256: input.budgetPolicySha256,
          legacyFreezeInventorySha256: existing?.legacyFreezeInventorySha256 ?? null,
          instructionContractSha256: existing?.instructionContractSha256 ?? null,
          budgetPolicySha256: existing?.budgetPolicySha256 ?? null,
          preparedAt: now,
          updatedAt: now,
        })
        .onConflictDoUpdate({
          target: crelioV6ProjectPolicies.projectId,
          set: {
            preparedGeneration: input.generation,
            preparedControllerUserId: input.controllerUserId,
            preparedControllerApiKeyId: input.controllerApiKeyId,
            preparedFencingGeneration: input.fencingGeneration,
            optimisticVersion: nextVersion,
            preparedManifestSha256: input.manifestSha256,
            preparedLegacyFreezeInventorySha256: input.legacyFreezeInventorySha256,
            preparedInstructionContractSha256: input.instructionContractSha256,
            preparedBudgetPolicySha256: input.budgetPolicySha256,
            preparedAt: now,
            updatedAt: now,
          },
        });
      await tx.insert(crelioV6ControllerGrants).values({
        companyId: project.companyId,
        projectId: project.id,
        boardUserId: input.controllerUserId,
        boardApiKeyId: input.controllerApiKeyId,
        generation: input.generation,
        allowedOperations: input.allowedOperations,
        allowedAgentIds: input.allowedAgentIds,
        scopeSha256: input.scopeSha256,
        rotationGeneration: 1,
      }).onConflictDoUpdate({
        target: [
          crelioV6ControllerGrants.boardApiKeyId,
          crelioV6ControllerGrants.projectId,
          crelioV6ControllerGrants.generation,
        ],
        set: {
          allowedOperations: input.allowedOperations,
          allowedAgentIds: input.allowedAgentIds,
          scopeSha256: input.scopeSha256,
          revokedAt: null,
          updatedAt: now,
        },
      });
      const sequence = await appendCrelioV6Journal(tx, {
        projectId: project.id,
        generation: input.generation,
        entityKind: "project_policy",
        entityId: project.id,
        entityVersion: nextVersion,
        mutationKind: "generation.prepared",
        reductionPayload: {
          schemaFloor: existing?.schemaFloor ?? 0,
          manifestSha256: input.manifestSha256,
          controllerApiKeyId: input.controllerApiKeyId,
          scopeSha256: input.scopeSha256,
        },
      });
      return { generation: input.generation, state: "prepared", version: nextVersion, journalSequence: sequence };
    });
  }

  async function activateGeneration(input: {
    actor: AuthorizationActor;
    projectId: string;
    generation: string;
    fencingGeneration: number;
    expectedVersion: number;
    manifestSha256: string;
    activationReceiptSha256: string;
  }) {
    requireGeneration(input.generation);
    requireFencingGeneration(input.fencingGeneration);
    requireSha256(input.manifestSha256, "manifestSha256");
    requireSha256(input.activationReceiptSha256, "activationReceiptSha256");
    if (!actorIsBoardSessionAdmin(input.actor)) {
      if (input.actor.type !== "board" || input.actor.source !== "board_key") {
        throw forbidden("Activating V6 requires the prepared controller key or an instance-admin board session");
      }
    }

    return db.transaction(async (tx) => {
      await tx.execute(sql`select project_id from crelio_v6_project_policies where project_id = ${input.projectId} for update`);
      const policy = await loadProjectPolicy(tx, input.projectId);
      if (!policy) throw notFound("V6 project policy not found");
      if (policy.preparedGeneration !== input.generation || policy.preparedManifestSha256 !== input.manifestSha256) {
        throw conflict("Prepared V6 generation or manifest does not match");
      }
      if (policy.optimisticVersion !== input.expectedVersion) {
        throw conflict("Stale V6 project policy version", { expected: input.expectedVersion, actual: policy.optimisticVersion });
      }
      if (input.actor.source === "board_key") {
        if (policy.preparedControllerUserId !== input.actor.userId || policy.preparedControllerApiKeyId !== input.actor.keyId) {
          throw forbidden("Only the exact prepared controller key may activate this generation");
        }
      }
      if (
        policy.preparedFencingGeneration !== input.fencingGeneration ||
        !policy.preparedControllerUserId ||
        !policy.preparedControllerApiKeyId ||
        !policy.preparedLegacyFreezeInventorySha256 ||
        !policy.preparedInstructionContractSha256 ||
        !policy.preparedBudgetPolicySha256
      ) {
        throw conflict("Prepared V6 generation policy is incomplete or uses a different fence");
      }
      const completedFreeze = await tx.select().from(crelioV6LegacyFreezes).where(and(
        eq(crelioV6LegacyFreezes.projectId, input.projectId),
        eq(crelioV6LegacyFreezes.generation, input.generation),
        eq(crelioV6LegacyFreezes.status, "completed"),
      )).then((rows) => rows[0] ?? null);
      if (
        !completedFreeze ||
        completedFreeze.inventorySha256 !== policy.preparedLegacyFreezeInventorySha256 ||
        !completedFreeze.completedAt ||
        !completedFreeze.result
      ) {
        throw conflict("Generation activation requires the exact completed legacy-freeze inventory");
      }
      if (policy.activeGeneration && policy.activeGeneration !== input.generation) {
        const priorIssueIds = await tx.select({ issueId: crelioV6IssueBindings.issueId })
          .from(crelioV6IssueBindings).where(and(
            eq(crelioV6IssueBindings.projectId, input.projectId),
            eq(crelioV6IssueBindings.generation, policy.activeGeneration),
          ));
        if (priorIssueIds.length > 0) {
          const ids = priorIssueIds.map((row) => row.issueId);
          const [activeRun, runnableWake] = await Promise.all([
            tx.select({ id: heartbeatRuns.id }).from(heartbeatRuns).where(and(
              inArray(sql<string | null>`${heartbeatRuns.contextSnapshot} ->> 'issueId'`, ids),
              inArray(heartbeatRuns.status, ["queued", "running"]),
            )).then((rows) => rows[0] ?? null),
            tx.select({ id: agentWakeupRequests.id }).from(agentWakeupRequests).where(and(
              inArray(sql<string | null>`coalesce(${agentWakeupRequests.payload} ->> 'issueId', ${agentWakeupRequests.payload} ->> 'taskId')`, ids),
              inArray(agentWakeupRequests.status, ["queued", "claimed", "deferred_issue_execution"]),
            )).then((rows) => rows[0] ?? null),
          ]);
          if (activeRun || runnableWake) {
            throw conflict("Generation activation requires the prior V6 generation to be quiescent");
          }
        }
      }
      const nextVersion = policy.optimisticVersion + 1;
      const now = new Date();
      const updated = await tx
        .update(crelioV6ProjectPolicies)
        .set({
          schemaFloor: CRELIO_V6_SCHEMA,
          activeGeneration: input.generation,
          controllerUserId: policy.preparedControllerUserId,
          controllerApiKeyId: policy.preparedControllerApiKeyId,
          activeFencingGeneration: input.fencingGeneration,
          legacyFreezeInventorySha256: policy.preparedLegacyFreezeInventorySha256,
          instructionContractSha256: policy.preparedInstructionContractSha256,
          budgetPolicySha256: policy.preparedBudgetPolicySha256,
          activationReceiptSha256: input.activationReceiptSha256,
          optimisticVersion: nextVersion,
          activatedAt: now,
          updatedAt: now,
        })
        .where(and(
          eq(crelioV6ProjectPolicies.projectId, input.projectId),
          eq(crelioV6ProjectPolicies.optimisticVersion, input.expectedVersion),
        ))
        .returning()
        .then((rows) => rows[0] ?? null);
      if (!updated) throw conflict("V6 generation activation lost an optimistic-version race");
      if (policy.activeGeneration && policy.activeGeneration !== input.generation) {
        await tx.update(crelioV6ControllerGrants).set({ revokedAt: now, updatedAt: now })
          .where(and(
            eq(crelioV6ControllerGrants.projectId, input.projectId),
            eq(crelioV6ControllerGrants.generation, policy.activeGeneration),
            isNull(crelioV6ControllerGrants.revokedAt),
          ));
      }
      const sequence = await appendCrelioV6Journal(tx, {
        projectId: input.projectId,
        generation: input.generation,
        entityKind: "project_policy",
        entityId: input.projectId,
        entityVersion: nextVersion,
        mutationKind: "generation.activated",
        reductionPayload: {
          schemaFloor: CRELIO_V6_SCHEMA,
          activationReceiptSha256: input.activationReceiptSha256,
          fencingGeneration: input.fencingGeneration,
        },
      });
      return { generation: input.generation, state: "active", version: nextVersion, journalSequence: sequence };
    });
  }

  async function prepareControllerKeyRotation(input: {
    actor: AuthorizationActor;
    projectId: string;
    generation: string;
    fencingGeneration: number;
    expectedVersion: number;
    controllerUserId: string;
    newControllerApiKeyId: string;
    allowedOperations: CrelioV6ControllerOperation[];
    allowedAgentIds: string[];
    scopeSha256: string;
  }) {
    if (!actorIsBoardSessionAdmin(input.actor)) {
      throw forbidden("Preparing controller-key rotation requires an instance-admin board session");
    }
    requireGeneration(input.generation);
    requireFencingGeneration(input.fencingGeneration);
    requireSha256(input.scopeSha256, "scopeSha256");
    if (
      input.allowedAgentIds.length !== 5 ||
      new Set(input.allowedAgentIds).size !== 5 ||
      stableStringify([...input.allowedOperations].sort()) !==
        stableStringify([...CRELIO_V6_CONTROLLER_OPERATIONS].sort())
    ) {
      throw unprocessable("Controller-key rotation must preserve the exact V6 grant");
    }

    return db.transaction(async (tx) => {
      await tx.execute(sql`select project_id from crelio_v6_project_policies where project_id = ${input.projectId} for update`);
      const policy = await loadProjectPolicy(tx, input.projectId);
      if (
        !policy ||
        policy.schemaFloor < CRELIO_V6_SCHEMA ||
        policy.activeGeneration !== input.generation ||
        policy.activeFencingGeneration !== input.fencingGeneration ||
        policy.controllerUserId !== input.controllerUserId ||
        !policy.controllerApiKeyId
      ) {
        throw conflict("Active V6 controller policy does not match the rotation request");
      }
      const [currentGrant, newKey, existingSuccessor] = await Promise.all([
        tx.select().from(crelioV6ControllerGrants).where(and(
          eq(crelioV6ControllerGrants.projectId, input.projectId),
          eq(crelioV6ControllerGrants.generation, input.generation),
          eq(crelioV6ControllerGrants.boardApiKeyId, policy.controllerApiKeyId),
          isNull(crelioV6ControllerGrants.revokedAt),
        )).then((rows) => rows[0] ?? null),
        tx.select().from(boardApiKeys).where(eq(boardApiKeys.id, input.newControllerApiKeyId))
          .then((rows) => rows[0] ?? null),
        tx.select().from(crelioV6ControllerGrants).where(and(
          eq(crelioV6ControllerGrants.projectId, input.projectId),
          eq(crelioV6ControllerGrants.generation, input.generation),
          eq(crelioV6ControllerGrants.boardApiKeyId, input.newControllerApiKeyId),
        )).then((rows) => rows[0] ?? null),
      ]);
      if (!currentGrant) throw conflict("Active controller grant is missing");
      if (
        !newKey ||
        newKey.userId !== input.controllerUserId ||
        newKey.revokedAt ||
        newKey.expiresAt
      ) {
        throw unprocessable("Rotation successor must be an active non-expiring key for the controller principal");
      }
      const exactGrant =
        stableStringify([...currentGrant.allowedOperations].sort()) === stableStringify([...input.allowedOperations].sort()) &&
        stableStringify([...currentGrant.allowedAgentIds].sort()) === stableStringify([...input.allowedAgentIds].sort()) &&
        currentGrant.scopeSha256 === input.scopeSha256;
      if (!exactGrant) throw conflict("Rotation would expand or change the active controller grant");
      if (existingSuccessor) {
        if (
          existingSuccessor.rotationPredecessorId !== currentGrant.id ||
          existingSuccessor.rotationGeneration !== currentGrant.rotationGeneration + 1 ||
          existingSuccessor.revokedAt ||
          !exactGrant
        ) {
          throw conflict("Controller rotation successor already exists with divergent state");
        }
        return {
          state: "prepared",
          replayed: true,
          version: policy.optimisticVersion,
          predecessorKeyId: currentGrant.boardApiKeyId,
          successorKeyId: existingSuccessor.boardApiKeyId,
          rotationGeneration: existingSuccessor.rotationGeneration,
          journalSequence: null,
        };
      }
      const otherSuccessor = await tx.select({ id: crelioV6ControllerGrants.id })
        .from(crelioV6ControllerGrants).where(and(
          eq(crelioV6ControllerGrants.rotationPredecessorId, currentGrant.id),
          isNull(crelioV6ControllerGrants.revokedAt),
        )).then((rows) => rows[0] ?? null);
      if (otherSuccessor) throw conflict("A different controller-key rotation is already prepared");
      if (policy.optimisticVersion !== input.expectedVersion) {
        throw conflict("Stale V6 project policy version", { expected: input.expectedVersion, actual: policy.optimisticVersion });
      }
      const now = new Date();
      const nextVersion = policy.optimisticVersion + 1;
      const successor = await tx.insert(crelioV6ControllerGrants).values({
        companyId: policy.companyId,
        projectId: input.projectId,
        boardUserId: input.controllerUserId,
        boardApiKeyId: input.newControllerApiKeyId,
        generation: input.generation,
        allowedOperations: input.allowedOperations,
        allowedAgentIds: input.allowedAgentIds,
        scopeSha256: input.scopeSha256,
        rotationPredecessorId: currentGrant.id,
        rotationGeneration: currentGrant.rotationGeneration + 1,
      }).returning().then((rows) => rows[0]);
      await tx.update(crelioV6ProjectPolicies).set({
        optimisticVersion: nextVersion,
        updatedAt: now,
      }).where(and(
        eq(crelioV6ProjectPolicies.projectId, input.projectId),
        eq(crelioV6ProjectPolicies.optimisticVersion, input.expectedVersion),
      ));
      const sequence = await appendCrelioV6Journal(tx, {
        projectId: input.projectId,
        generation: input.generation,
        entityKind: "controller_key_grant",
        entityId: successor.id,
        entityVersion: successor.rotationGeneration,
        mutationKind: "controller_key.rotation_prepared",
        reductionPayload: {
          predecessorKeyId: currentGrant.boardApiKeyId,
          successorKeyId: successor.boardApiKeyId,
          rotationGeneration: successor.rotationGeneration,
          scopeSha256: successor.scopeSha256,
        },
      });
      return {
        state: "prepared",
        replayed: false,
        version: nextVersion,
        predecessorKeyId: currentGrant.boardApiKeyId,
        successorKeyId: successor.boardApiKeyId,
        rotationGeneration: successor.rotationGeneration,
        journalSequence: sequence,
      };
    });
  }

  async function activateControllerKeyRotation(input: {
    actor: AuthorizationActor;
    projectId: string;
    generation: string;
    fencingGeneration: number;
    expectedVersion: number;
    predecessorKeyId: string;
  }) {
    const admitted = await assertCrelioV6ControllerGrant(db, {
      actor: input.actor,
      projectId: input.projectId,
      generation: input.generation,
      operation: "controller_key.activate",
      fencingGeneration: input.fencingGeneration,
    });
    if (
      admitted.policy.controllerApiKeyId === input.actor.keyId &&
      admitted.grant.rotationPredecessorId
    ) {
      return {
        state: "active",
        replayed: true,
        version: admitted.policy.optimisticVersion,
        controllerApiKeyId: input.actor.keyId,
        rotationGeneration: admitted.grant.rotationGeneration,
      };
    }
    if (admitted.policy.controllerApiKeyId !== input.predecessorKeyId) {
      throw conflict("Rotation predecessor does not match the active controller key");
    }
    return db.transaction(async (tx) => {
      await tx.execute(sql`select project_id from crelio_v6_project_policies where project_id = ${input.projectId} for update`);
      const policy = await loadProjectPolicy(tx, input.projectId);
      if (!policy) throw notFound("V6 project policy not found");
      if (
        policy.optimisticVersion !== input.expectedVersion ||
        policy.controllerApiKeyId !== input.predecessorKeyId ||
        policy.activeGeneration !== input.generation ||
        policy.activeFencingGeneration !== input.fencingGeneration
      ) {
        throw conflict("Controller-key activation preconditions are stale");
      }
      const successor = await tx.select().from(crelioV6ControllerGrants).where(and(
        eq(crelioV6ControllerGrants.projectId, input.projectId),
        eq(crelioV6ControllerGrants.generation, input.generation),
        eq(crelioV6ControllerGrants.boardApiKeyId, input.actor.keyId!),
        isNull(crelioV6ControllerGrants.revokedAt),
      )).then((rows) => rows[0] ?? null);
      const predecessor = successor?.rotationPredecessorId
        ? await tx.select().from(crelioV6ControllerGrants)
            .where(eq(crelioV6ControllerGrants.id, successor.rotationPredecessorId))
            .then((rows) => rows[0] ?? null)
        : null;
      if (
        !successor ||
        !predecessor ||
        predecessor.boardApiKeyId !== input.predecessorKeyId ||
        predecessor.revokedAt
      ) throw conflict("Prepared controller-key rotation successor is missing");
      const issueIds = await tx.select({ issueId: crelioV6IssueBindings.issueId })
        .from(crelioV6IssueBindings).where(and(
          eq(crelioV6IssueBindings.projectId, input.projectId),
          eq(crelioV6IssueBindings.generation, input.generation),
        ));
      if (issueIds.length > 0) {
        const ids = issueIds.map((row) => row.issueId);
        const [activeRun, runnableWake] = await Promise.all([
          tx.select({ id: heartbeatRuns.id }).from(heartbeatRuns).where(and(
            inArray(sql<string | null>`${heartbeatRuns.contextSnapshot} ->> 'issueId'`, ids),
            inArray(heartbeatRuns.status, ["queued", "running"]),
          )).then((rows) => rows[0] ?? null),
          tx.select({ id: agentWakeupRequests.id }).from(agentWakeupRequests).where(and(
            inArray(sql<string | null>`coalesce(${agentWakeupRequests.payload} ->> 'issueId', ${agentWakeupRequests.payload} ->> 'taskId')`, ids),
            inArray(agentWakeupRequests.status, ["queued", "pending", "claimed", "running", "deferred_issue_execution"]),
          )).then((rows) => rows[0] ?? null),
        ]);
        if (activeRun || runnableWake) {
          throw conflict("Controller-key rotation activation requires a quiescent V6 project");
        }
      }
      const now = new Date();
      const nextVersion = policy.optimisticVersion + 1;
      await tx.update(crelioV6ProjectPolicies).set({
        controllerApiKeyId: successor.boardApiKeyId,
        optimisticVersion: nextVersion,
        updatedAt: now,
      }).where(and(
        eq(crelioV6ProjectPolicies.projectId, input.projectId),
        eq(crelioV6ProjectPolicies.optimisticVersion, input.expectedVersion),
      ));
      await tx.update(crelioV6ControllerGrants).set({ revokedAt: now, updatedAt: now })
        .where(and(eq(crelioV6ControllerGrants.id, predecessor.id), isNull(crelioV6ControllerGrants.revokedAt)));
      await tx.update(boardApiKeys).set({ revokedAt: now })
        .where(and(eq(boardApiKeys.id, predecessor.boardApiKeyId), isNull(boardApiKeys.revokedAt)));
      const sequence = await appendCrelioV6Journal(tx, {
        projectId: input.projectId,
        generation: input.generation,
        entityKind: "controller_key_grant",
        entityId: successor.id,
        entityVersion: successor.rotationGeneration,
        mutationKind: "controller_key.rotation_activated",
        reductionPayload: {
          predecessorKeyId: predecessor.boardApiKeyId,
          successorKeyId: successor.boardApiKeyId,
          rotationGeneration: successor.rotationGeneration,
          predecessorRevoked: true,
        },
      });
      return {
        state: "active",
        replayed: false,
        version: nextVersion,
        controllerApiKeyId: successor.boardApiKeyId,
        rotationGeneration: successor.rotationGeneration,
        journalSequence: sequence,
      };
    });
  }

  async function probeControllerKeyRotation(input: {
    actor: AuthorizationActor;
    projectId: string;
    generation: string;
    fencingGeneration: number;
  }) {
    const { policy, grant, key } = await assertCrelioV6ControllerGrant(db, {
      actor: input.actor,
      projectId: input.projectId,
      generation: input.generation,
      operation: "controller_key.probe",
      fencingGeneration: input.fencingGeneration,
    });
    return {
      state: policy.controllerApiKeyId === key.id ? "active" : "prepared_successor",
      projectId: input.projectId,
      generation: input.generation,
      controllerUserId: key.userId,
      controllerApiKeyId: key.id,
      predecessorGrantId: grant.rotationPredecessorId,
      rotationGeneration: grant.rotationGeneration,
      scopeSha256: grant.scopeSha256,
      expiresAt: key.expiresAt,
      revokedAt: key.revokedAt,
    };
  }

  async function advanceFence(input: {
    actor: AuthorizationActor;
    projectId: string;
    generation: string;
    previousFencingGeneration: number;
    nextFencingGeneration: number;
    expectedVersion: number;
  }) {
    requireFencingGeneration(input.previousFencingGeneration);
    requireFencingGeneration(input.nextFencingGeneration);
    if (input.nextFencingGeneration <= input.previousFencingGeneration) {
      throw unprocessable("The next fencing generation must be greater than the previous generation");
    }
    const initialPolicy = await loadProjectPolicy(db, input.projectId);
    if (!initialPolicy) throw notFound("V6 project policy not found");
    const advancingPrepared = initialPolicy.preparedGeneration === input.generation
      && initialPolicy.activeGeneration !== input.generation;
    if (advancingPrepared) {
      if (
        input.actor.type !== "board" || input.actor.source !== "board_key" ||
        !input.actor.userId || !input.actor.keyId ||
        initialPolicy.preparedControllerUserId !== input.actor.userId ||
        initialPolicy.preparedControllerApiKeyId !== input.actor.keyId ||
        initialPolicy.preparedFencingGeneration !== input.previousFencingGeneration
      ) {
        throw forbidden("Prepared generation fencing requires its exact prepared controller key and fence");
      }
      const now = new Date();
      const [key, grant] = await Promise.all([
        db.select().from(boardApiKeys).where(eq(boardApiKeys.id, input.actor.keyId))
          .then((rows) => rows[0] ?? null),
        db.select().from(crelioV6ControllerGrants).where(and(
          eq(crelioV6ControllerGrants.projectId, input.projectId),
          eq(crelioV6ControllerGrants.generation, input.generation),
          eq(crelioV6ControllerGrants.boardUserId, input.actor.userId),
          eq(crelioV6ControllerGrants.boardApiKeyId, input.actor.keyId),
          isNull(crelioV6ControllerGrants.revokedAt),
        )).then((rows) => rows[0] ?? null),
      ]);
      if (
        !key || key.userId !== input.actor.userId || key.revokedAt ||
        (key.expiresAt && key.expiresAt <= now) ||
        !grant || !grant.allowedOperations.includes("generation.fence")
      ) {
        throw forbidden("Prepared generation controller key is invalid or lacks fencing authority");
      }
    } else {
      await assertCrelioV6ControllerGrant(db, {
        actor: input.actor,
        projectId: input.projectId,
        generation: input.generation,
        operation: "generation.fence",
        fencingGeneration: input.previousFencingGeneration,
      });
    }
    return db.transaction(async (tx) => {
      const field = advancingPrepared
        ? crelioV6ProjectPolicies.preparedFencingGeneration
        : crelioV6ProjectPolicies.activeFencingGeneration;
      const generationField = advancingPrepared
        ? crelioV6ProjectPolicies.preparedGeneration
        : crelioV6ProjectPolicies.activeGeneration;
      const updated = await tx
        .update(crelioV6ProjectPolicies)
        .set({
          ...(advancingPrepared
            ? { preparedFencingGeneration: input.nextFencingGeneration }
            : { activeFencingGeneration: input.nextFencingGeneration }),
          optimisticVersion: sql`${crelioV6ProjectPolicies.optimisticVersion} + 1`,
          updatedAt: new Date(),
        })
        .where(and(
          eq(crelioV6ProjectPolicies.projectId, input.projectId),
          eq(generationField, input.generation),
          eq(field, input.previousFencingGeneration),
          eq(crelioV6ProjectPolicies.optimisticVersion, input.expectedVersion),
        ))
        .returning()
        .then((rows) => rows[0] ?? null);
      if (!updated) throw conflict("V6 fence advance lost a policy-version race");
      const sequence = await appendCrelioV6Journal(tx, {
        projectId: input.projectId,
        generation: input.generation,
        entityKind: "project_policy",
        entityId: input.projectId,
        entityVersion: updated.optimisticVersion,
        mutationKind: advancingPrepared ? "generation.prepared_fenced" : "generation.fenced",
        reductionPayload: {
          state: advancingPrepared ? "prepared" : "active",
          previousFencingGeneration: input.previousFencingGeneration,
          nextFencingGeneration: input.nextFencingGeneration,
        },
      });
      return { policy: updated, journalSequence: sequence };
    });
  }

  async function createIssue(input: {
    actor: AuthorizationActor;
    projectId: string;
    generation: string;
    fencingGeneration: number;
    idempotencyKey: string;
    issueId: string;
    rootIssueId?: string | null;
    phase: string;
    attempt: number;
    controllerStateVersion: number;
    workspaceAnchorIssueId?: string | null;
    inheritExecutionWorkspaceFromIssueId?: string | null;
    title: string;
    description: string;
    parentId?: string | null;
    assigneeAgentId?: string | null;
    responsibleUserId: string;
    assigneeAdapterOverrides?: Record<string, unknown> | null;
    executionPolicy?: Record<string, unknown> | null;
  }) {
    if (!input.idempotencyKey.trim() || input.idempotencyKey.length > 200) throw unprocessable("Invalid idempotency key");
    if (!Number.isSafeInteger(input.controllerStateVersion) || input.controllerStateVersion < 1) {
      throw unprocessable("controllerStateVersion must be a positive safe integer");
    }
    if (!Number.isSafeInteger(input.attempt) || input.attempt < 1) throw unprocessable("attempt must be positive");
    if (input.executionPolicy != null) {
      throw unprocessable("V6 issue creation cannot install an execution policy; Final Handoff policy is installed separately");
    }
    if (input.phase === "root" && (input.assigneeAgentId || input.parentId || input.rootIssueId)) {
      throw unprocessable("The passive V6 root must be unassigned, parentless, and self-rooted");
    }
    if (input.phase !== "root" && !CRELIO_V6_PHASES.includes(input.phase as (typeof CRELIO_V6_PHASES)[number])) {
      throw unprocessable("Unknown schema-v6 article phase");
    }
    if (input.phase !== "root") {
      if (!input.rootIssueId || input.parentId !== input.rootIssueId || !input.assigneeAgentId) {
        throw unprocessable("A V6 phase must be assigned and be a direct child of its passive root");
      }
      if (input.phase === "strategy_intake") {
        if (input.workspaceAnchorIssueId || input.inheritExecutionWorkspaceFromIssueId) {
          throw unprocessable("Strategy Intake creates the workspace anchor and cannot inherit one");
        }
      } else if (
        !input.workspaceAnchorIssueId ||
        input.inheritExecutionWorkspaceFromIssueId !== input.workspaceAnchorIssueId
      ) {
        throw unprocessable("Every post-bootstrap V6 phase must inherit the exact Strategy Intake workspace anchor");
      }
    }
    await assertCrelioV6ControllerGrant(db, {
      actor: input.actor,
      projectId: input.projectId,
      generation: input.generation,
      operation: "issue.create",
      fencingGeneration: input.fencingGeneration,
      targetAgentId: input.assigneeAgentId,
    });
    const createRequestSha256 = crelioV6Sha256({
      projectId: input.projectId,
      generation: input.generation,
      fencingGeneration: input.fencingGeneration,
      idempotencyKey: input.idempotencyKey,
      issueId: input.issueId,
      rootIssueId: input.rootIssueId ?? null,
      phase: input.phase,
      attempt: input.attempt,
      controllerStateVersion: input.controllerStateVersion,
      workspaceAnchorIssueId: input.workspaceAnchorIssueId ?? null,
      inheritExecutionWorkspaceFromIssueId: input.inheritExecutionWorkspaceFromIssueId ?? null,
      title: input.title,
      description: input.description,
      parentId: input.parentId ?? null,
      assigneeAgentId: input.assigneeAgentId ?? null,
      responsibleUserId: input.responsibleUserId,
      assigneeAdapterOverrides: input.assigneeAdapterOverrides ?? null,
      executionPolicy: null,
    });

    return db.transaction(async (tx) => {
      const project = await tx.select().from(projects).where(eq(projects.id, input.projectId)).then((rows) => rows[0] ?? null);
      if (!project) throw notFound("Project not found");
      if (input.rootIssueId) {
        const root = await loadCrelioV6IssueBinding(tx, input.rootIssueId);
        if (!root || root.rootIssueId !== input.rootIssueId || root.projectId !== input.projectId || root.generation !== input.generation) {
          throw conflict("V6 root binding does not match the requested chain");
        }
      } else if (input.phase !== "root") {
        throw unprocessable("Only the passive root may omit rootIssueId");
      }
      if (input.workspaceAnchorIssueId) {
        const anchor = await loadCrelioV6IssueBinding(tx, input.workspaceAnchorIssueId);
        if (!anchor || anchor.rootIssueId !== input.rootIssueId || anchor.phase !== "strategy_intake") {
          throw conflict("workspaceAnchorIssueId must be the bound Strategy Intake issue in this chain");
        }
      }

      const issue = await issuesSvc.create(project.companyId, {
        crelioV6AuthorizedCreate: true,
        id: input.issueId,
        projectId: input.projectId,
        parentId: input.parentId ?? null,
        title: input.title,
        description: input.description,
        status: input.phase === "root" ? "todo" : "backlog",
        assigneeAgentId: input.assigneeAgentId ?? null,
        responsibleUserId: input.responsibleUserId,
        assigneeAdapterOverrides: input.assigneeAdapterOverrides ?? null,
        executionPolicy: null,
        inheritExecutionWorkspaceFromIssueId: input.inheritExecutionWorkspaceFromIssueId ?? undefined,
        idempotencyKey: `crelio-v6:${input.generation}:${input.idempotencyKey}`,
        allowDuplicate: true,
        trustExplicitResponsibleUserId: true,
        createdByUserId: input.actor.userId ?? null,
        originKind: "crelio_v6",
        originId: input.generation,
      }, tx);
      if (issue.id !== input.issueId) {
        throw conflict("Idempotent V6 issue creation returned an unexpected issue identity");
      }
      const rootIssueId = input.rootIssueId ?? issue.id;
      const existingBinding = await loadCrelioV6IssueBinding(tx, issue.id);
      if (existingBinding) {
        if (existingBinding.createRequestSha256 !== createRequestSha256) {
          throw conflict("V6 issue idempotency key was reused with a different request");
        }
        return { issue, binding: existingBinding, replayed: true, journalSequence: null };
      }
      const binding = await tx.insert(crelioV6IssueBindings).values({
        issueId: issue.id,
        companyId: project.companyId,
        projectId: input.projectId,
        rootIssueId,
        generation: input.generation,
        workflowSchema: CRELIO_V6_SCHEMA,
        controllerStateVersion: input.controllerStateVersion,
        createRequestSha256,
        phase: input.phase,
        currentAttempt: input.attempt,
        workspaceAnchorIssueId: input.workspaceAnchorIssueId ?? (input.phase === "strategy_intake" ? issue.id : null),
        lifecycleState: input.phase === "root" ? "passive" : "backlog",
      }).returning().then((rows) => rows[0]);
      const sequence = await appendCrelioV6Journal(tx, {
        projectId: input.projectId,
        generation: input.generation,
        entityKind: "issue",
        entityId: issue.id,
        entityVersion: binding.issueVersion,
        mutationKind: "issue.created",
        reductionPayload: {
          rootIssueId,
          phase: input.phase,
          attempt: input.attempt,
          status: issue.status,
          assigneeAgentId: issue.assigneeAgentId,
          workspaceAnchorIssueId: binding.workspaceAnchorIssueId,
        },
      });
      return { issue, binding, replayed: false, journalSequence: sequence };
    });
  }

  async function activateIssue(input: {
    actor: AuthorizationActor;
    issueId: string;
    generation: string;
    fencingGeneration: number;
    activationKind: "activate" | "reopen" | "retry" | "human_input_release";
    attempt: number;
    idempotencyKey: string;
    nonce: string;
    expectedIssueVersion: number;
    expectedControllerStateVersion: number;
    expectedStatus: string;
    assigneeAgentId: string;
    expiresAt: Date;
    context: Record<string, unknown>;
  }) {
    if (input.nonce.length < 32 || input.nonce.length > 512) throw unprocessable("Lifecycle nonce has an invalid length");
    const binding = await loadCrelioV6IssueBinding(db, input.issueId);
    if (!binding) throw notFound("V6 issue binding not found");
    const operation = input.activationKind === "activate" ? "issue.activate" : "issue.reopen";
    await assertCrelioV6ControllerGrant(db, {
      actor: input.actor,
      projectId: binding.projectId,
      generation: input.generation,
      operation,
      fencingGeneration: input.fencingGeneration,
      targetAgentId: input.assigneeAgentId,
    });
    const nonceSha256 = crelioV6Sha256(input.nonce);
    const requestSha256 = crelioV6Sha256({
      issueId: input.issueId,
      generation: input.generation,
      fencingGeneration: input.fencingGeneration,
      activationKind: input.activationKind,
      attempt: input.attempt,
      idempotencyKey: input.idempotencyKey,
      nonceSha256,
      expectedIssueVersion: input.expectedIssueVersion,
      expectedControllerStateVersion: input.expectedControllerStateVersion,
      expectedStatus: input.expectedStatus,
      assigneeAgentId: input.assigneeAgentId,
      expiresAt: input.expiresAt.toISOString(),
      context: input.context,
    });

    return db.transaction(async (tx) => {
      await tx.execute(sql`select issue_id from crelio_v6_issue_bindings where issue_id = ${input.issueId} for update`);
      const currentBinding = await loadCrelioV6IssueBinding(tx, input.issueId);
      const issue = await tx.select().from(issues).where(eq(issues.id, input.issueId)).then((rows) => rows[0] ?? null);
      if (!currentBinding || !issue) throw notFound("V6 issue not found");
      const existingAuthorization = await tx
        .select()
        .from(crelioV6LifecycleAuthorizations)
        .where(and(
          eq(crelioV6LifecycleAuthorizations.projectId, currentBinding.projectId),
          eq(crelioV6LifecycleAuthorizations.generation, input.generation),
          eq(crelioV6LifecycleAuthorizations.idempotencyKey, input.idempotencyKey),
        ))
        .then((rows) => rows[0] ?? null);
      if (existingAuthorization) {
        if (existingAuthorization.requestSha256 !== requestSha256) {
          throw conflict("V6 lifecycle idempotency key was reused with a different request");
        }
        const run = existingAuthorization.runId
          ? await tx.select().from(heartbeatRuns).where(eq(heartbeatRuns.id, existingAuthorization.runId)).then((rows) => rows[0] ?? null)
          : null;
        return { authorization: existingAuthorization, run, replayed: true, journalSequence: null };
      }
      if (input.expiresAt <= new Date()) throw unprocessable("Lifecycle authorization must expire in the future");
      if (
        currentBinding.generation !== input.generation ||
        currentBinding.issueVersion !== input.expectedIssueVersion ||
        currentBinding.controllerStateVersion !== input.expectedControllerStateVersion ||
        currentBinding.currentAttempt < 1
      ) throw conflict("Stale V6 issue activation precondition");
      const expectedAttempt = input.activationKind === "activate"
        ? currentBinding.currentAttempt
        : currentBinding.currentAttempt + 1;
      if (input.attempt !== expectedAttempt) {
        throw conflict("V6 lifecycle attempt does not match the activation kind");
      }
      if (issue.status !== input.expectedStatus || issue.assigneeAgentId !== input.assigneeAgentId || issue.assigneeUserId) {
        throw conflict("V6 issue status or assignee does not match activation precondition");
      }
      if (currentBinding.phase === "root") {
        throw conflict("The passive V6 root can never be activated");
      }
      const projectPolicy = await loadProjectPolicy(tx, currentBinding.projectId);
      const contextInstructionHash = typeof input.context.instructionContractSha256 === "string"
        ? input.context.instructionContractSha256
        : null;
      if (
        !projectPolicy ||
        !projectPolicy.instructionContractSha256 ||
        !contextInstructionHash ||
        contextInstructionHash !== projectPolicy.instructionContractSha256 ||
        !isSha256(contextInstructionHash)
      ) {
        throw conflict("V6 lifecycle instruction contract does not match the active project policy");
      }
      const issueOverrides = issue.assigneeAdapterOverrides;
      if (!issueOverrides || typeof issueOverrides !== "object" || Array.isArray(issueOverrides)) {
        throw conflict("V6 phase has no issue-level adapter overrides");
      }
      if ((issueOverrides as Record<string, unknown>).modelProfile !== undefined) {
        throw conflict("V6 phases must use exact adapterConfig overrides, not a named model profile");
      }
      assertCrelioV6RuntimeContract(
        input.context.crelioV6RuntimeContract,
        (issueOverrides as Record<string, unknown>).adapterConfig,
      );
      if (currentBinding.phase === "final_handoff") {
        const subject = await tx.select().from(crelioV6ApprovalSubjects)
          .where(eq(crelioV6ApprovalSubjects.issueId, issue.id)).then((rows) => rows[0] ?? null);
        if (!subject || subject.generation !== input.generation) {
          throw conflict("Final Handoff cannot activate before its approval subject is installed");
        }
        if (
          subject.descriptionSha256 !== crelioV6Sha256(issue.description ?? "") ||
          subject.policySha256 !== crelioV6Sha256(issue.executionPolicy ?? null)
        ) {
          throw conflict("Final Handoff approval subject no longer matches its frozen issue");
        }
      } else if (issue.executionPolicy) {
        throw conflict("Only Final Handoff may have a V6 execution policy");
      }
      const expectedProvider = currentBinding.phase === "seo_research"
        ? "dataforseo"
        : currentBinding.phase === "visual_production" ? "image" : null;
      const contextReceipt = typeof input.context.authorizationReceiptSha256 === "string"
        ? input.context.authorizationReceiptSha256
        : null;
      if (expectedProvider) {
        if (
          currentBinding.authorizationOperation !== expectedProvider ||
          !currentBinding.authorizationReceiptSha256 ||
          contextReceipt !== currentBinding.authorizationReceiptSha256 ||
          !currentBinding.authorizationExpiresAt ||
          currentBinding.authorizationExpiresAt <= new Date()
        ) throw conflict("Provider phase cannot activate without its current immutable receipt");
      } else if (currentBinding.authorizationReceiptSha256 || contextReceipt) {
        throw conflict("Non-provider V6 phase cannot carry a provider authorization receipt");
      }
      const inlineContextPacket = input.context.inlineContextPacket;
      const contextSha256 = typeof input.context.contextSha256 === "string"
        ? input.context.contextSha256
        : null;
      if (currentBinding.phase === "strategy_intake") {
        if (typeof inlineContextPacket !== "string" || !contextSha256 || !isSha256(contextSha256)) {
          throw conflict("Strategy Intake requires one hash-bound inline context packet");
        }
        if (Buffer.byteLength(inlineContextPacket, "utf8") > 16 * 1024) {
          throw unprocessable("Strategy Intake inline context packet exceeds 16 KiB");
        }
        let parsedPacket: Record<string, unknown>;
        try {
          const parsed = JSON.parse(inlineContextPacket);
          if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
          parsedPacket = parsed as Record<string, unknown>;
        } catch {
          throw unprocessable("Strategy Intake inline context packet is invalid JSON");
        }
        const suppliedPacketHash = parsedPacket.context_sha256;
        const packetMaterial = { ...parsedPacket };
        delete packetMaterial.context_sha256;
        if (
          suppliedPacketHash !== contextSha256 ||
          crelioV6Sha256(packetMaterial) !== contextSha256 ||
          stableStringify(parsedPacket) !== inlineContextPacket ||
          parsedPacket.schema_version !== CRELIO_V6_SCHEMA ||
          parsedPacket.phase !== "strategy_intake" ||
          parsedPacket.phase_issue_id !== input.issueId ||
          parsedPacket.attempt !== input.attempt
        ) {
          throw conflict("Strategy Intake inline context packet is stale or noncanonical");
        }
      } else if (inlineContextPacket !== undefined) {
        throw conflict("Only Strategy Intake may carry an inline context packet");
      }
      const activeLifecycleRuns = await tx
        .select({
          runId: heartbeatRuns.id,
          issueId: crelioV6LifecycleAuthorizations.issueId,
          status: heartbeatRuns.status,
        })
        .from(crelioV6LifecycleAuthorizations)
        .innerJoin(heartbeatRuns, eq(heartbeatRuns.id, crelioV6LifecycleAuthorizations.runId))
        .where(and(
          eq(crelioV6LifecycleAuthorizations.rootIssueId, currentBinding.rootIssueId),
          eq(crelioV6LifecycleAuthorizations.generation, input.generation),
          inArray(heartbeatRuns.status, ["queued", "running"]),
        ));
      if (activeLifecycleRuns.length > 0) {
        throw conflict("A V6 lifecycle run is already queued or running for this chain", {
          activeLifecycleRuns,
        });
      }

      const activeBindings = await tx
        .select({ issueId: crelioV6IssueBindings.issueId })
        .from(crelioV6IssueBindings)
        .innerJoin(issues, eq(issues.id, crelioV6IssueBindings.issueId))
        .where(and(
          eq(crelioV6IssueBindings.rootIssueId, currentBinding.rootIssueId),
          inArray(issues.status, ["todo", "in_progress", "in_review"]),
        ));
      if (activeBindings.some((row) => row.issueId !== input.issueId)) {
        throw conflict("Another V6 phase is already active for this chain");
      }

      const nextIssueVersion = currentBinding.issueVersion + 1;
      const now = new Date();
      await tx.update(issues).set({
        status: "todo",
        startedAt: null,
        completedAt: null,
        cancelledAt: null,
        updatedAt: now,
      }).where(and(eq(issues.id, input.issueId), eq(issues.status, input.expectedStatus)));
      await tx.update(crelioV6IssueBindings).set({
        issueVersion: nextIssueVersion,
        currentAttempt: input.attempt,
        lifecycleState: "authorized",
        updatedAt: now,
      }).where(eq(crelioV6IssueBindings.issueId, input.issueId));

      const authorizationId = randomUUID();
      const wakeupRequest = await tx.insert(agentWakeupRequests).values({
        companyId: issue.companyId,
        agentId: input.assigneeAgentId,
        source: "automation",
        triggerDetail: "system",
        reason: "crelio_v6_external_lifecycle",
        payload: {
          issueId: input.issueId,
          crelioV6LifecycleAuthorizationId: authorizationId,
          activationKind: input.activationKind,
        },
        status: "queued",
        requestedByActorType: "system",
        requestedByActorId: input.actor.keyId ?? null,
        idempotencyKey: input.idempotencyKey,
      }).returning().then((rows) => rows[0]);
      const contextSnapshot = {
        ...input.context,
        issueId: input.issueId,
        taskId: input.issueId,
        projectId: currentBinding.projectId,
        forceFreshSession: true,
        wakeReason: "crelio_v6_external_lifecycle",
        source: "crelio.v6.controller",
        crelioV6: {
          schema: CRELIO_V6_SCHEMA,
          generation: input.generation,
          controllerStateVersion: input.expectedControllerStateVersion,
          issueVersion: nextIssueVersion,
          attempt: input.attempt,
          activationKind: input.activationKind,
          authorizationId,
          idempotencyKey: input.idempotencyKey,
          fencingGeneration: input.fencingGeneration,
        },
      };
      const run = await tx.insert(heartbeatRuns).values({
        companyId: issue.companyId,
        agentId: input.assigneeAgentId,
        invocationSource: "automation",
        triggerDetail: "system",
        status: "queued",
        responsibleUserId: issue.responsibleUserId,
        wakeupRequestId: wakeupRequest.id,
        contextSnapshot,
        sessionIdBefore: null,
      }).returning().then((rows) => rows[0]);
      await tx.update(agentWakeupRequests).set({ runId: run.id, updatedAt: now }).where(eq(agentWakeupRequests.id, wakeupRequest.id));
      const authorization = await tx.insert(crelioV6LifecycleAuthorizations).values({
        id: authorizationId,
        companyId: issue.companyId,
        projectId: currentBinding.projectId,
        rootIssueId: currentBinding.rootIssueId,
        issueId: input.issueId,
        generation: input.generation,
        attempt: input.attempt,
        activationKind: input.activationKind,
        idempotencyKey: input.idempotencyKey,
        requestSha256,
        nonceSha256,
        expectedIssueVersion: nextIssueVersion,
        expectedControllerStateVersion: input.expectedControllerStateVersion,
        expectedStatus: "todo",
        expectedAssigneeAgentId: input.assigneeAgentId,
        fencingGeneration: input.fencingGeneration,
        wakeupRequestId: wakeupRequest.id,
        runId: run.id,
        expiresAt: input.expiresAt,
      }).returning().then((rows) => rows[0]);
      const sequence = await appendCrelioV6Journal(tx, {
        projectId: currentBinding.projectId,
        generation: input.generation,
        entityKind: "issue",
        entityId: input.issueId,
        entityVersion: nextIssueVersion,
        mutationKind: input.activationKind === "activate" ? "issue.activated" : "issue.reopened",
        reductionPayload: {
          rootIssueId: currentBinding.rootIssueId,
          phase: currentBinding.phase,
          attempt: input.attempt,
          status: "todo",
          assigneeAgentId: input.assigneeAgentId,
          authorizationId,
          wakeupRequestId: wakeupRequest.id,
          runId: run.id,
          forceFreshSession: true,
        },
      });
      const queuedWake = await tx.select().from(agentWakeupRequests)
        .where(eq(agentWakeupRequests.id, wakeupRequest.id)).then((rows) => rows[0]);
      await appendCrelioV6WakeStatusJournal(tx, queuedWake);
      await appendCrelioV6RunStatusJournal(tx, run);
      return { authorization, run, replayed: false, journalSequence: sequence };
    });
  }

  async function installProviderReceipt(input: {
    actor: AuthorizationActor;
    issueId: string;
    generation: string;
    fencingGeneration: number;
    expectedIssueVersion: number;
    expectedControllerStateVersion: number;
    receiptSha256: string;
    operation: "dataforseo" | "image";
    outputPrefix: string;
    expiresAt: Date;
  }) {
    requireSha256(input.receiptSha256, "receiptSha256");
    if (input.expiresAt <= new Date()) throw unprocessable("Provider receipt must expire in the future");
    if (
      !input.outputPrefix ||
      input.outputPrefix.startsWith("/") ||
      input.outputPrefix.includes("..") ||
      !input.outputPrefix.endsWith("/")
    ) throw unprocessable("Provider receipt outputPrefix is unsafe");
    const binding = await loadCrelioV6IssueBinding(db, input.issueId);
    if (!binding) throw notFound("V6 issue binding not found");
    await assertCrelioV6ControllerGrant(db, {
      actor: input.actor,
      projectId: binding.projectId,
      generation: input.generation,
      operation: "provider.receipt.install",
      fencingGeneration: input.fencingGeneration,
    });
    return db.transaction(async (tx) => {
      await tx.execute(sql`select issue_id from crelio_v6_issue_bindings where issue_id = ${input.issueId} for update`);
      const [current, issue] = await Promise.all([
        loadCrelioV6IssueBinding(tx, input.issueId),
        tx.select().from(issues).where(eq(issues.id, input.issueId)).then((rows) => rows[0] ?? null),
      ]);
      if (!current || !issue) throw notFound("V6 provider phase not found");
      const expectedOperation = current.phase === "seo_research"
        ? "dataforseo"
        : current.phase === "visual_production" ? "image" : null;
      if (
        expectedOperation !== input.operation ||
        current.generation !== input.generation ||
        current.controllerStateVersion !== input.expectedControllerStateVersion ||
        issue.status !== "backlog" ||
        issue.executionPolicy
      ) throw conflict("V6 provider receipt does not match a backlog provider phase");
      if (current.authorizationReceiptSha256) {
        if (
          current.authorizationReceiptSha256 !== input.receiptSha256 ||
          current.authorizationOperation !== input.operation ||
          current.authorizationOutputPrefix !== input.outputPrefix ||
          current.authorizationExpiresAt?.getTime() !== input.expiresAt.getTime()
        ) throw conflict("V6 provider phase already has a divergent immutable receipt");
        return { binding: current, replayed: true, journalSequence: null };
      }
      if (current.issueVersion !== input.expectedIssueVersion) {
        throw conflict("V6 provider receipt issue version is stale");
      }
      const nextIssueVersion = current.issueVersion + 1;
      const updated = await tx.update(crelioV6IssueBindings).set({
        issueVersion: nextIssueVersion,
        authorizationReceiptSha256: input.receiptSha256,
        authorizationOperation: input.operation,
        authorizationOutputPrefix: input.outputPrefix,
        authorizationExpiresAt: input.expiresAt,
        updatedAt: new Date(),
      }).where(eq(crelioV6IssueBindings.issueId, input.issueId)).returning().then((rows) => rows[0]);
      const journalSequence = await appendCrelioV6Journal(tx, {
        projectId: current.projectId,
        generation: current.generation,
        entityKind: "provider_receipt",
        entityId: input.issueId,
        entityVersion: nextIssueVersion,
        mutationKind: "provider_receipt.installed",
        reductionPayload: {
          rootIssueId: current.rootIssueId,
          issueId: input.issueId,
          operation: input.operation,
          receiptSha256: input.receiptSha256,
          outputPrefix: input.outputPrefix,
          expiresAt: input.expiresAt.toISOString(),
        },
      });
      return { binding: updated, replayed: false, journalSequence };
    });
  }

  async function readProviderEvidence(input: {
    actor: AuthorizationActor;
    issueId: string;
  }) {
    if (
      input.actor.type !== "board" ||
      input.actor.source !== "board_key" ||
      !input.actor.userId ||
      !input.actor.keyId
    ) throw forbidden("V6 provider evidence requires a read-only board API key");
    const [binding, issue] = await Promise.all([
      loadCrelioV6IssueBinding(db, input.issueId),
      db.select().from(issues).where(eq(issues.id, input.issueId)).then((rows) => rows[0] ?? null),
    ]);
    if (!binding || !issue) throw notFound("V6 provider phase not found");
    if (
      !input.actor.companyIds?.includes(binding.companyId) ||
      !binding.authorizationReceiptSha256 ||
      !binding.authorizationOperation ||
      !binding.authorizationOutputPrefix ||
      !binding.authorizationExpiresAt
    ) throw forbidden("V6 provider evidence is outside this service key or incomplete");
    const [rootIssue, anchorIssue] = await Promise.all([
      db.select().from(issues).where(eq(issues.id, binding.rootIssueId)).then((rows) => rows[0] ?? null),
      binding.workspaceAnchorIssueId
        ? db.select().from(issues).where(eq(issues.id, binding.workspaceAnchorIssueId)).then((rows) => rows[0] ?? null)
        : Promise.resolve(null),
    ]);
    if (!rootIssue || !anchorIssue) throw forbidden("V6 provider chain workspace evidence is incomplete");
    const payload = {
      schema: CRELIO_V6_SCHEMA,
      projectId: binding.projectId,
      rootIssueId: binding.rootIssueId,
      issueId: binding.issueId,
      generation: binding.generation,
      phase: binding.phase,
      controllerStateVersion: binding.controllerStateVersion,
      issueVersion: binding.issueVersion,
      status: issue.status,
      assigneeAgentId: issue.assigneeAgentId,
      descriptionSha256: crelioV6Sha256(issue.description ?? ""),
      rootStatus: rootIssue.status,
      workspaceAnchorIssueId: binding.workspaceAnchorIssueId,
      executionWorkspaceId: issue.executionWorkspaceId,
      anchorExecutionWorkspaceId: anchorIssue.executionWorkspaceId,
      receiptSha256: binding.authorizationReceiptSha256,
      operation: binding.authorizationOperation,
      outputPrefix: binding.authorizationOutputPrefix,
      expiresAt: binding.authorizationExpiresAt,
    };
    return { ...payload, evidenceSha256: crelioV6Sha256(payload) };
  }

  async function readOperatorSession(input: {
    actor: AuthorizationActor;
    projectId: string;
  }) {
    if (
      input.actor.type !== "board" ||
      !["session", "board_key"].includes(input.actor.source ?? "") ||
      !input.actor.userId
    ) throw forbidden("V6 operator access requires an authenticated board session or board API key");
    const [project, policy] = await Promise.all([
      db.select().from(projects)
        .where(eq(projects.id, input.projectId)).then((rows) => rows[0] ?? null),
      loadProjectPolicy(db, input.projectId),
    ]);
    if (!project) throw notFound("V6 operator project not found");
    if (!input.actor.companyIds?.includes(project.companyId)) {
      throw forbidden("V6 operator is not a member of this project company");
    }
    if (
      input.actor.source === "board_key" &&
      (!input.actor.keyId || input.actor.keyId === policy?.controllerApiKeyId)
    ) {
      throw forbidden("The controller service key cannot be used as a human operator credential");
    }
    return {
      schema: CRELIO_V6_SCHEMA,
      userId: input.actor.userId,
      companyId: project.companyId,
      projectId: project.id,
      authenticatedBy: input.actor.source === "session" ? "board_session" : "board_api_key",
      keyId: input.actor.source === "board_key" ? input.actor.keyId : null,
    };
  }

  async function installApprovalSubject(input: {
    actor: AuthorizationActor;
    issueId: string;
    generation: string;
    fencingGeneration: number;
    expectedIssueVersion: number;
    expectedControllerStateVersion: number;
    approverUserId: string;
    stageId: string;
    participantId: string;
    frozenHeadOid: string;
    checkpointSha256: string;
    packageSha256: string;
    attachmentReceiptSha256: string;
    descriptionSha256: string;
    expectedPolicySha256: string;
  }) {
    if (!/^[a-f0-9]{40}([a-f0-9]{24})?$/.test(input.frozenHeadOid)) {
      throw unprocessable("frozenHeadOid must be a complete Git object ID");
    }
    for (const [value, field] of [
      [input.checkpointSha256, "checkpointSha256"],
      [input.packageSha256, "packageSha256"],
      [input.attachmentReceiptSha256, "attachmentReceiptSha256"],
      [input.descriptionSha256, "descriptionSha256"],
      [input.expectedPolicySha256, "expectedPolicySha256"],
    ] as const) requireSha256(value, field);
    const binding = await loadCrelioV6IssueBinding(db, input.issueId);
    if (!binding) throw notFound("V6 issue binding not found");
    await assertCrelioV6ControllerGrant(db, {
      actor: input.actor,
      projectId: binding.projectId,
      generation: input.generation,
      operation: "approval.subject.install",
      fencingGeneration: input.fencingGeneration,
    });
    const policy = normalizeIssueExecutionPolicy({
      mode: "normal",
      commentRequired: true,
      stages: [{
        id: input.stageId,
        type: "approval",
        approvalsNeeded: 1,
        participants: [{ id: input.participantId, type: "user", userId: input.approverUserId }],
      }],
      monitor: null,
    });
    if (!policy) throw unprocessable("Final Handoff approval policy is invalid");
    const policySha256 = crelioV6Sha256(policy);
    if (policySha256 !== input.expectedPolicySha256) {
      throw conflict("Final Handoff policy hash does not match the controller expectation");
    }
    const subjectPayload = {
      issueId: input.issueId,
      generation: input.generation,
      approverUserId: input.approverUserId,
      frozenHeadOid: input.frozenHeadOid,
      checkpointSha256: input.checkpointSha256,
      packageSha256: input.packageSha256,
      attachmentReceiptSha256: input.attachmentReceiptSha256,
      policySha256,
      descriptionSha256: input.descriptionSha256,
    };
    const subjectSha256 = crelioV6Sha256(subjectPayload);

    return db.transaction(async (tx) => {
      await tx.execute(sql`select issue_id from crelio_v6_issue_bindings where issue_id = ${input.issueId} for update`);
      const [currentBinding, issue, existing] = await Promise.all([
        loadCrelioV6IssueBinding(tx, input.issueId),
        tx.select().from(issues).where(eq(issues.id, input.issueId)).then((rows) => rows[0] ?? null),
        tx.select().from(crelioV6ApprovalSubjects).where(eq(crelioV6ApprovalSubjects.issueId, input.issueId))
          .then((rows) => rows[0] ?? null),
      ]);
      if (!currentBinding || !issue) throw notFound("Final Handoff issue not found");
      if (existing) {
        if (existing.subjectSha256 !== subjectSha256) {
          throw conflict("Final Handoff approval subject is already installed with different immutable content");
        }
        return { subject: existing, policy: issue.executionPolicy, replayed: true, journalSequence: null };
      }
      if (
        currentBinding.phase !== "final_handoff" ||
        currentBinding.generation !== input.generation ||
        currentBinding.issueVersion !== input.expectedIssueVersion ||
        currentBinding.controllerStateVersion !== input.expectedControllerStateVersion ||
        issue.status !== "backlog" ||
        issue.executionState != null ||
        issue.executionPolicy != null ||
        issue.assigneeUserId != null ||
        !issue.assigneeAgentId
      ) throw conflict("Final Handoff is not in the exact pre-activation state required to install approval");
      if (crelioV6Sha256(issue.description ?? "") !== input.descriptionSha256) {
        throw conflict("Final Handoff description hash does not match the frozen subject");
      }
      const now = new Date();
      const nextIssueVersion = currentBinding.issueVersion + 1;
      await tx.update(issues).set({ executionPolicy: policy as unknown as Record<string, unknown>, updatedAt: now })
        .where(eq(issues.id, issue.id));
      await tx.update(crelioV6IssueBindings).set({ issueVersion: nextIssueVersion, updatedAt: now })
        .where(eq(crelioV6IssueBindings.issueId, issue.id));
      const subject = await tx.insert(crelioV6ApprovalSubjects).values({
        ...subjectPayload,
        projectId: currentBinding.projectId,
        subjectSha256,
      }).returning().then((rows) => rows[0]);
      const journalSequence = await appendCrelioV6Journal(tx, {
        projectId: currentBinding.projectId,
        generation: input.generation,
        entityKind: "approval_subject",
        entityId: issue.id,
        entityVersion: nextIssueVersion,
        mutationKind: "approval_subject.installed",
        reductionPayload: {
          rootIssueId: currentBinding.rootIssueId,
          issueId: issue.id,
          approverUserId: input.approverUserId,
          subjectSha256,
          policySha256,
          descriptionSha256: input.descriptionSha256,
        },
      });
      return { subject, policy, replayed: false, journalSequence };
    });
  }

  async function finalizeApprovalSubject(input: {
    actor: AuthorizationActor;
    issueId: string;
    generation: string;
    fencingGeneration: number;
    subjectSha256: string;
    handoffFinalizedSha256: string;
  }) {
    requireSha256(input.subjectSha256, "subjectSha256");
    requireSha256(input.handoffFinalizedSha256, "handoffFinalizedSha256");
    const binding = await loadCrelioV6IssueBinding(db, input.issueId);
    if (!binding) throw notFound("V6 issue binding not found");
    await assertCrelioV6ControllerGrant(db, {
      actor: input.actor,
      projectId: binding.projectId,
      generation: input.generation,
      operation: "approval.subject.finalize",
      fencingGeneration: input.fencingGeneration,
    });
    return db.transaction(async (tx) => {
      await tx.execute(sql`select issue_id from crelio_v6_approval_subjects where issue_id = ${input.issueId} for update`);
      const [subject, currentBinding, issue] = await Promise.all([
        tx.select().from(crelioV6ApprovalSubjects).where(eq(crelioV6ApprovalSubjects.issueId, input.issueId))
          .then((rows) => rows[0] ?? null),
        loadCrelioV6IssueBinding(tx, input.issueId),
        tx.select().from(issues).where(eq(issues.id, input.issueId)).then((rows) => rows[0] ?? null),
      ]);
      if (!subject || !currentBinding || !issue) throw notFound("Final Handoff approval subject not found");
      if (subject.subjectSha256 !== input.subjectSha256 || subject.generation !== input.generation) {
        throw conflict("Final Handoff approval subject hash or generation does not match");
      }
      if (subject.handoffFinalizedSha256) {
        if (subject.handoffFinalizedSha256 !== input.handoffFinalizedSha256) {
          throw conflict("Final Handoff was finalized with a different immutable receipt");
        }
        return { subject, replayed: true, journalSequence: null };
      }
      if (issue.status !== "in_review" || issue.assigneeUserId !== subject.approverUserId || issue.assigneeAgentId) {
        throw conflict("Final Handoff must be pending with its configured human approver before finalization");
      }
      if (
        subject.descriptionSha256 !== crelioV6Sha256(issue.description ?? "") ||
        subject.policySha256 !== crelioV6Sha256(issue.executionPolicy ?? null)
      ) throw conflict("Final Handoff subject drifted before finalization");
      const updated = await tx.update(crelioV6ApprovalSubjects).set({
        handoffFinalizedSha256: input.handoffFinalizedSha256,
        updatedAt: new Date(),
      }).where(and(
        eq(crelioV6ApprovalSubjects.issueId, input.issueId),
        isNull(crelioV6ApprovalSubjects.handoffFinalizedSha256),
      )).returning().then((rows) => rows[0] ?? null);
      if (!updated) throw conflict("Final Handoff finalization lost a concurrency race");
      const journalSequence = await appendCrelioV6Journal(tx, {
        projectId: currentBinding.projectId,
        generation: input.generation,
        entityKind: "approval_subject",
        entityId: input.issueId,
        entityVersion: currentBinding.issueVersion,
        mutationKind: "approval_subject.finalized",
        reductionPayload: {
          rootIssueId: currentBinding.rootIssueId,
          issueId: input.issueId,
          subjectSha256: input.subjectSha256,
          handoffFinalizedSha256: input.handoffFinalizedSha256,
        },
      });
      return { subject: updated, replayed: false, journalSequence };
    });
  }

  async function readIntegrationEvidence(input: {
    actor: AuthorizationActor;
    issueId: string;
  }) {
    if (
      input.actor.type !== "board" ||
      input.actor.source !== "board_key" ||
      !input.actor.userId ||
      !input.actor.keyId
    ) {
      throw forbidden("V6 integration evidence requires a board API key");
    }
    const [subject, binding, issue] = await Promise.all([
      db.select().from(crelioV6ApprovalSubjects)
        .where(eq(crelioV6ApprovalSubjects.issueId, input.issueId))
        .then((rows) => rows[0] ?? null),
      loadCrelioV6IssueBinding(db, input.issueId),
      db.select().from(issues).where(eq(issues.id, input.issueId))
        .then((rows) => rows[0] ?? null),
    ]);
    if (!subject || !binding || !issue) throw notFound("V6 Final Handoff evidence not found");
    if (
      binding.phase !== "final_handoff" ||
      input.actor.userId !== subject.approverUserId ||
      subject.decision !== "approved" ||
      !subject.decidedAt ||
      !subject.handoffFinalizedSha256 ||
      issue.status !== "done" ||
      issue.assigneeAgentId ||
      issue.assigneeUserId
    ) {
      throw conflict("V6 Final Handoff does not have a complete matching human approval");
    }
    if (
      subject.descriptionSha256 !== crelioV6Sha256(issue.description ?? "") ||
      subject.policySha256 !== crelioV6Sha256(issue.executionPolicy ?? null)
    ) throw conflict("V6 Final Handoff approval evidence drifted");
    const [attachments, decisions, workspace, policy] = await Promise.all([
      db.select({
        id: issueAttachments.id,
        issueId: issueAttachments.issueId,
        contentType: assets.contentType,
        byteSize: assets.byteSize,
        sha256: assets.sha256,
        originalFilename: assets.originalFilename,
      }).from(issueAttachments).innerJoin(assets, eq(assets.id, issueAttachments.assetId))
        .where(eq(issueAttachments.issueId, input.issueId)).orderBy(asc(issueAttachments.createdAt)),
      db.select({
        id: issueExecutionDecisions.id,
        stageId: issueExecutionDecisions.stageId,
        actorUserId: issueExecutionDecisions.actorUserId,
        outcome: issueExecutionDecisions.outcome,
        createdAt: issueExecutionDecisions.createdAt,
      }).from(issueExecutionDecisions)
        .where(eq(issueExecutionDecisions.issueId, input.issueId))
        .orderBy(asc(issueExecutionDecisions.createdAt)),
      issue.executionWorkspaceId
        ? db.select().from(executionWorkspaces)
          .where(eq(executionWorkspaces.id, issue.executionWorkspaceId))
          .then((rows) => rows[0] ?? null)
        : Promise.resolve(null),
      db.select({
        schemaFloor: crelioV6ProjectPolicies.schemaFloor,
        activeGeneration: crelioV6ProjectPolicies.activeGeneration,
        activeFencingGeneration: crelioV6ProjectPolicies.activeFencingGeneration,
      }).from(crelioV6ProjectPolicies)
        .where(eq(crelioV6ProjectPolicies.projectId, binding.projectId))
        .then((rows) => rows[0] ?? null),
    ]);
    if (
      !policy ||
      policy.schemaFloor !== CRELIO_V6_SCHEMA ||
      policy.activeGeneration !== binding.generation ||
      !policy.activeFencingGeneration
    ) throw conflict("V6 integration evidence has no matching active generation fence");
    const payload = {
      schema: CRELIO_V6_SCHEMA,
      binding: {
        projectId: binding.projectId,
        rootIssueId: binding.rootIssueId,
        generation: binding.generation,
        issueId: binding.issueId,
        phase: binding.phase,
      },
      subject,
      issue: {
        id: issue.id,
        companyId: issue.companyId,
        projectId: issue.projectId,
        status: issue.status,
        executionWorkspaceId: issue.executionWorkspaceId,
        executionState: issue.executionState,
      },
      attachments,
      decisions,
      workspace,
      projectPolicy: policy,
    };
    return { ...payload, evidenceSha256: crelioV6Sha256(payload) };
  }

  async function completeIssue(input: {
    actor: AuthorizationActor;
    issueId: string;
    idempotencyKey: string;
    generation: string;
    attempt: number;
    comment: string;
    disposition: "done" | "blocked" | "in_review";
    commitOid: string;
    handoffSha256: string;
  }) {
    if (input.actor.type !== "agent" || input.actor.source !== "agent_jwt" || !input.actor.agentId || !input.actor.runId) {
      throw forbidden("V6 completion requires the signed current run principal");
    }
    if (!input.comment.trim() || input.comment.length > CRELIO_V6_MAX_COMMENT_CHARS) {
      throw unprocessable(`V6 completion comment must be 1-${CRELIO_V6_MAX_COMMENT_CHARS} characters`);
    }
    if (!/^[a-f0-9]{40}([a-f0-9]{24})?$/.test(input.commitOid)) {
      throw unprocessable("commitOid must be a complete SHA-1 or SHA-256 Git object ID");
    }
    requireSha256(input.handoffSha256, "handoffSha256");
    const requestSha256 = crelioV6Sha256({
      issueId: input.issueId,
      generation: input.generation,
      attempt: input.attempt,
      comment: input.comment,
      disposition: input.disposition,
      commitOid: input.commitOid,
      handoffSha256: input.handoffSha256,
    });

    return db.transaction(async (tx) => {
      await tx.execute(sql`select issue_id from crelio_v6_issue_bindings where issue_id = ${input.issueId} for update`);
      const existingReceipt = await tx
        .select()
        .from(crelioV6CompletionReceipts)
        .where(and(
          eq(crelioV6CompletionReceipts.projectId, sql`(select project_id from crelio_v6_issue_bindings where issue_id = ${input.issueId})`),
          eq(crelioV6CompletionReceipts.generation, input.generation),
          eq(crelioV6CompletionReceipts.idempotencyKey, input.idempotencyKey),
        ))
        .then((rows) => rows[0] ?? null);
      if (existingReceipt) {
        if (existingReceipt.requestSha256 !== requestSha256) {
          throw conflict("V6 completion idempotency key was reused with a different payload");
        }
        return { receipt: existingReceipt, replayed: true };
      }
      const [binding, issue, run, authorization] = await Promise.all([
        loadCrelioV6IssueBinding(tx, input.issueId),
        tx.select().from(issues).where(eq(issues.id, input.issueId)).then((rows) => rows[0] ?? null),
        tx.select().from(heartbeatRuns).where(eq(heartbeatRuns.id, input.actor.runId!)).then((rows) => rows[0] ?? null),
        tx.select().from(crelioV6LifecycleAuthorizations).where(and(
          eq(crelioV6LifecycleAuthorizations.issueId, input.issueId),
          eq(crelioV6LifecycleAuthorizations.consumingRunId, input.actor.runId!),
        )).then((rows) => rows[0] ?? null),
      ]);
      if (!binding || !issue || !run || !authorization) throw conflict("V6 run lifecycle is incomplete");
      if (
        binding.generation !== input.generation ||
        binding.currentAttempt !== input.attempt ||
        issue.assigneeAgentId !== input.actor.agentId ||
        run.agentId !== input.actor.agentId ||
        run.status !== "running" ||
        authorization.attempt !== input.attempt
      ) throw conflict("V6 completion principal, generation, or attempt is stale");
      const allowed = binding.phase === "final_handoff"
        ? new Set(["in_review", "blocked"])
        : new Set(["done", "blocked"]);
      if (!allowed.has(input.disposition)) {
        throw unprocessable("Disposition is not allowed for this V6 phase");
      }
      if (issue.status !== "in_progress" && issue.status !== "todo") {
        throw conflict("V6 completion requires the currently active issue");
      }

      let executionTransition: ReturnType<typeof applyIssueExecutionPolicyTransition> | null = null;
      let finalSubject: typeof crelioV6ApprovalSubjects.$inferSelect | null = null;
      if (binding.phase === "final_handoff" && input.disposition === "in_review") {
        finalSubject = await tx.select().from(crelioV6ApprovalSubjects)
          .where(eq(crelioV6ApprovalSubjects.issueId, issue.id)).then((rows) => rows[0] ?? null);
        if (!finalSubject || finalSubject.generation !== input.generation || finalSubject.decidedAt) {
          throw conflict("Final Handoff approval subject is missing, divergent, or already decided");
        }
        if (
          finalSubject.descriptionSha256 !== crelioV6Sha256(issue.description ?? "") ||
          finalSubject.policySha256 !== crelioV6Sha256(issue.executionPolicy ?? null)
        ) throw conflict("Final Handoff approval subject no longer matches its frozen issue");
        const policy = normalizeIssueExecutionPolicy(issue.executionPolicy);
        if (!policy) throw conflict("Final Handoff approval policy is missing");
        executionTransition = applyIssueExecutionPolicyTransition({
          issue,
          policy,
          requestedStatus: "in_review",
          requestedAssigneePatch: {},
          actor: { agentId: input.actor.agentId, userId: null },
          commentBody: input.comment,
        });
        if (
          executionTransition.patch.status !== "in_review" ||
          executionTransition.patch.assigneeAgentId !== null ||
          executionTransition.patch.assigneeUserId !== finalSubject.approverUserId
        ) throw conflict("Paperclip execution policy did not route Final Handoff to the configured human approver");
      }

      const now = new Date();
      const comment = await tx.insert(issueComments).values({
        companyId: issue.companyId,
        issueId: issue.id,
        authorAgentId: input.actor.agentId,
        authorType: "agent",
        createdByRunId: run.id,
        body: input.comment,
        metadata: {
          version: 1,
          sourceRunId: run.id,
          sections: [{
            title: "Crelio V6 completion",
            rows: [
              { type: "key_value", label: "Generation", value: input.generation },
              { type: "key_value", label: "Attempt", value: String(input.attempt) },
            ],
          }],
        },
      }).returning().then((rows) => rows[0]);
      const nextIssueVersion = binding.issueVersion + 1;
      const updatedIssue = await tx.update(issues).set({
        ...(executionTransition?.patch ?? {}),
        status: input.disposition,
        assigneeAgentId: input.disposition === "in_review" ? null : issue.assigneeAgentId,
        assigneeUserId: input.disposition === "in_review" ? finalSubject!.approverUserId : null,
        completedAt: input.disposition === "done" ? now : null,
        checkoutRunId: null,
        executionRunId: null,
        executionAgentNameKey: null,
        executionLockedAt: null,
        updatedAt: now,
      }).where(eq(issues.id, issue.id)).returning().then((rows) => rows[0]);
      if (input.disposition === "done") await finalizeSummarySlotsForTerminalIssue(tx, updatedIssue as any);
      await tx.update(crelioV6IssueBindings).set({
        issueVersion: nextIssueVersion,
        lifecycleState: input.disposition,
        updatedAt: now,
      }).where(eq(crelioV6IssueBindings.issueId, issue.id));
      const journalSequence = await appendCrelioV6Journal(tx, {
        projectId: binding.projectId,
        generation: input.generation,
        entityKind: "issue",
        entityId: issue.id,
        entityVersion: nextIssueVersion,
        mutationKind: "issue.completed",
        reductionPayload: {
          rootIssueId: binding.rootIssueId,
          phase: binding.phase,
          attempt: input.attempt,
          runId: run.id,
          commentId: comment.id,
          disposition: input.disposition,
          commitOid: input.commitOid,
          handoffSha256: input.handoffSha256,
        },
      });
      const receipt = await tx.insert(crelioV6CompletionReceipts).values({
        companyId: issue.companyId,
        projectId: binding.projectId,
        rootIssueId: binding.rootIssueId,
        issueId: issue.id,
        runId: run.id,
        generation: input.generation,
        attempt: input.attempt,
        idempotencyKey: input.idempotencyKey,
        requestSha256,
        commentId: comment.id,
        commentSha256: crelioV6Sha256(input.comment),
        disposition: input.disposition,
        resultingIssueVersion: nextIssueVersion,
        resultingPolicyVersion: null,
        commitOid: input.commitOid,
        handoffSha256: input.handoffSha256,
        journalSequence,
      }).returning().then((rows) => rows[0]);
      return { receipt, replayed: false };
    });
  }

  async function decideFinalApproval(input: {
    actor: AuthorizationActor;
    issueId: string;
    decision: "approved" | "rejected";
    idempotencyKey: string;
    comment: string;
  }) {
    if (
      input.actor.type !== "board" ||
      !["session", "board_key"].includes(input.actor.source ?? "") ||
      !input.actor.userId
    ) {
      throw forbidden("Final V6 approval requires the configured human board session or board API key");
    }
    if (!input.comment.trim() || input.comment.length > 1_200) {
      throw unprocessable("Final V6 approval comment must be 1-1200 characters");
    }
    if (!input.idempotencyKey.trim() || input.idempotencyKey.length > 200) {
      throw unprocessable("Invalid final approval idempotency key");
    }
    return db.transaction(async (tx) => {
      await tx.execute(sql`select issue_id from crelio_v6_approval_subjects where issue_id = ${input.issueId} for update`);
      const [subject, binding, issue] = await Promise.all([
        tx.select().from(crelioV6ApprovalSubjects).where(eq(crelioV6ApprovalSubjects.issueId, input.issueId))
          .then((rows) => rows[0] ?? null),
        loadCrelioV6IssueBinding(tx, input.issueId),
        tx.select().from(issues).where(eq(issues.id, input.issueId)).then((rows) => rows[0] ?? null),
      ]);
      if (!subject || !binding || !issue || binding.phase !== "final_handoff") {
        throw notFound("Final Handoff approval subject not found");
      }
      const projectPolicy = await loadProjectPolicy(tx, binding.projectId);
      if (
        input.actor.source === "board_key" &&
        (!input.actor.keyId || input.actor.keyId === projectPolicy?.controllerApiKeyId)
      ) {
        throw forbidden("The controller service key cannot decide a human approval subject");
      }
      if (input.actor.userId !== subject.approverUserId) {
        throw forbidden("Only the configured Final Handoff participant may decide this subject");
      }
      const suffix = [
        "",
        "--- Crelio V6 approval subject ---",
        `Checkpoint-SHA256: ${subject.checkpointSha256}`,
        `Package-SHA256: ${subject.packageSha256}`,
        `Attachment-Receipt-SHA256: ${subject.attachmentReceiptSha256}`,
        `Policy-SHA256: ${subject.policySha256}`,
        `Handoff-Finalized-SHA256: ${subject.handoffFinalizedSha256 ?? "missing"}`,
        `Subject-SHA256: ${subject.subjectSha256}`,
        `Decision-Idempotency-Key: ${input.idempotencyKey}`,
      ].join("\n");
      const body = `${input.comment.trim()}${suffix}`;
      const requestSha256 = crelioV6Sha256({
        issueId: input.issueId,
        decision: input.decision,
        idempotencyKey: input.idempotencyKey,
        body,
        subjectSha256: subject.subjectSha256,
      });
      if (subject.decision) {
        const prior = await tx.select().from(issueExecutionDecisions).where(and(
          eq(issueExecutionDecisions.issueId, input.issueId),
          eq(issueExecutionDecisions.actorUserId, input.actor.userId),
        )).orderBy(asc(issueExecutionDecisions.createdAt)).then((rows) => rows.at(-1) ?? null);
        if (
          subject.decision !== input.decision ||
          !prior ||
          crelioV6Sha256({
            issueId: input.issueId,
            decision: subject.decision,
            idempotencyKey: input.idempotencyKey,
            body: prior.body,
            subjectSha256: subject.subjectSha256,
          }) !== requestSha256
        ) throw conflict("Final approval is already decided with a different request");
        return { subject, issue, replayed: true, requestSha256 };
      }
      if (!subject.handoffFinalizedSha256) {
        throw conflict("Final approval is disabled until the handoff finalization barrier is recorded");
      }
      const policy = normalizeIssueExecutionPolicy(issue.executionPolicy);
      if (
        binding.generation !== subject.generation ||
        issue.status !== "in_review" ||
        issue.assigneeUserId !== subject.approverUserId ||
        issue.assigneeAgentId ||
        !policy ||
        crelioV6Sha256(issue.description ?? "") !== subject.descriptionSha256 ||
        crelioV6Sha256(issue.executionPolicy ?? null) !== subject.policySha256
      ) throw conflict("Final Handoff state no longer matches the immutable approval subject");

      const now = new Date();
      const comment = await tx.insert(issueComments).values({
        companyId: issue.companyId,
        issueId: issue.id,
        authorUserId: input.actor.userId,
        authorType: "user",
        body,
        metadata: {
          version: 1,
          sections: [{
            title: "Crelio V6 final approval",
            rows: [
              { type: "key_value", label: "Decision", value: input.decision },
              { type: "key_value", label: "Request SHA-256", value: requestSha256 },
              { type: "key_value", label: "Subject SHA-256", value: subject.subjectSha256 },
            ],
          }],
        },
      }).returning().then((rows) => rows[0]);
      const decisionId = randomUUID();
      let updatedIssue = issue;
      if (input.decision === "approved") {
        const transition = applyIssueExecutionPolicyTransition({
          issue,
          policy,
          requestedStatus: "done",
          requestedAssigneePatch: {},
          actor: { userId: input.actor.userId, agentId: null },
          commentBody: body,
        });
        if (!transition.decision || transition.decision.outcome !== "approved") {
          throw conflict("Native execution policy did not accept the configured final approval");
        }
        const nextExecutionState = transition.patch.executionState;
        if (!nextExecutionState || typeof nextExecutionState !== "object") {
          throw conflict("Native execution policy did not produce a terminal approval state");
        }
        updatedIssue = await tx.update(issues).set({
          ...transition.patch,
          executionState: { ...nextExecutionState, lastDecisionId: decisionId },
          status: "done",
          assigneeAgentId: null,
          assigneeUserId: null,
          completedAt: now,
          updatedAt: now,
        }).where(eq(issues.id, issue.id)).returning().then((rows) => rows[0]);
        await finalizeSummarySlotsForTerminalIssue(tx, updatedIssue as any);
        await tx.insert(issueExecutionDecisions).values({
          id: decisionId,
          companyId: issue.companyId,
          issueId: issue.id,
          stageId: transition.decision.stageId,
          stageType: transition.decision.stageType,
          actorUserId: input.actor.userId,
          outcome: transition.decision.outcome,
          body,
        });
      } else {
        const executionState = issue.executionState && typeof issue.executionState === "object"
          ? issue.executionState as Record<string, unknown>
          : {};
        await tx.update(issues).set({
          executionState: { ...executionState, lastDecisionId: decisionId, lastDecisionOutcome: "changes_requested" },
          updatedAt: now,
        }).where(eq(issues.id, issue.id));
        const activeHold = await tx.select({ id: issueTreeHolds.id }).from(issueTreeHolds).where(and(
          eq(issueTreeHolds.rootIssueId, binding.rootIssueId),
          eq(issueTreeHolds.status, "active"),
        )).then((rows) => rows[0] ?? null);
        if (!activeHold) {
          await tx.insert(issueTreeHolds).values({
            companyId: issue.companyId,
            rootIssueId: binding.rootIssueId,
            mode: "pause",
            status: "active",
            reason: "Crelio V6 final package rejected by configured human approver",
            releasePolicy: { kind: "terminal", code: "human_final_rejection", subjectSha256: subject.subjectSha256 },
            createdByActorType: "user",
            createdByUserId: input.actor.userId,
          });
        }
        await tx.insert(issueExecutionDecisions).values({
          id: decisionId,
          companyId: issue.companyId,
          issueId: issue.id,
          stageId: String((issue.executionState as Record<string, unknown> | null)?.currentStageId ?? "v6-final-approval"),
          stageType: "approval",
          actorUserId: input.actor.userId,
          outcome: "changes_requested",
          body,
        });
      }
      const nextIssueVersion = binding.issueVersion + 1;
      await tx.update(crelioV6IssueBindings).set({
        issueVersion: nextIssueVersion,
        lifecycleState: input.decision === "approved" ? "done" : "human_rejected",
        updatedAt: now,
      }).where(eq(crelioV6IssueBindings.issueId, issue.id));
      const decided = await tx.update(crelioV6ApprovalSubjects).set({
        decidedAt: now,
        decision: input.decision,
        updatedAt: now,
      }).where(and(eq(crelioV6ApprovalSubjects.issueId, issue.id), isNull(crelioV6ApprovalSubjects.decidedAt)))
        .returning().then((rows) => rows[0] ?? null);
      if (!decided) throw conflict("Final approval lost a decision race");
      const journalSequence = await appendCrelioV6Journal(tx, {
        projectId: binding.projectId,
        generation: binding.generation,
        entityKind: "approval_subject",
        entityId: issue.id,
        entityVersion: nextIssueVersion,
        mutationKind: input.decision === "approved" ? "approval_subject.approved" : "approval_subject.rejected",
        reductionPayload: {
          rootIssueId: binding.rootIssueId,
          issueId: issue.id,
          commentId: comment.id,
          decisionId,
          decision: input.decision,
          subjectSha256: subject.subjectSha256,
          requestSha256,
          status: input.decision === "approved" ? "done" : "in_review",
        },
      });
      return { subject: decided, issue: updatedIssue, replayed: false, requestSha256, journalSequence };
    });
  }

  async function closeRoot(input: {
    actor: AuthorizationActor;
    issueId: string;
    finalIssueId: string;
    generation: string;
    fencingGeneration: number;
    expectedIssueVersion: number;
    integrationReceiptSha256: string;
  }) {
    requireSha256(input.integrationReceiptSha256, "integrationReceiptSha256");
    const binding = await loadCrelioV6IssueBinding(db, input.issueId);
    if (!binding) throw notFound("V6 root binding not found");
    await assertCrelioV6ControllerGrant(db, {
      actor: input.actor,
      projectId: binding.projectId,
      generation: input.generation,
      operation: "issue.close_root",
      fencingGeneration: input.fencingGeneration,
    });
    return db.transaction(async (tx) => {
      await tx.execute(sql`select issue_id from crelio_v6_issue_bindings where issue_id = ${input.issueId} for update`);
      const [rootBinding, root, finalBinding, finalIssue, subject] = await Promise.all([
        loadCrelioV6IssueBinding(tx, input.issueId),
        tx.select().from(issues).where(eq(issues.id, input.issueId)).then((rows) => rows[0] ?? null),
        loadCrelioV6IssueBinding(tx, input.finalIssueId),
        tx.select().from(issues).where(eq(issues.id, input.finalIssueId)).then((rows) => rows[0] ?? null),
        tx.select().from(crelioV6ApprovalSubjects).where(eq(crelioV6ApprovalSubjects.issueId, input.finalIssueId))
          .then((rows) => rows[0] ?? null),
      ]);
      if (!rootBinding || !root || !finalBinding || !finalIssue || !subject) {
        throw conflict("V6 root close dependencies are incomplete");
      }
      if (root.status === "done") {
        const prior = await tx.select().from(crelioV6JournalEvents).where(and(
          eq(crelioV6JournalEvents.projectId, rootBinding.projectId),
          eq(crelioV6JournalEvents.entityKind, "issue"),
          eq(crelioV6JournalEvents.entityId, root.id),
          eq(crelioV6JournalEvents.mutationKind, "root.closed"),
        )).orderBy(asc(crelioV6JournalEvents.sequence)).then((rows) => rows.at(-1) ?? null);
        if (prior?.reductionPayload?.integrationReceiptSha256 !== input.integrationReceiptSha256) {
          throw conflict("V6 root was closed against a different integration receipt");
        }
        return { issue: root, replayed: true, journalSequence: prior.sequence };
      }
      if (
        rootBinding.phase !== "root" ||
        rootBinding.rootIssueId !== root.id ||
        rootBinding.generation !== input.generation ||
        rootBinding.issueVersion !== input.expectedIssueVersion ||
        root.status !== "todo" || root.assigneeAgentId || root.assigneeUserId ||
        finalBinding.phase !== "final_handoff" ||
        finalBinding.rootIssueId !== root.id ||
        finalIssue.status !== "done" ||
        subject.decision !== "approved" || !subject.decidedAt
      ) throw conflict("V6 root cannot close before exact final approval and integration preconditions");
      const issueIds = await tx.select({ id: crelioV6IssueBindings.issueId }).from(crelioV6IssueBindings)
        .where(eq(crelioV6IssueBindings.rootIssueId, root.id)).then((rows) => rows.map((row) => row.id));
      const runIssueId = sql<string>`${heartbeatRuns.contextSnapshot} ->> 'issueId'`;
      const activeRuns = await tx.select({ id: heartbeatRuns.id }).from(heartbeatRuns).where(and(
        inArray(runIssueId, issueIds),
        inArray(heartbeatRuns.status, ["queued", "running", "scheduled_retry"]),
      ));
      if (activeRuns.length > 0) throw conflict("V6 root cannot close while a chain run remains active");
      const wakeIssueId = sql<string>`${agentWakeupRequests.payload} ->> 'issueId'`;
      const activeWakes = await tx.select({ id: agentWakeupRequests.id }).from(agentWakeupRequests).where(and(
        inArray(wakeIssueId, issueIds),
        inArray(agentWakeupRequests.status, ["queued", "claimed", "deferred_issue_execution"]),
      ));
      if (activeWakes.length > 0) throw conflict("V6 root cannot close while a chain wake remains active");
      const now = new Date();
      const nextIssueVersion = rootBinding.issueVersion + 1;
      const updated = await tx.update(issues).set({ status: "done", completedAt: now, updatedAt: now })
        .where(and(eq(issues.id, root.id), eq(issues.status, "todo"))).returning().then((rows) => rows[0] ?? null);
      if (!updated) throw conflict("V6 root close lost a state race");
      await finalizeSummarySlotsForTerminalIssue(tx, updated as any);
      await tx.update(crelioV6IssueBindings).set({
        issueVersion: nextIssueVersion,
        lifecycleState: "done",
        updatedAt: now,
      }).where(eq(crelioV6IssueBindings.issueId, root.id));
      const journalSequence = await appendCrelioV6Journal(tx, {
        projectId: rootBinding.projectId,
        generation: rootBinding.generation,
        entityKind: "issue",
        entityId: root.id,
        entityVersion: nextIssueVersion,
        mutationKind: "root.closed",
        reductionPayload: {
          rootIssueId: root.id,
          finalIssueId: finalIssue.id,
          integrationReceiptSha256: input.integrationReceiptSha256,
          subjectSha256: subject.subjectSha256,
          status: "done",
        },
      });
      return { issue: updated, replayed: false, journalSequence };
    });
  }

  async function listEvents(input: {
    actor: AuthorizationActor;
    projectId: string;
    generation: string;
    fencingGeneration: number;
    afterSequence: number;
    limit: number;
  }) {
    await assertCrelioV6ControllerGrant(db, {
      actor: input.actor,
      projectId: input.projectId,
      generation: input.generation,
      operation: "events.read",
      fencingGeneration: input.fencingGeneration,
    });
    const limit = Math.max(1, Math.min(CRELIO_V6_EVENT_LIMIT_MAX, Math.floor(input.limit)));
    const head = await db.select().from(crelioV6JournalHeads)
      .where(eq(crelioV6JournalHeads.projectId, input.projectId)).then((rows) => rows[0] ?? null);
    const firstAvailableSequence = head?.firstRetainedSequence ?? 1;
    const lastCommittedSequence = head?.lastCommittedSequence ?? 0;
    if (input.afterSequence < firstAvailableSequence - 1) {
      throw conflict("V6 journal retention gap", {
        code: "crelio_v6_journal_retention_gap",
        firstAvailableSequence,
        lastCommittedSequence,
      });
    }
    const events = await db.select().from(crelioV6JournalEvents).where(and(
      eq(crelioV6JournalEvents.projectId, input.projectId),
      gt(crelioV6JournalEvents.sequence, input.afterSequence),
    )).orderBy(asc(crelioV6JournalEvents.sequence)).limit(limit);
    return {
      events,
      firstAvailableSeq: firstAvailableSequence,
      lastCommittedSeq: lastCommittedSequence,
      nextAfterSeq: events.at(-1)?.sequence ?? input.afterSequence,
    };
  }

  async function createSnapshot(input: {
    actor: AuthorizationActor;
    projectId: string;
    generation: string;
    fencingGeneration: number;
    rootIssueId: string;
  }) {
    await assertCrelioV6ControllerGrant(db, {
      actor: input.actor,
      projectId: input.projectId,
      generation: input.generation,
      operation: "snapshot.read",
      fencingGeneration: input.fencingGeneration,
    });
    if (!input.actor.keyId) throw forbidden("Snapshot sessions require the controller API key");

    return db.transaction(async (tx) => {
      await tx.execute(sql`set transaction isolation level repeatable read`);
      const policy = await loadProjectPolicy(tx, input.projectId);
      const bindings = await tx.select().from(crelioV6IssueBindings).where(and(
        eq(crelioV6IssueBindings.projectId, input.projectId),
        eq(crelioV6IssueBindings.rootIssueId, input.rootIssueId),
        eq(crelioV6IssueBindings.generation, input.generation),
      )).orderBy(asc(crelioV6IssueBindings.createdAt), asc(crelioV6IssueBindings.issueId));
      if (bindings.length === 0) throw notFound("V6 chain not found");
      const issueIds = bindings.map((binding) => binding.issueId);
      const issueRows = await tx.select({
        id: issues.id,
        parentId: issues.parentId,
        identifier: issues.identifier,
        status: issues.status,
        assigneeAgentId: issues.assigneeAgentId,
        assigneeUserId: issues.assigneeUserId,
        checkoutRunId: issues.checkoutRunId,
        executionRunId: issues.executionRunId,
        executionLockedAt: issues.executionLockedAt,
        executionWorkspaceId: issues.executionWorkspaceId,
        executionState: issues.executionState,
        updatedAt: issues.updatedAt,
      }).from(issues).where(inArray(issues.id, issueIds)).orderBy(asc(issues.createdAt), asc(issues.id));
      const comments = await tx.select({
        id: issueComments.id,
        issueId: issueComments.issueId,
        authorAgentId: issueComments.authorAgentId,
        authorUserId: issueComments.authorUserId,
        createdByRunId: issueComments.createdByRunId,
        deletedAt: issueComments.deletedAt,
        createdAt: issueComments.createdAt,
      }).from(issueComments).where(inArray(issueComments.issueId, issueIds))
        .orderBy(asc(issueComments.createdAt), asc(issueComments.id));
      const runIssueId = sql<string>`${heartbeatRuns.contextSnapshot} ->> 'issueId'`;
      const runRows = await tx.select({
        id: heartbeatRuns.id,
        agentId: heartbeatRuns.agentId,
        status: heartbeatRuns.status,
        wakeupRequestId: heartbeatRuns.wakeupRequestId,
        retryOfRunId: heartbeatRuns.retryOfRunId,
        sessionIdBefore: heartbeatRuns.sessionIdBefore,
        sessionIdAfter: heartbeatRuns.sessionIdAfter,
        contextSnapshot: heartbeatRuns.contextSnapshot,
        usageJson: heartbeatRuns.usageJson,
        errorCode: heartbeatRuns.errorCode,
        lastOutputAt: heartbeatRuns.lastOutputAt,
        lastOutputSeq: heartbeatRuns.lastOutputSeq,
        lastOutputStream: heartbeatRuns.lastOutputStream,
        lastOutputBytes: heartbeatRuns.lastOutputBytes,
        startedAt: heartbeatRuns.startedAt,
        finishedAt: heartbeatRuns.finishedAt,
        createdAt: heartbeatRuns.createdAt,
        issueId: runIssueId,
      }).from(heartbeatRuns).where(inArray(runIssueId, issueIds)).orderBy(asc(heartbeatRuns.createdAt), asc(heartbeatRuns.id));
      const runs = runRows.map((run) => ({ ...run, usageJson: sanitizedRunUsage(run.usageJson) }));
      const wakeIssueId = sql<string>`${agentWakeupRequests.payload} ->> 'issueId'`;
      const wakes = await tx.select({
            id: agentWakeupRequests.id,
            agentId: agentWakeupRequests.agentId,
            status: agentWakeupRequests.status,
            source: agentWakeupRequests.source,
            reason: agentWakeupRequests.reason,
            idempotencyKey: agentWakeupRequests.idempotencyKey,
            runId: agentWakeupRequests.runId,
            requestedAt: agentWakeupRequests.requestedAt,
            finishedAt: agentWakeupRequests.finishedAt,
            issueId: wakeIssueId,
          }).from(agentWakeupRequests).where(inArray(wakeIssueId, issueIds))
            .orderBy(asc(agentWakeupRequests.requestedAt), asc(agentWakeupRequests.id));
      const holds = await tx.select({
        id: issueTreeHolds.id,
        rootIssueId: issueTreeHolds.rootIssueId,
        mode: issueTreeHolds.mode,
        status: issueTreeHolds.status,
        reason: issueTreeHolds.reason,
        createdByActorType: issueTreeHolds.createdByActorType,
        createdByAgentId: issueTreeHolds.createdByAgentId,
        createdByUserId: issueTreeHolds.createdByUserId,
        createdByRunId: issueTreeHolds.createdByRunId,
        releasedAt: issueTreeHolds.releasedAt,
        releasedByActorType: issueTreeHolds.releasedByActorType,
        releasedByAgentId: issueTreeHolds.releasedByAgentId,
        releasedByUserId: issueTreeHolds.releasedByUserId,
        releasedByRunId: issueTreeHolds.releasedByRunId,
        createdAt: issueTreeHolds.createdAt,
        updatedAt: issueTreeHolds.updatedAt,
      }).from(issueTreeHolds).where(eq(issueTreeHolds.rootIssueId, input.rootIssueId))
        .orderBy(asc(issueTreeHolds.createdAt), asc(issueTreeHolds.id));
      const decisions = await tx.select({
        id: issueExecutionDecisions.id,
        issueId: issueExecutionDecisions.issueId,
        stageId: issueExecutionDecisions.stageId,
        stageType: issueExecutionDecisions.stageType,
        actorAgentId: issueExecutionDecisions.actorAgentId,
        actorUserId: issueExecutionDecisions.actorUserId,
        outcome: issueExecutionDecisions.outcome,
        createdByRunId: issueExecutionDecisions.createdByRunId,
        createdAt: issueExecutionDecisions.createdAt,
      }).from(issueExecutionDecisions).where(inArray(issueExecutionDecisions.issueId, issueIds))
        .orderBy(asc(issueExecutionDecisions.createdAt), asc(issueExecutionDecisions.id));
      const linkedApprovals = await tx.select({
        issueId: issueApprovals.issueId,
        approvalId: approvals.id,
        status: approvals.status,
        type: approvals.type,
        decidedByUserId: approvals.decidedByUserId,
        decidedAt: approvals.decidedAt,
        updatedAt: approvals.updatedAt,
      }).from(issueApprovals).innerJoin(approvals, eq(approvals.id, issueApprovals.approvalId))
        .where(inArray(issueApprovals.issueId, issueIds)).orderBy(asc(approvals.createdAt), asc(approvals.id));
      const attachments = await tx.select({
        id: issueAttachments.id,
        issueId: issueAttachments.issueId,
        assetId: assets.id,
        contentType: assets.contentType,
        byteSize: assets.byteSize,
        sha256: assets.sha256,
        originalFilename: assets.originalFilename,
        createdAt: issueAttachments.createdAt,
      }).from(issueAttachments).innerJoin(assets, eq(assets.id, issueAttachments.assetId))
        .where(inArray(issueAttachments.issueId, issueIds)).orderBy(asc(issueAttachments.createdAt), asc(issueAttachments.id));
      const workspaceIds = issueRows.map((issue) => issue.executionWorkspaceId).filter((id): id is string => Boolean(id));
      const workspaces = workspaceIds.length
        ? await tx.select({
            id: executionWorkspaces.id,
            projectId: executionWorkspaces.projectId,
            sourceIssueId: executionWorkspaces.sourceIssueId,
            mode: executionWorkspaces.mode,
            strategyType: executionWorkspaces.strategyType,
            name: executionWorkspaces.name,
            status: executionWorkspaces.status,
            cwd: executionWorkspaces.cwd,
            repoUrl: executionWorkspaces.repoUrl,
            baseRef: executionWorkspaces.baseRef,
            branchName: executionWorkspaces.branchName,
            providerType: executionWorkspaces.providerType,
            derivedFromExecutionWorkspaceId: executionWorkspaces.derivedFromExecutionWorkspaceId,
            openedAt: executionWorkspaces.openedAt,
            closedAt: executionWorkspaces.closedAt,
            cleanupEligibleAt: executionWorkspaces.cleanupEligibleAt,
            updatedAt: executionWorkspaces.updatedAt,
          }).from(executionWorkspaces).where(inArray(executionWorkspaces.id, workspaceIds))
            .orderBy(asc(executionWorkspaces.createdAt), asc(executionWorkspaces.id))
        : [];
      const workspaceOps = await tx.select({
        id: workspaceOperations.id,
        executionWorkspaceId: workspaceOperations.executionWorkspaceId,
        heartbeatRunId: workspaceOperations.heartbeatRunId,
        issueId: workspaceOperations.issueId,
        phase: workspaceOperations.phase,
        status: workspaceOperations.status,
        exitCode: workspaceOperations.exitCode,
        logBytes: workspaceOperations.logBytes,
        logSha256: workspaceOperations.logSha256,
        logCompressed: workspaceOperations.logCompressed,
        startedAt: workspaceOperations.startedAt,
        finishedAt: workspaceOperations.finishedAt,
        createdAt: workspaceOperations.createdAt,
        updatedAt: workspaceOperations.updatedAt,
      }).from(workspaceOperations).where(or(
        inArray(workspaceOperations.issueId, issueIds),
        ...(workspaceIds.length ? [inArray(workspaceOperations.executionWorkspaceId, workspaceIds)] : []),
      )!).orderBy(asc(workspaceOperations.createdAt), asc(workspaceOperations.id));
      const authorizations = await tx.select({
        id: crelioV6LifecycleAuthorizations.id,
        issueId: crelioV6LifecycleAuthorizations.issueId,
        generation: crelioV6LifecycleAuthorizations.generation,
        attempt: crelioV6LifecycleAuthorizations.attempt,
        activationKind: crelioV6LifecycleAuthorizations.activationKind,
        idempotencyKey: crelioV6LifecycleAuthorizations.idempotencyKey,
        expectedIssueVersion: crelioV6LifecycleAuthorizations.expectedIssueVersion,
        fencingGeneration: crelioV6LifecycleAuthorizations.fencingGeneration,
        runId: crelioV6LifecycleAuthorizations.runId,
        expiresAt: crelioV6LifecycleAuthorizations.expiresAt,
        consumedAt: crelioV6LifecycleAuthorizations.consumedAt,
        consumingRunId: crelioV6LifecycleAuthorizations.consumingRunId,
        createdAt: crelioV6LifecycleAuthorizations.createdAt,
      }).from(crelioV6LifecycleAuthorizations).where(eq(crelioV6LifecycleAuthorizations.rootIssueId, input.rootIssueId))
        .orderBy(asc(crelioV6LifecycleAuthorizations.createdAt), asc(crelioV6LifecycleAuthorizations.id));
      const completions = await tx.select().from(crelioV6CompletionReceipts)
        .where(eq(crelioV6CompletionReceipts.rootIssueId, input.rootIssueId))
        .orderBy(asc(crelioV6CompletionReceipts.createdAt), asc(crelioV6CompletionReceipts.id));
      const approvalSubjects = await tx.select().from(crelioV6ApprovalSubjects)
        .where(inArray(crelioV6ApprovalSubjects.issueId, issueIds)).orderBy(asc(crelioV6ApprovalSubjects.issueId));
      const head = await tx.select().from(crelioV6JournalHeads)
        .where(eq(crelioV6JournalHeads.projectId, input.projectId)).then((rows) => rows[0] ?? null);
      const payload = {
        schema: CRELIO_V6_SCHEMA,
        generation: input.generation,
        projectId: input.projectId,
        rootIssueId: input.rootIssueId,
        projectPolicy: policy,
        journalHead: head,
        bindings,
        issues: issueRows,
        comments,
        runs,
        wakes,
        holds,
        executionDecisions: decisions,
        approvals: linkedApprovals,
        attachments,
        workspaces,
        workspaceOperations: workspaceOps,
        lifecycleAuthorizations: authorizations,
        completionReceipts: completions,
        approvalSubjects,
        exactCounts: {
          bindings: bindings.length,
          issues: issueRows.length,
          comments: comments.length,
          runs: runs.length,
          wakes: wakes.length,
          holds: holds.length,
          executionDecisions: decisions.length,
          approvals: linkedApprovals.length,
          attachments: attachments.length,
          workspaces: workspaces.length,
          workspaceOperations: workspaceOps.length,
          lifecycleAuthorizations: authorizations.length,
          completionReceipts: completions.length,
          approvalSubjects: approvalSubjects.length,
        },
      };
      const snapshotSha256 = crelioV6Sha256(payload);
      const expiresAt = new Date(Date.now() + CRELIO_V6_SNAPSHOT_TTL_MS);
      const session = await tx.insert(crelioV6SnapshotSessions).values({
        projectId: input.projectId,
        rootIssueId: input.rootIssueId,
        generation: input.generation,
        boardApiKeyId: input.actor.keyId!,
        snapshotSha256,
        payload,
        expiresAt,
      }).returning().then((rows) => rows[0]);
      return { token: session.id, snapshotSha256, expiresAt, payload };
    });
  }

  async function readSnapshotPage(input: {
    actor: AuthorizationActor;
    projectId: string;
    generation: string;
    fencingGeneration: number;
    token: string;
    collection: string;
    after: number;
    limit: number;
  }) {
    await assertCrelioV6ControllerGrant(db, {
      actor: input.actor,
      projectId: input.projectId,
      generation: input.generation,
      operation: "snapshot.read",
      fencingGeneration: input.fencingGeneration,
    });
    const session = await db.select().from(crelioV6SnapshotSessions).where(and(
      eq(crelioV6SnapshotSessions.id, input.token),
      eq(crelioV6SnapshotSessions.projectId, input.projectId),
      eq(crelioV6SnapshotSessions.generation, input.generation),
      eq(crelioV6SnapshotSessions.boardApiKeyId, input.actor.keyId!),
    )).then((rows) => rows[0] ?? null);
    if (!session || session.expiresAt <= new Date()) throw conflict("V6 snapshot token is missing or expired");
    const payload = session.payload as Record<string, unknown>;
    const value = payload[input.collection];
    if (!Array.isArray(value)) throw unprocessable("Unknown V6 snapshot collection");
    const after = Math.max(0, Math.floor(input.after));
    const limit = Math.max(1, Math.min(CRELIO_V6_SNAPSHOT_PAGE_LIMIT_MAX, Math.floor(input.limit)));
    const items = value.slice(after, after + limit);
    const nextAfter = after + items.length;
    return {
      token: session.id,
      snapshotSha256: session.snapshotSha256,
      collection: input.collection,
      items,
      nextAfter,
      complete: nextAfter >= value.length,
      total: value.length,
      exactCounts: payload.exactCounts,
      journalHead: payload.journalHead,
      projectPolicy: payload.projectPolicy,
      expiresAt: session.expiresAt,
    };
  }

  return {
    inspectLegacyInventory,
    freezeLegacyInventory,
    reconcileCre32Terminal,
    readBudgetOverview,
    readDiagnostics,
    prepareGeneration,
    activateGeneration,
    prepareControllerKeyRotation,
    probeControllerKeyRotation,
    activateControllerKeyRotation,
    advanceFence,
    createIssue,
    activateIssue,
    installProviderReceipt,
    readProviderEvidence,
    readOperatorSession,
    installApprovalSubject,
    finalizeApprovalSubject,
    readIntegrationEvidence,
    completeIssue,
    decideFinalApproval,
    closeRoot,
    listEvents,
    createSnapshot,
    readSnapshotPage,
    getProjectPolicy: (projectId: string) => loadProjectPolicy(db, projectId),
  };
}

/**
 * Atomically consumes the one-time lifecycle authorization and claims its run.
 * This is called from heartbeat admission immediately before adapter launch.
 */
export async function claimCrelioV6LifecycleRun(
  db: Db,
  input: { runId: string; issueId: string; agentId: string; responsibleUserId: string | null; claimedAt: Date },
) {
  return db.transaction(async (tx) => {
    const run = await tx.select().from(heartbeatRuns).where(eq(heartbeatRuns.id, input.runId))
      .then((rows) => rows[0] ?? null);
    if (!run || run.status !== "queued") return null;
    const context = run.contextSnapshot && typeof run.contextSnapshot === "object"
      ? run.contextSnapshot as Record<string, unknown>
      : {};
    const v6 = context.crelioV6 && typeof context.crelioV6 === "object"
      ? context.crelioV6 as Record<string, unknown>
      : null;
    const authorizationId = typeof v6?.authorizationId === "string" ? v6.authorizationId : null;
    if (!authorizationId) {
      const frozen = await isCrelioV6ExecutionFrozenIssue(tx, input.issueId);
      if (frozen) {
        throw conflict(frozen.legacy
          ? "Legacy issue execution is frozen by the active V6 project schema floor"
          : "V6 issue run is missing its one-time external lifecycle authorization");
      }
      return undefined;
    }
    await tx.execute(sql`select id from crelio_v6_lifecycle_authorizations where id = ${authorizationId} for update`);
    const [authorization, binding, issue] = await Promise.all([
      tx.select().from(crelioV6LifecycleAuthorizations)
        .where(eq(crelioV6LifecycleAuthorizations.id, authorizationId)).then((rows) => rows[0] ?? null),
      loadCrelioV6IssueBinding(tx, input.issueId),
      tx.select().from(issues).where(eq(issues.id, input.issueId)).then((rows) => rows[0] ?? null),
    ]);
    if (!authorization || !binding || !issue) throw conflict("V6 lifecycle authorization is missing");
    const policy = await loadProjectPolicy(tx, binding.projectId);
    if (
      authorization.runId !== run.id ||
      authorization.issueId !== input.issueId ||
      authorization.expectedAssigneeAgentId !== input.agentId ||
      authorization.generation !== binding.generation ||
      authorization.expectedIssueVersion !== binding.issueVersion ||
      authorization.expectedControllerStateVersion !== binding.controllerStateVersion ||
      authorization.expectedStatus !== issue.status ||
      issue.assigneeAgentId !== input.agentId ||
      authorization.consumedAt ||
      authorization.expiresAt <= input.claimedAt ||
      !policy ||
      policy.schemaFloor < CRELIO_V6_SCHEMA ||
      policy.activeGeneration !== authorization.generation ||
      policy.activeFencingGeneration !== authorization.fencingGeneration ||
      context.forceFreshSession !== true ||
      run.sessionIdBefore !== null
    ) throw conflict("V6 lifecycle authorization failed adapter-admission validation");

    const claimed = await tx.update(heartbeatRuns).set({
      status: "running",
      responsibleUserId: input.responsibleUserId,
      startedAt: run.startedAt ?? input.claimedAt,
      updatedAt: input.claimedAt,
    }).where(and(eq(heartbeatRuns.id, run.id), eq(heartbeatRuns.status, "queued")))
      .returning().then((rows) => rows[0] ?? null);
    if (!claimed) return null;
    const consumed = await tx.update(crelioV6LifecycleAuthorizations).set({
      consumedAt: input.claimedAt,
      consumingRunId: run.id,
    }).where(and(
      eq(crelioV6LifecycleAuthorizations.id, authorization.id),
      isNull(crelioV6LifecycleAuthorizations.consumedAt),
    )).returning().then((rows) => rows[0] ?? null);
    if (!consumed) throw conflict("V6 lifecycle authorization was already consumed");
    await tx.update(crelioV6IssueBindings).set({
      lifecycleState: "running",
      updatedAt: input.claimedAt,
    }).where(eq(crelioV6IssueBindings.issueId, input.issueId));
    await appendCrelioV6Journal(tx, {
      projectId: binding.projectId,
      generation: binding.generation,
      entityKind: "run",
      entityId: run.id,
      entityVersion: 1,
      mutationKind: "run.admitted",
      reductionPayload: {
        rootIssueId: binding.rootIssueId,
        issueId: input.issueId,
        phase: binding.phase,
        attempt: binding.currentAttempt,
        authorizationId: authorization.id,
        status: "running",
        forceFreshSession: true,
      },
    });
    return claimed;
  });
}

export async function isCrelioV6ExternallyOwnedIssue(dbOrTx: DbLike, issueId: string) {
  const binding = await loadCrelioV6IssueBinding(dbOrTx, issueId);
  if (!binding) return null;
  const policy = await loadProjectPolicy(dbOrTx, binding.projectId);
  return policy?.schemaFloor && policy.schemaFloor >= CRELIO_V6_SCHEMA
    ? { binding, policy }
    : null;
}

export async function appendCrelioV6RunStatusJournal(
  tx: DbLike,
  run: typeof heartbeatRuns.$inferSelect,
) {
  const context = run.contextSnapshot && typeof run.contextSnapshot === "object"
    ? run.contextSnapshot as Record<string, unknown>
    : null;
  const issueId = typeof context?.issueId === "string" ? context.issueId : null;
  if (!issueId) return null;
  const owned = await isCrelioV6ExternallyOwnedIssue(tx, issueId);
  if (!owned) return null;
  const previous = await tx
    .select({ count: sql<number>`count(*)::integer` })
    .from(crelioV6JournalEvents)
    .where(and(
      eq(crelioV6JournalEvents.projectId, owned.binding.projectId),
      eq(crelioV6JournalEvents.entityKind, "run"),
      eq(crelioV6JournalEvents.entityId, run.id),
    ))
    .then((rows: Array<{ count: number }>) => Number(rows[0]?.count ?? 0));
  return appendCrelioV6Journal(tx, {
    projectId: owned.binding.projectId,
    generation: owned.binding.generation,
    entityKind: "run",
    entityId: run.id,
    entityVersion: previous + 1,
    mutationKind: `run.${run.status}`,
    reductionPayload: {
      rootIssueId: owned.binding.rootIssueId,
      issueId,
      phase: owned.binding.phase,
      attempt: owned.binding.currentAttempt,
      status: run.status,
      wakeupRequestId: run.wakeupRequestId,
      retryOfRunId: run.retryOfRunId,
      errorCode: run.errorCode,
      startedAt: run.startedAt?.toISOString() ?? null,
      finishedAt: run.finishedAt?.toISOString() ?? null,
      sessionIdBeforePresent: Boolean(run.sessionIdBefore),
      sessionIdAfterPresent: Boolean(run.sessionIdAfter),
    },
  });
}

export async function appendCrelioV6WakeStatusJournal(
  tx: DbLike,
  wake: typeof agentWakeupRequests.$inferSelect,
) {
  const payload = wake.payload && typeof wake.payload === "object" && !Array.isArray(wake.payload)
    ? wake.payload as Record<string, unknown>
    : {};
  const nested = payload._paperclipWakeContext && typeof payload._paperclipWakeContext === "object" && !Array.isArray(payload._paperclipWakeContext)
    ? payload._paperclipWakeContext as Record<string, unknown>
    : {};
  const issueId = [payload.issueId, payload.taskId, nested.issueId, nested.taskId]
    .find((value): value is string => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value));
  if (!issueId) return null;
  const owned = await isCrelioV6ExternallyOwnedIssue(tx, issueId);
  if (!owned) return null;
  const previous = await tx.select({ count: sql<number>`count(*)::integer` })
    .from(crelioV6JournalEvents)
    .where(and(
      eq(crelioV6JournalEvents.projectId, owned.binding.projectId),
      eq(crelioV6JournalEvents.entityKind, "wake"),
      eq(crelioV6JournalEvents.entityId, wake.id),
    )).then((rows: Array<{ count: number }>) => Number(rows[0]?.count ?? 0));
  return appendCrelioV6Journal(tx, {
    projectId: owned.binding.projectId,
    generation: owned.binding.generation,
    entityKind: "wake",
    entityId: wake.id,
    entityVersion: previous + 1,
    mutationKind: `wake.${wake.status}`,
    reductionPayload: {
      rootIssueId: owned.binding.rootIssueId,
      issueId,
      phase: owned.binding.phase,
      attempt: owned.binding.currentAttempt,
      status: wake.status,
      runId: wake.runId,
      source: wake.source,
      reason: wake.reason,
      finishedAt: wake.finishedAt?.toISOString() ?? null,
    },
  });
}

export async function appendCrelioV6WorkspaceOperationJournal(
  tx: DbLike,
  operation: typeof workspaceOperations.$inferSelect,
) {
  let issueId = operation.issueId ?? null;
  if (!issueId && operation.executionWorkspaceId) {
    issueId = await tx.select({ sourceIssueId: executionWorkspaces.sourceIssueId })
      .from(executionWorkspaces)
      .where(eq(executionWorkspaces.id, operation.executionWorkspaceId))
      .then((rows: Array<{ sourceIssueId: string | null }>) => rows[0]?.sourceIssueId ?? null);
  }
  if (!issueId) return null;
  const binding = await loadCrelioV6IssueBinding(tx, issueId);
  if (!binding) return null;
  const previous = await tx.select({ count: sql<number>`count(*)::integer` })
    .from(crelioV6JournalEvents)
    .where(and(
      eq(crelioV6JournalEvents.projectId, binding.projectId),
      eq(crelioV6JournalEvents.entityKind, "workspace_operation"),
      eq(crelioV6JournalEvents.entityId, operation.id),
    )).then((rows: Array<{ count: number }>) => Number(rows[0]?.count ?? 0));
  return appendCrelioV6Journal(tx, {
    projectId: binding.projectId,
    generation: binding.generation,
    entityKind: "workspace_operation",
    entityId: operation.id,
    entityVersion: previous + 1,
    mutationKind: `workspace_operation.${operation.status}`,
    reductionPayload: {
      rootIssueId: binding.rootIssueId,
      issueId,
      executionWorkspaceId: operation.executionWorkspaceId,
      heartbeatRunId: operation.heartbeatRunId,
      phase: operation.phase,
      status: operation.status,
      exitCode: operation.exitCode,
      logBytes: operation.logBytes,
      logSha256: operation.logSha256,
      startedAt: operation.startedAt.toISOString(),
      finishedAt: operation.finishedAt?.toISOString() ?? null,
    },
  });
}

/**
 * Applies the narrow issue workspace metadata change required while an admitted
 * V6 run is being realized. Stock issue update remains frozen for every other
 * caller and field.
 */
export async function applyCrelioV6RunWorkspaceIssuePatch(
  db: Db,
  input: {
    issueId: string;
    runId: string;
    patch: Record<string, unknown>;
  },
) {
  const allowedKeys = new Set([
    "executionWorkspaceId",
    "projectWorkspaceId",
    "executionWorkspacePreference",
    "executionWorkspaceSettings",
  ]);
  if (Object.keys(input.patch).some((key) => !allowedKeys.has(key))) {
    throw conflict("V6 run workspace patch contains a non-workspace issue field");
  }
  if (Object.keys(input.patch).length === 0) return false;
  const owned = await isCrelioV6ExternallyOwnedIssue(db, input.issueId);
  if (!owned) return false;

  return db.transaction(async (tx) => {
    await tx.execute(sql`select issue_id from crelio_v6_issue_bindings where issue_id = ${input.issueId} for update`);
    const binding = await loadCrelioV6IssueBinding(tx, input.issueId);
    const [issue, authorization] = await Promise.all([
      tx.select().from(issues).where(eq(issues.id, input.issueId)).then((rows) => rows[0] ?? null),
      tx.select().from(crelioV6LifecycleAuthorizations).where(and(
        eq(crelioV6LifecycleAuthorizations.issueId, input.issueId),
        eq(crelioV6LifecycleAuthorizations.consumingRunId, input.runId),
      )).then((rows) => rows[0] ?? null),
    ]);
    if (
      !binding ||
      !issue ||
      !authorization ||
      binding.generation !== authorization.generation ||
      binding.lifecycleState !== "running" ||
      issue.assigneeAgentId !== authorization.expectedAssigneeAgentId ||
      issue.checkoutRunId !== input.runId ||
      issue.executionRunId !== input.runId
    ) {
      throw conflict("V6 workspace binding requires the exact admitted and checked-out run");
    }
    const now = new Date();
    const updatedIssue = await tx.update(issues).set({
      ...input.patch,
      updatedAt: now,
    }).where(and(
      eq(issues.id, input.issueId),
      eq(issues.checkoutRunId, input.runId),
      eq(issues.executionRunId, input.runId),
    )).returning().then((rows) => rows[0] ?? null);
    if (!updatedIssue) throw conflict("V6 workspace binding lost its run-lock race");
    const nextIssueVersion = binding.issueVersion + 1;
    const updatedBinding = await tx.update(crelioV6IssueBindings).set({
      issueVersion: nextIssueVersion,
      updatedAt: now,
    }).where(and(
      eq(crelioV6IssueBindings.issueId, input.issueId),
      eq(crelioV6IssueBindings.issueVersion, binding.issueVersion),
    )).returning().then((rows) => rows[0] ?? null);
    if (!updatedBinding) throw conflict("V6 workspace binding lost its issue-version race");
    await appendCrelioV6Journal(tx, {
      projectId: binding.projectId,
      generation: binding.generation,
      entityKind: "issue",
      entityId: input.issueId,
      entityVersion: nextIssueVersion,
      mutationKind: "issue.workspace_bound",
      reductionPayload: {
        rootIssueId: binding.rootIssueId,
        phase: binding.phase,
        attempt: binding.currentAttempt,
        runId: input.runId,
        executionWorkspaceId: updatedIssue.executionWorkspaceId,
        projectWorkspaceId: updatedIssue.projectWorkspaceId,
        executionWorkspacePreference: updatedIssue.executionWorkspacePreference,
      },
    });
    return true;
  });
}

export async function appendCrelioV6WorkspaceStatusJournal(
  tx: DbLike,
  workspace: typeof executionWorkspaces.$inferSelect,
) {
  if (!workspace.sourceIssueId) return null;
  const binding = await loadCrelioV6IssueBinding(tx, workspace.sourceIssueId);
  if (!binding) return null;
  const previous = await tx.select({ count: sql<number>`count(*)::integer` })
    .from(crelioV6JournalEvents)
    .where(and(
      eq(crelioV6JournalEvents.projectId, binding.projectId),
      eq(crelioV6JournalEvents.entityKind, "workspace"),
      eq(crelioV6JournalEvents.entityId, workspace.id),
    )).then((rows: Array<{ count: number }>) => Number(rows[0]?.count ?? 0));
  return appendCrelioV6Journal(tx, {
    projectId: binding.projectId,
    generation: binding.generation,
    entityKind: "workspace",
    entityId: workspace.id,
    entityVersion: previous + 1,
    mutationKind: `workspace.${workspace.status}`,
    reductionPayload: {
      rootIssueId: binding.rootIssueId,
      sourceIssueId: workspace.sourceIssueId,
      status: workspace.status,
      branchName: workspace.branchName,
      closedAt: workspace.closedAt?.toISOString() ?? null,
      cleanupEligibleAt: workspace.cleanupEligibleAt?.toISOString() ?? null,
      cleanupSucceeded: workspace.status === "archived" && !workspace.cleanupReason,
    },
  });
}
