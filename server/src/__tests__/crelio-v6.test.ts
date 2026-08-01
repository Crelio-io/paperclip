import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import express from "express";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { eq } from "drizzle-orm";
import {
  agents,
  authUsers,
  boardApiKeys,
  companies,
  createDb,
  crelioV6ApprovalSubjects,
  crelioV6ControllerGrants,
  crelioV6IssueBindings,
  crelioV6JournalEvents,
  crelioV6LegacyFreezes,
  crelioV6LifecycleAuthorizations,
  crelioV6ProjectPolicies,
  heartbeatRuns,
  executionWorkspaces,
  issueComments,
  issueExecutionDecisions,
  issueTreeHolds,
  issues,
  projects,
} from "@paperclipai/db";
import {
  CRELIO_V6_CONTROLLER_OPERATIONS,
  CRELIO_V6_PHASES,
  assertCrelioV6RuntimeContract,
  appendCrelioV6Journal,
  applyCrelioV6RunWorkspaceIssuePatch,
  claimCrelioV6LifecycleRun,
  crelioV6Service,
  crelioV6Sha256,
} from "../services/crelio-v6.js";
import { issueService } from "../services/issues.js";
import { boardAuthService } from "../services/board-auth.js";
import { crelioV6MaintenanceMutationGuard } from "../app.js";
import { errorHandler } from "../middleware/index.js";
import { executionWorkspaceRoutes } from "../routes/execution-workspaces.js";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";

const support = await getEmbeddedPostgresTestSupport();
const describePostgres = support.supported ? describe : describe.skip;

if (!support.supported) {
  console.warn(`Skipping Crelio V6 integration tests: ${support.reason ?? "unsupported environment"}`);
}

const QUALIFIED_RUNTIME_CONTRACT = {
  engine: "cli",
  model: "gpt-5.6-sol",
  modelReasoningEffort: "medium",
  timeoutSec: 2700,
  graceSec: 20,
  outputInactivityTimeoutMs: 1_200_000,
};

describe("Crelio V6 canonical hashing", () => {
  it("is stable across object key order", () => {
    expect(crelioV6Sha256({ b: 2, a: { d: 4, c: 3 } }))
      .toBe(crelioV6Sha256({ a: { c: 3, d: 4 }, b: 2 }));
  });

  it("requires the exact canonical issue/run Codex runtime contract", () => {
    expect(assertCrelioV6RuntimeContract(
      QUALIFIED_RUNTIME_CONTRACT,
      { ...QUALIFIED_RUNTIME_CONTRACT, env: { SAFE: "value" } },
    )).toEqual(QUALIFIED_RUNTIME_CONTRACT);
    expect(() => assertCrelioV6RuntimeContract(
      { ...QUALIFIED_RUNTIME_CONTRACT, reasoningEffort: "medium" },
      QUALIFIED_RUNTIME_CONTRACT,
    )).toThrow("only the canonical");
    expect(() => assertCrelioV6RuntimeContract(
      QUALIFIED_RUNTIME_CONTRACT,
      { ...QUALIFIED_RUNTIME_CONTRACT, model: "different-model" },
    )).toThrow("diverges");
  });

  it("keeps the controller capability set exact and diagnostic reads explicit", () => {
    expect(new Set(CRELIO_V6_CONTROLLER_OPERATIONS).size)
      .toBe(CRELIO_V6_CONTROLLER_OPERATIONS.length);
    expect(CRELIO_V6_CONTROLLER_OPERATIONS).toContain("diagnostics.read");
    expect(CRELIO_V6_CONTROLLER_OPERATIONS).not.toContain("issue.update");
    expect(CRELIO_V6_CONTROLLER_OPERATIONS).not.toContain("agent.create");
    expect(CRELIO_V6_PHASES).toHaveLength(12);
    expect(new Set(CRELIO_V6_PHASES).size).toBe(12);
  });

  it("keeps migration 0184 additive and limited to Crelio V6 objects", () => {
    const migration = readFileSync(
      new URL("../../../packages/db/src/migrations/0184_crelio_v6_lifecycle.sql", import.meta.url),
      "utf8",
    );
    expect(migration).toContain('CREATE TABLE "crelio_v6_project_policies"');
    expect(migration).toContain('CREATE TABLE "crelio_v6_journal_events"');
    expect(migration).toContain('"create_request_sha256" text NOT NULL');
    expect(migration).toContain('"request_sha256" text NOT NULL');
    expect(migration).not.toMatch(/CREATE TABLE "(?:agents|issues|heartbeat_runs|projects)"/);
    expect(migration).not.toMatch(/ALTER TABLE "(?:agents|issues|heartbeat_runs|projects)"/);
    expect(migration).not.toMatch(/DROP\s+(?:TABLE|COLUMN|INDEX)/i);
  });

  it("keeps every documented lifecycle hook wired in source", () => {
    const heartbeat = readFileSync(new URL("../services/heartbeat.ts", import.meta.url), "utf8");
    const issuesSource = readFileSync(new URL("../services/issues.ts", import.meta.url), "utf8");
    const workspace = readFileSync(new URL("../services/workspace-operations.ts", import.meta.url), "utf8");
    const workspaceRoutes = readFileSync(new URL("../routes/execution-workspaces.ts", import.meta.url), "utf8");
    expect(heartbeat).toContain("claimCrelioV6LifecycleRun");
    expect(heartbeat).toContain("crelio_v6_external_retry_owner");
    expect(heartbeat).toContain("crelio_v6_external_lifecycle_owner");
    expect(heartbeat).toContain("suppressed native missing-comment retry for V6 issue");
    expect(heartbeat).toContain("suppressed native process-loss retry for V6 issue");
    expect(heartbeat).toContain("suppressed native liveness continuation for V6 issue");
    expect(heartbeat).toContain("suppressed native successful-run handoff recovery for V6 issue");
    expect(issuesSource).toContain("Stock and internal issue creation are frozen");
    expect(issuesSource).toContain("Schema-v6 comments require the atomic completion");
    expect(workspace).toContain("appendCrelioV6WorkspaceOperationJournal");
    expect(workspaceRoutes).toContain("assertExactCrelioV6WorkspaceClose");
    expect(workspaceRoutes).toContain('operation: "workspace.close"');
    expect(workspaceRoutes).toContain("V6 workspaces may only be archived by the exact active controller grant");
  });

  it("guarded maintenance denies stock mutations and permits only narrow cutover routes", () => {
    const previous = process.env.CRELIO_V6_MAINTENANCE_MODE;
    process.env.CRELIO_V6_MAINTENANCE_MODE = "1";
    try {
      const guard = crelioV6MaintenanceMutationGuard();
      const denied: { status?: number; body?: unknown } = {};
      const deniedResponse = {
        status(code: number) { denied.status = code; return this; },
        json(body: unknown) { denied.body = body; return this; },
      };
      let deniedNext = false;
      guard(
        { method: "POST", path: `/api/issues/${randomUUID()}` } as any,
        deniedResponse as any,
        (() => { deniedNext = true; }) as any,
      );
      expect(deniedNext).toBe(false);
      expect(denied.status).toBe(503);
      expect(denied.body).toMatchObject({ code: "crelio_v6_maintenance_mode" });

      let allowedNext = false;
      guard(
        { method: "POST", path: `/api/projects/${randomUUID()}/v6-generation/prepare` } as any,
        deniedResponse as any,
        (() => { allowedNext = true; }) as any,
      );
      expect(allowedNext).toBe(true);
    } finally {
      if (previous === undefined) delete process.env.CRELIO_V6_MAINTENANCE_MODE;
      else process.env.CRELIO_V6_MAINTENANCE_MODE = previous;
    }
  });
});

describePostgres("Crelio V6 lifecycle extension", () => {
  let db!: ReturnType<typeof createDb>;
  let tempDb: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>> | null = null;

  beforeAll(async () => {
    tempDb = await startEmbeddedPostgresTestDatabase("paperclip-crelio-v6-");
    db = createDb(tempDb.connectionString);
  }, 30_000);

  afterAll(async () => {
    await tempDb?.cleanup();
  });

  async function base(name: string) {
    const companyId = randomUUID();
    const projectId = randomUUID();
    const agentId = randomUUID();
    const userId = `${name}-user`;
    await db.insert(authUsers).values({
      id: userId,
      name,
      email: `${name}@example.invalid`,
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    await db.insert(companies).values({
      id: companyId,
      name,
      issuePrefix: name.replace(/[^A-Za-z]/g, "").slice(0, 6).toUpperCase(),
      requireBoardApprovalForNewAgents: false,
    });
    await db.insert(agents).values({
      id: agentId,
      companyId,
      name: `${name} agent`,
      role: "general",
      status: "idle",
      adapterType: "codex_local",
      adapterConfig: {},
      runtimeConfig: {},
      permissions: {},
    });
    await db.insert(projects).values({ id: projectId, companyId, name });
    return { companyId, projectId, agentId, userId };
  }

  it("rejects an unauthorized queued legacy run after the project schema floor reaches V6", async () => {
    const seeded = await base("LegacyFreeze");
    const issueId = randomUUID();
    const runId = randomUUID();
    await db.insert(issues).values({
      id: issueId,
      companyId: seeded.companyId,
      projectId: seeded.projectId,
      issueNumber: 1,
      identifier: "LEGACY-1",
      title: "Legacy work",
      status: "todo",
      priority: "medium",
      assigneeAgentId: seeded.agentId,
    });
    await db.insert(crelioV6ProjectPolicies).values({
      projectId: seeded.projectId,
      companyId: seeded.companyId,
      schemaFloor: 6,
      activeGeneration: "g-test",
      activeFencingGeneration: 1,
    });
    await db.insert(heartbeatRuns).values({
      id: runId,
      companyId: seeded.companyId,
      agentId: seeded.agentId,
      invocationSource: "manual",
      status: "queued",
      contextSnapshot: { issueId },
    });

    await expect(claimCrelioV6LifecycleRun(db, {
      runId,
      issueId,
      agentId: seeded.agentId,
      responsibleUserId: seeded.userId,
      claimedAt: new Date(),
    })).rejects.toThrow("Legacy issue execution is frozen");
    const stored = await db.select({ status: heartbeatRuns.status }).from(heartbeatRuns)
      .where(eq(heartbeatRuns.id, runId)).then((rows) => rows[0]);
    expect(stored.status).toBe("queued");
  });

  it("admits one exact fresh-session run and rejects reuse of its consumed nonce", async () => {
    const seeded = await base("NonceOnce");
    const issueId = randomUUID();
    const runId = randomUUID();
    const replayRunId = randomUUID();
    const authorizationId = randomUUID();
    await db.insert(issues).values({
      id: issueId,
      companyId: seeded.companyId,
      projectId: seeded.projectId,
      issueNumber: 1,
      identifier: "NONCE-1",
      title: "Authorized phase",
      status: "todo",
      priority: "medium",
      assigneeAgentId: seeded.agentId,
    });
    await db.insert(crelioV6ProjectPolicies).values({
      projectId: seeded.projectId,
      companyId: seeded.companyId,
      schemaFloor: 6,
      activeGeneration: "g-nonce",
      activeFencingGeneration: 9,
    });
    await db.insert(crelioV6IssueBindings).values({
      issueId,
      companyId: seeded.companyId,
      projectId: seeded.projectId,
      rootIssueId: issueId,
      generation: "g-nonce",
      controllerStateVersion: 1,
      createRequestSha256: crelioV6Sha256("nonce-issue-create"),
      issueVersion: 1,
      phase: "strategy_intake",
      currentAttempt: 1,
      lifecycleState: "authorized",
    });
    await db.insert(heartbeatRuns).values([
      {
        id: runId,
        companyId: seeded.companyId,
        agentId: seeded.agentId,
        invocationSource: "automation",
        status: "queued",
        contextSnapshot: {
          issueId,
          forceFreshSession: true,
          crelioV6: { schema: 6, authorizationId },
        },
      },
      {
        id: replayRunId,
        companyId: seeded.companyId,
        agentId: seeded.agentId,
        invocationSource: "automation",
        status: "queued",
        contextSnapshot: {
          issueId,
          forceFreshSession: true,
          crelioV6: { schema: 6, authorizationId },
        },
      },
    ]);
    await db.insert(crelioV6LifecycleAuthorizations).values({
      id: authorizationId,
      companyId: seeded.companyId,
      projectId: seeded.projectId,
      rootIssueId: issueId,
      issueId,
      generation: "g-nonce",
      attempt: 1,
      activationKind: "activate",
      idempotencyKey: "nonce-once:test:1",
      requestSha256: crelioV6Sha256("nonce-once-request"),
      nonceSha256: crelioV6Sha256("nonce-once"),
      expectedIssueVersion: 1,
      expectedControllerStateVersion: 1,
      expectedStatus: "todo",
      expectedAssigneeAgentId: seeded.agentId,
      fencingGeneration: 9,
      runId,
      expiresAt: new Date(Date.now() + 60_000),
    });

    const claimed = await claimCrelioV6LifecycleRun(db, {
      runId,
      issueId,
      agentId: seeded.agentId,
      responsibleUserId: seeded.userId,
      claimedAt: new Date(),
    });
    expect(claimed?.status).toBe("running");
    expect(await claimCrelioV6LifecycleRun(db, {
      runId,
      issueId,
      agentId: seeded.agentId,
      responsibleUserId: seeded.userId,
      claimedAt: new Date(),
    })).toBeNull();
    await expect(claimCrelioV6LifecycleRun(db, {
      runId: replayRunId,
      issueId,
      agentId: seeded.agentId,
      responsibleUserId: seeded.userId,
      claimedAt: new Date(),
    })).rejects.toThrow("adapter-admission validation");
    const replay = await db.select({ status: heartbeatRuns.status }).from(heartbeatRuns)
      .where(eq(heartbeatRuns.id, replayRunId)).then((rows) => rows[0]);
    expect(replay.status).toBe("queued");
  });

  it("rejects a second lifecycle authorization while the chain already has a queued or running V6 run", async () => {
    const seeded = await base("SingleActiveRun");
    const issueId = randomUUID();
    const keyId = randomUUID();
    const instructionContractSha256 = crelioV6Sha256("single-active-run-instructions");
    await db.insert(boardApiKeys).values({
      id: keyId,
      userId: seeded.userId,
      name: "single-active-run-controller",
      keyHash: crelioV6Sha256("single-active-run-key"),
    });
    await db.insert(issues).values({
      id: issueId,
      companyId: seeded.companyId,
      projectId: seeded.projectId,
      issueNumber: 1,
      identifier: "ONE-RUN-1",
      title: "One active lifecycle run",
      status: "backlog",
      priority: "medium",
      assigneeAgentId: seeded.agentId,
      responsibleUserId: seeded.userId,
      assigneeAdapterOverrides: {
        adapterConfig: QUALIFIED_RUNTIME_CONTRACT,
        useProjectWorkspace: true,
      },
    });
    await db.insert(crelioV6ProjectPolicies).values({
      projectId: seeded.projectId,
      companyId: seeded.companyId,
      schemaFloor: 6,
      activeGeneration: "g-one-run",
      controllerUserId: seeded.userId,
      controllerApiKeyId: keyId,
      activeFencingGeneration: 17,
      instructionContractSha256,
    });
    await db.insert(crelioV6ControllerGrants).values({
      companyId: seeded.companyId,
      projectId: seeded.projectId,
      boardUserId: seeded.userId,
      boardApiKeyId: keyId,
      generation: "g-one-run",
      allowedOperations: ["issue.activate", "issue.reopen"],
      allowedAgentIds: [seeded.agentId],
      scopeSha256: crelioV6Sha256("single-active-run-scope"),
    });
    await db.insert(crelioV6IssueBindings).values({
      issueId,
      companyId: seeded.companyId,
      projectId: seeded.projectId,
      rootIssueId: issueId,
      generation: "g-one-run",
      controllerStateVersion: 1,
      createRequestSha256: crelioV6Sha256("single-run-issue-create"),
      issueVersion: 1,
      phase: "draft",
      currentAttempt: 1,
      lifecycleState: "backlog",
    });

    const service = crelioV6Service(db);
    const actor = {
      type: "board",
      source: "board_key",
      userId: seeded.userId,
      keyId,
      companyIds: [seeded.companyId],
      isInstanceAdmin: false,
    } as any;
    const firstRequest = {
      actor,
      issueId,
      generation: "g-one-run",
      fencingGeneration: 17,
      activationKind: "activate" as const,
      attempt: 1,
      idempotencyKey: "one-run:first",
      nonce: "first-single-active-run-nonce-material",
      expectedIssueVersion: 1,
      expectedControllerStateVersion: 1,
      expectedStatus: "backlog",
      assigneeAgentId: seeded.agentId,
      expiresAt: new Date(Date.now() + 60_000),
      context: {
        instructionContractSha256,
        crelioV6RuntimeContract: QUALIFIED_RUNTIME_CONTRACT,
      },
    };
    const first = await service.activateIssue(firstRequest);
    expect(first.run?.status).toBe("queued");
    expect((await service.activateIssue(firstRequest)).replayed).toBe(true);

    const claimed = await claimCrelioV6LifecycleRun(db, {
      runId: first.run!.id,
      issueId,
      agentId: seeded.agentId,
      responsibleUserId: seeded.userId,
      claimedAt: new Date(),
    });
    expect(claimed?.status).toBe("running");
    await issueService(db).checkout(issueId, seeded.agentId, ["todo"], first.run!.id, {
      crelioV6TransactionHook: (tx, checkout) => appendCrelioV6Journal(tx, {
        projectId: checkout.binding.projectId,
        generation: checkout.binding.generation,
        entityKind: "issue",
        entityId: checkout.issue.id,
        entityVersion: checkout.issueVersion,
        mutationKind: "issue.checked_out",
        reductionPayload: {
          rootIssueId: checkout.binding.rootIssueId,
          runId: checkout.runId,
          status: checkout.issue.status,
        },
      }).then(() => undefined),
    });
    expect(await applyCrelioV6RunWorkspaceIssuePatch(db, {
      issueId,
      runId: first.run!.id,
      patch: { executionWorkspacePreference: "reuse_existing" },
    })).toBe(true);
    await expect(issueService(db).update(issueId, { title: "forbidden stock update" }))
      .rejects.toThrow("dedicated lifecycle endpoint");
    const boundAfterWorkspace = await db.select().from(crelioV6IssueBindings)
      .where(eq(crelioV6IssueBindings.issueId, issueId)).then((rows) => rows[0]);
    expect(boundAfterWorkspace.issueVersion).toBe(4);
    const mutations = await db.select({ mutationKind: crelioV6JournalEvents.mutationKind })
      .from(crelioV6JournalEvents)
      .where(eq(crelioV6JournalEvents.projectId, seeded.projectId));
    expect(mutations.map((row) => row.mutationKind)).toContain("issue.checked_out");
    expect(mutations.map((row) => row.mutationKind)).toContain("issue.workspace_bound");
    expect(mutations.map((row) => row.mutationKind)).toContain("wake.queued");
    expect(mutations.map((row) => row.mutationKind)).toContain("run.queued");

    const retryRequest = {
      ...firstRequest,
      activationKind: "retry" as const,
      attempt: 2,
      idempotencyKey: "one-run:retry",
      nonce: "second-single-active-run-nonce-material",
      expectedIssueVersion: 4,
      expectedStatus: "in_progress",
    };
    await expect(service.activateIssue(retryRequest)).rejects.toThrow(
      "already queued or running",
    );

    await db.update(heartbeatRuns).set({ status: "failed", finishedAt: new Date() })
      .where(eq(heartbeatRuns.id, first.run!.id));
    await db.update(issues).set({
      checkoutRunId: null,
      executionRunId: null,
      executionAgentNameKey: null,
      executionLockedAt: null,
    }).where(eq(issues.id, issueId));
    const retry = await service.activateIssue(retryRequest);
    expect(retry.run?.status).toBe("queued");
  });

  it("creates only canonical V6 root/phase shapes with hash-exact idempotent replay", async () => {
    const seeded = await base("CanonicalGraph");
    const keyId = randomUUID();
    await db.insert(boardApiKeys).values({
      id: keyId,
      userId: seeded.userId,
      name: "canonical-graph-controller",
      keyHash: crelioV6Sha256("canonical-graph-key"),
    });
    await db.insert(crelioV6ProjectPolicies).values({
      projectId: seeded.projectId,
      companyId: seeded.companyId,
      schemaFloor: 6,
      activeGeneration: "g-canonical-graph",
      controllerUserId: seeded.userId,
      controllerApiKeyId: keyId,
      activeFencingGeneration: 23,
    });
    await db.insert(crelioV6ControllerGrants).values({
      companyId: seeded.companyId,
      projectId: seeded.projectId,
      boardUserId: seeded.userId,
      boardApiKeyId: keyId,
      generation: "g-canonical-graph",
      allowedOperations: ["issue.create"],
      allowedAgentIds: [seeded.agentId],
      scopeSha256: crelioV6Sha256("canonical-graph-scope"),
    });
    const actor = {
      type: "board",
      source: "board_key",
      userId: seeded.userId,
      keyId,
      companyIds: [seeded.companyId],
      isInstanceAdmin: false,
    } as any;
    const service = crelioV6Service(db);
    const rootIssueId = randomUUID();
    const rootRequest = {
      actor,
      projectId: seeded.projectId,
      generation: "g-canonical-graph",
      fencingGeneration: 23,
      idempotencyKey: "canonical-root",
      issueId: rootIssueId,
      phase: "root",
      attempt: 1,
      controllerStateVersion: 1,
      title: "Passive root",
      description: "Passive canonical V6 article root.",
      responsibleUserId: seeded.userId,
    };
    const root = await service.createIssue(rootRequest);
    expect(root.issue).toMatchObject({ id: rootIssueId, status: "todo", assigneeAgentId: null });
    expect((await service.createIssue(rootRequest)).replayed).toBe(true);
    await expect(service.createIssue({ ...rootRequest, title: "Divergent replay" }))
      .rejects.toThrow("different request");

    const strategyIssueId = randomUUID();
    const strategy = await service.createIssue({
      actor,
      projectId: seeded.projectId,
      generation: "g-canonical-graph",
      fencingGeneration: 23,
      idempotencyKey: "canonical-strategy",
      issueId: strategyIssueId,
      rootIssueId,
      phase: "strategy_intake",
      attempt: 1,
      controllerStateVersion: 2,
      title: "Strategy intake",
      description: "Bounded strategy intake.",
      parentId: rootIssueId,
      assigneeAgentId: seeded.agentId,
      responsibleUserId: seeded.userId,
      assigneeAdapterOverrides: {
        adapterConfig: QUALIFIED_RUNTIME_CONTRACT,
        useProjectWorkspace: true,
      },
    });
    expect(strategy.issue).toMatchObject({ status: "backlog", parentId: rootIssueId });
    expect(strategy.binding.workspaceAnchorIssueId).toBe(strategyIssueId);
    await expect(service.createIssue({
      actor,
      projectId: seeded.projectId,
      generation: "g-canonical-graph",
      fencingGeneration: 23,
      idempotencyKey: "unknown-phase",
      issueId: randomUUID(),
      rootIssueId,
      phase: "invented_phase",
      attempt: 1,
      controllerStateVersion: 3,
      title: "Unknown",
      description: "Must fail.",
      parentId: rootIssueId,
      assigneeAgentId: seeded.agentId,
      responsibleUserId: seeded.userId,
    })).rejects.toThrow("Unknown schema-v6 article phase");
    await expect(service.createIssue({
      actor,
      projectId: seeded.projectId,
      generation: "g-canonical-graph",
      fencingGeneration: 23,
      idempotencyKey: "wrong-anchor",
      issueId: randomUUID(),
      rootIssueId,
      phase: "draft",
      attempt: 1,
      controllerStateVersion: 3,
      workspaceAnchorIssueId: strategyIssueId,
      inheritExecutionWorkspaceFromIssueId: rootIssueId,
      title: "Draft",
      description: "Wrong inherited workspace.",
      parentId: rootIssueId,
      assigneeAgentId: seeded.agentId,
      responsibleUserId: seeded.userId,
    })).rejects.toThrow("exact Strategy Intake workspace anchor");
  });

  it("binds diagnostics to the exact controller key and rejects another key for the same user", async () => {
    const seeded = await base("ExactKey");
    const agentIds = [seeded.agentId];
    for (let index = 0; index < 4; index += 1) {
      const id = randomUUID();
      agentIds.push(id);
      await db.insert(agents).values({
        id,
        companyId: seeded.companyId,
        name: `ExactKey agent ${index}`,
        role: "general",
        status: "idle",
        adapterType: "codex_local",
        adapterConfig: {},
        runtimeConfig: {},
        permissions: {},
      });
    }
    const keyId = randomUUID();
    const alternateKeyId = randomUUID();
    await db.insert(boardApiKeys).values([
      { id: keyId, userId: seeded.userId, name: "controller", keyHash: crelioV6Sha256("exact-key") },
      { id: alternateKeyId, userId: seeded.userId, name: "alternate", keyHash: crelioV6Sha256("alternate-key") },
    ]);
    const service = crelioV6Service(db);
    const prepared = await service.prepareGeneration({
      actor: {
        type: "board",
        source: "session",
        userId: seeded.userId,
        companyIds: [seeded.companyId],
        isInstanceAdmin: true,
      } as any,
      projectId: seeded.projectId,
      generation: "g-exact-key",
      controllerUserId: seeded.userId,
      controllerApiKeyId: keyId,
      allowedAgentIds: agentIds,
      allowedOperations: [...CRELIO_V6_CONTROLLER_OPERATIONS],
      fencingGeneration: 11,
      expectedVersion: 0,
      manifestSha256: crelioV6Sha256("manifest"),
      legacyFreezeInventorySha256: crelioV6Sha256("freeze"),
      instructionContractSha256: crelioV6Sha256("instructions"),
      budgetPolicySha256: crelioV6Sha256("budget"),
      scopeSha256: crelioV6Sha256("scope"),
    });
    await db.insert(crelioV6LegacyFreezes).values({
      projectId: seeded.projectId,
      companyId: seeded.companyId,
      generation: "g-exact-key",
      status: "completed",
      inventorySha256: crelioV6Sha256("freeze"),
      inventory: { schema: 6, issues: [], roots: [] },
      result: { active_runs_after: 0, queued_wakes_after: 0 },
      completedAt: new Date(),
    });
    const activated = await service.activateGeneration({
      actor: {
        type: "board",
        source: "board_key",
        userId: seeded.userId,
        keyId,
        companyIds: [seeded.companyId],
        isInstanceAdmin: false,
      } as any,
      projectId: seeded.projectId,
      generation: "g-exact-key",
      fencingGeneration: 11,
      expectedVersion: prepared.version,
      manifestSha256: crelioV6Sha256("manifest"),
      activationReceiptSha256: crelioV6Sha256("activation"),
    });
    // Diagnostics are project-scoped and must not fail because an unrelated stock
    // run contains malformed legacy context JSON.
    await db.insert(heartbeatRuns).values({
      id: randomUUID(),
      companyId: seeded.companyId,
      agentId: seeded.agentId,
      invocationSource: "manual",
      status: "queued",
      contextSnapshot: { issueId: "not-a-uuid" },
    });
    const diagnostics = await service.readDiagnostics({
      actor: {
        type: "board",
        source: "board_key",
        userId: seeded.userId,
        keyId,
        companyIds: [seeded.companyId],
        isInstanceAdmin: false,
      } as any,
      projectId: seeded.projectId,
      generation: "g-exact-key",
      fencingGeneration: 11,
    });
    expect(diagnostics.controllerKey).toMatchObject({ id: keyId, userId: seeded.userId });
    expect(diagnostics.controllerGrant.allowedAgentIds.sort()).toEqual(agentIds.sort());
    await expect(service.readDiagnostics({
      actor: {
        type: "board",
        source: "board_key",
        userId: seeded.userId,
        keyId: alternateKeyId,
        companyIds: [seeded.companyId],
        isInstanceAdmin: false,
      } as any,
      projectId: seeded.projectId,
      generation: "g-exact-key",
      fencingGeneration: 11,
    })).rejects.toThrow();

    const successorKeyId = randomUUID();
    await db.insert(boardApiKeys).values({
      id: successorKeyId,
      userId: seeded.userId,
      name: "controller-successor",
      keyHash: crelioV6Sha256("controller-successor-key"),
    });
    const rotation = await service.prepareControllerKeyRotation({
      actor: {
        type: "board",
        source: "session",
        userId: seeded.userId,
        companyIds: [seeded.companyId],
        isInstanceAdmin: true,
      } as any,
      projectId: seeded.projectId,
      generation: "g-exact-key",
      fencingGeneration: 11,
      expectedVersion: activated.version,
      controllerUserId: seeded.userId,
      newControllerApiKeyId: successorKeyId,
      allowedAgentIds: agentIds,
      allowedOperations: [...CRELIO_V6_CONTROLLER_OPERATIONS],
      scopeSha256: crelioV6Sha256("scope"),
    });
    const successorActor = {
      type: "board",
      source: "board_key",
      userId: seeded.userId,
      keyId: successorKeyId,
      companyIds: [seeded.companyId],
      isInstanceAdmin: false,
    } as any;
    expect(await service.probeControllerKeyRotation({
      actor: successorActor,
      projectId: seeded.projectId,
      generation: "g-exact-key",
      fencingGeneration: 11,
    })).toMatchObject({
      state: "prepared_successor",
      controllerApiKeyId: successorKeyId,
      rotationGeneration: 2,
    });
    expect((await service.readDiagnostics({
      actor: {
        type: "board",
        source: "board_key",
        userId: seeded.userId,
        keyId,
        companyIds: [seeded.companyId],
        isInstanceAdmin: false,
      } as any,
      projectId: seeded.projectId,
      generation: "g-exact-key",
      fencingGeneration: 11,
    })).controllerKey.id).toBe(keyId);
    const rotated = await service.activateControllerKeyRotation({
      actor: successorActor,
      projectId: seeded.projectId,
      generation: "g-exact-key",
      fencingGeneration: 11,
      expectedVersion: rotation.version,
      predecessorKeyId: keyId,
    });
    expect(rotated).toMatchObject({
      state: "active",
      controllerApiKeyId: successorKeyId,
      rotationGeneration: 2,
    });
    expect(await service.activateControllerKeyRotation({
      actor: successorActor,
      projectId: seeded.projectId,
      generation: "g-exact-key",
      fencingGeneration: 11,
      expectedVersion: rotated.version,
      predecessorKeyId: keyId,
    })).toMatchObject({ state: "active", replayed: true });
    const predecessorKey = await db.select().from(boardApiKeys)
      .where(eq(boardApiKeys.id, keyId)).then((rows) => rows[0]);
    expect(predecessorKey.revokedAt).toBeInstanceOf(Date);
    await expect(service.readDiagnostics({
      actor: {
        type: "board",
        source: "board_key",
        userId: seeded.userId,
        keyId,
        companyIds: [seeded.companyId],
        isInstanceAdmin: false,
      } as any,
      projectId: seeded.projectId,
      generation: "g-exact-key",
      fencingGeneration: 11,
    })).rejects.toThrow();

    const nextPrepared = await service.prepareGeneration({
      actor: {
        type: "board",
        source: "session",
        userId: seeded.userId,
        companyIds: [seeded.companyId],
        isInstanceAdmin: true,
      } as any,
      projectId: seeded.projectId,
      generation: "g-exact-key-next",
      controllerUserId: seeded.userId,
      controllerApiKeyId: successorKeyId,
      allowedAgentIds: agentIds,
      allowedOperations: [...CRELIO_V6_CONTROLLER_OPERATIONS],
      fencingGeneration: 12,
      expectedVersion: rotated.version,
      manifestSha256: crelioV6Sha256("manifest-next"),
      legacyFreezeInventorySha256: crelioV6Sha256("freeze-next"),
      instructionContractSha256: crelioV6Sha256("instructions-next"),
      budgetPolicySha256: crelioV6Sha256("budget-next"),
      scopeSha256: crelioV6Sha256("scope"),
    });
    expect(await service.getProjectPolicy(seeded.projectId)).toMatchObject({
      activeGeneration: "g-exact-key",
      controllerApiKeyId: successorKeyId,
      activeFencingGeneration: 11,
      preparedGeneration: "g-exact-key-next",
      preparedControllerApiKeyId: successorKeyId,
      preparedFencingGeneration: 12,
    });
    await db.insert(crelioV6LegacyFreezes).values({
      projectId: seeded.projectId,
      companyId: seeded.companyId,
      generation: "g-exact-key-next",
      status: "completed",
      inventorySha256: crelioV6Sha256("freeze-next"),
      inventory: { schema: 6, issues: [], roots: [] },
      result: { active_runs_after: 0, queued_wakes_after: 0 },
      completedAt: new Date(),
    });
    const preparedFence = await service.advanceFence({
      actor: successorActor,
      projectId: seeded.projectId,
      generation: "g-exact-key-next",
      previousFencingGeneration: 12,
      nextFencingGeneration: 13,
      expectedVersion: nextPrepared.version,
    });
    expect(preparedFence.policy).toMatchObject({
      activeGeneration: "g-exact-key",
      activeFencingGeneration: 11,
      preparedGeneration: "g-exact-key-next",
      preparedFencingGeneration: 13,
    });
    expect(await service.activateGeneration({
      actor: successorActor,
      projectId: seeded.projectId,
      generation: "g-exact-key-next",
      fencingGeneration: 13,
      expectedVersion: preparedFence.policy.optimisticVersion,
      manifestSha256: crelioV6Sha256("manifest-next"),
      activationReceiptSha256: crelioV6Sha256("activation-next"),
    })).toMatchObject({ state: "active" });
    expect(await service.getProjectPolicy(seeded.projectId)).toMatchObject({
      activeGeneration: "g-exact-key-next",
      controllerApiKeyId: successorKeyId,
      activeFencingGeneration: 13,
      instructionContractSha256: crelioV6Sha256("instructions-next"),
    });
    const revokedSuccessor = await boardAuthService(db).revokeBoardApiKey(successorKeyId);
    expect(revokedSuccessor?.id).toBe(successorKeyId);
    const successorGrant = await db.select().from(crelioV6ControllerGrants)
      .where(eq(crelioV6ControllerGrants.boardApiKeyId, successorKeyId))
      .then((rows) => rows.find((row) => row.rotationGeneration === 2));
    expect(successorGrant?.revokedAt).toBeInstanceOf(Date);
    const revocationEvents = await db.select().from(crelioV6JournalEvents)
      .where(eq(crelioV6JournalEvents.entityId, successorKeyId));
    expect(revocationEvents.some((event) => event.mutationKind === "controller_key.revoked_external"))
      .toBe(true);
    await expect(service.readDiagnostics({
      actor: successorActor,
      projectId: seeded.projectId,
      generation: "g-exact-key-next",
      fencingGeneration: 12,
    })).rejects.toThrow();
  });

  it("permits only an exact controller archive on a V6-bound execution workspace", async () => {
    const seeded = await base("ExactWorkspaceClose");
    const issueId = randomUUID();
    const workspaceId = randomUUID();
    const keyId = randomUUID();
    const alternateKeyId = randomUUID();
    await db.insert(boardApiKeys).values([
      { id: keyId, userId: seeded.userId, name: "workspace-controller", keyHash: crelioV6Sha256("workspace-key") },
      { id: alternateKeyId, userId: seeded.userId, name: "workspace-alternate", keyHash: crelioV6Sha256("workspace-alternate") },
    ]);
    await db.insert(issues).values({
      id: issueId,
      companyId: seeded.companyId,
      projectId: seeded.projectId,
      issueNumber: 1,
      identifier: "WORKSPACE-1",
      title: "Strategy workspace anchor",
      status: "done",
      priority: "medium",
      assigneeAgentId: null,
    });
    await db.insert(executionWorkspaces).values({
      id: workspaceId,
      companyId: seeded.companyId,
      projectId: seeded.projectId,
      sourceIssueId: issueId,
      mode: "isolated_workspace",
      strategyType: "git_worktree",
      name: "V6 workspace",
      status: "archived",
      providerType: "local_fs",
    });
    await db.update(issues).set({ executionWorkspaceId: workspaceId }).where(eq(issues.id, issueId));
    await db.insert(crelioV6ProjectPolicies).values({
      projectId: seeded.projectId,
      companyId: seeded.companyId,
      schemaFloor: 6,
      activeGeneration: "g-workspace-close",
      controllerUserId: seeded.userId,
      controllerApiKeyId: keyId,
      activeFencingGeneration: 41,
    });
    await db.insert(crelioV6ControllerGrants).values({
      companyId: seeded.companyId,
      projectId: seeded.projectId,
      boardUserId: seeded.userId,
      boardApiKeyId: keyId,
      generation: "g-workspace-close",
      allowedOperations: [...CRELIO_V6_CONTROLLER_OPERATIONS],
      allowedAgentIds: [seeded.agentId],
      scopeSha256: crelioV6Sha256("workspace-scope"),
    });
    await db.insert(crelioV6IssueBindings).values({
      issueId,
      companyId: seeded.companyId,
      projectId: seeded.projectId,
      rootIssueId: issueId,
      generation: "g-workspace-close",
      controllerStateVersion: 1,
      createRequestSha256: crelioV6Sha256("workspace-issue"),
      issueVersion: 1,
      phase: "strategy_intake",
      currentAttempt: 1,
      lifecycleState: "completed",
    });

    const app = (key: string, source: "board_key" | "session" = "board_key") => {
      const instance = express();
      instance.use(express.json());
      instance.use((req, _res, next) => {
        req.actor = {
          type: "board",
          source,
          userId: seeded.userId,
          keyId: key,
          companyIds: [seeded.companyId],
          isInstanceAdmin: false,
        } as any;
        next();
      });
      instance.use("/api", executionWorkspaceRoutes(db));
      instance.use(errorHandler);
      return instance;
    };

    await request(app(keyId))
      .patch(`/api/execution-workspaces/${workspaceId}`)
      .set("X-Crelio-Controller-Generation", "41")
      .send({ status: "archived" })
      .expect(200);
    await request(app(alternateKeyId))
      .patch(`/api/execution-workspaces/${workspaceId}`)
      .set("X-Crelio-Controller-Generation", "41")
      .send({ status: "archived" })
      .expect(403);
    await request(app(keyId))
      .patch(`/api/execution-workspaces/${workspaceId}`)
      .set("X-Crelio-Controller-Generation", "41")
      .send({ status: "archived", name: "broader mutation" })
      .expect(403);
    await request(app(keyId, "session"))
      .patch(`/api/execution-workspaces/${workspaceId}`)
      .set("X-Crelio-Controller-Generation", "41")
      .send({ status: "archived" })
      .expect(403);
  });

  it("produces a transactional snapshot without provider results, comment bodies, or arbitrary workspace data", async () => {
    const seeded = await base("SnapshotSafe");
    const rootIssueId = randomUUID();
    const runId = randomUUID();
    const keyId = randomUUID();
    await db.insert(boardApiKeys).values({
      id: keyId,
      userId: seeded.userId,
      name: "controller",
      keyHash: crelioV6Sha256("controller-key"),
    });
    await db.insert(issues).values({
      id: rootIssueId,
      companyId: seeded.companyId,
      projectId: seeded.projectId,
      issueNumber: 1,
      identifier: "SNAP-1",
      title: "Snapshot root",
      status: "todo",
      priority: "medium",
    });
    await db.insert(crelioV6ProjectPolicies).values({
      projectId: seeded.projectId,
      companyId: seeded.companyId,
      schemaFloor: 6,
      activeGeneration: "g-snapshot",
      controllerUserId: seeded.userId,
      controllerApiKeyId: keyId,
      activeFencingGeneration: 7,
    });
    await db.insert(crelioV6ControllerGrants).values({
      companyId: seeded.companyId,
      projectId: seeded.projectId,
      boardUserId: seeded.userId,
      boardApiKeyId: keyId,
      generation: "g-snapshot",
      allowedOperations: ["snapshot.read"],
      allowedAgentIds: [seeded.agentId],
      scopeSha256: crelioV6Sha256("scope"),
    });
    await db.insert(crelioV6IssueBindings).values({
      issueId: rootIssueId,
      companyId: seeded.companyId,
      projectId: seeded.projectId,
      rootIssueId,
      generation: "g-snapshot",
      controllerStateVersion: 1,
      createRequestSha256: crelioV6Sha256("snapshot-issue-create"),
      phase: "root",
      lifecycleState: "passive",
    });
    await db.insert(heartbeatRuns).values({
      id: runId,
      companyId: seeded.companyId,
      agentId: seeded.agentId,
      invocationSource: "automation",
      status: "succeeded",
      contextSnapshot: { issueId: rootIssueId },
      usageJson: { inputTokens: 12, outputTokens: 3, providerCredential: "must-not-leak" },
      resultJson: { providerResponse: "must-not-leak" },
    });
    await db.insert(issueComments).values({
      companyId: seeded.companyId,
      issueId: rootIssueId,
      authorUserId: seeded.userId,
      authorType: "user",
      body: "must-not-leak-comment-body",
    });

    const snapshot = await crelioV6Service(db).createSnapshot({
      actor: {
        type: "board",
        source: "board_key",
        userId: seeded.userId,
        keyId,
        companyIds: [seeded.companyId],
        isInstanceAdmin: false,
      } as any,
      projectId: seeded.projectId,
      rootIssueId,
      generation: "g-snapshot",
      fencingGeneration: 7,
    });
    const serialized = JSON.stringify(snapshot.payload);
    expect(serialized).not.toContain("must-not-leak");
    expect((snapshot.payload.runs as Array<any>)[0].usageJson).toEqual({ inputTokens: 12, outputTokens: 3 });
    expect((snapshot.payload.comments as Array<any>)[0]).not.toHaveProperty("body");
  });

  it("atomically binds the configured human approval to the immutable subject and closes the final stage", async () => {
    const seeded = await base("FinalApprove");
    const rootIssueId = randomUUID();
    const finalIssueId = randomUUID();
    const stageId = randomUUID();
    const participantId = randomUUID();
    const policy = {
      mode: "normal",
      commentRequired: true,
      stages: [{
        id: stageId,
        type: "approval",
        approvalsNeeded: 1,
        participants: [{ id: participantId, type: "user", userId: seeded.userId }],
      }],
      monitor: null,
    };
    const description = "Frozen final handoff";
    await db.insert(issues).values([
      {
        id: rootIssueId,
        companyId: seeded.companyId,
        projectId: seeded.projectId,
        issueNumber: 1,
        identifier: "FINAL-1",
        title: "Root",
        status: "todo",
        priority: "medium",
      },
      {
        id: finalIssueId,
        companyId: seeded.companyId,
        projectId: seeded.projectId,
        parentId: rootIssueId,
        issueNumber: 2,
        identifier: "FINAL-2",
        title: "Final Handoff",
        description,
        status: "in_review",
        priority: "medium",
        assigneeUserId: seeded.userId,
        executionPolicy: policy,
        executionState: {
          status: "pending",
          currentStageId: stageId,
          currentStageIndex: 0,
          currentStageType: "approval",
          currentParticipant: { type: "user", userId: seeded.userId },
          returnAssignee: { type: "agent", agentId: seeded.agentId },
          reviewRequest: null,
          completedStageIds: [],
          lastDecisionId: null,
          lastDecisionOutcome: null,
          monitor: null,
        },
      },
    ]);
    await db.insert(crelioV6ProjectPolicies).values({
      projectId: seeded.projectId,
      companyId: seeded.companyId,
      schemaFloor: 6,
      activeGeneration: "g-final",
      activeFencingGeneration: 2,
    });
    await db.insert(crelioV6IssueBindings).values([
      {
        issueId: rootIssueId,
        companyId: seeded.companyId,
        projectId: seeded.projectId,
        rootIssueId,
        generation: "g-final",
        controllerStateVersion: 1,
        createRequestSha256: crelioV6Sha256("final-root-issue-create"),
        phase: "root",
        lifecycleState: "passive",
      },
      {
        issueId: finalIssueId,
        companyId: seeded.companyId,
        projectId: seeded.projectId,
        rootIssueId,
        generation: "g-final",
        controllerStateVersion: 12,
        createRequestSha256: crelioV6Sha256("final-handoff-issue-create"),
        phase: "final_handoff",
        lifecycleState: "in_review",
      },
    ]);
    const subjectInput = {
      issueId: finalIssueId,
      generation: "g-final",
      approverUserId: seeded.userId,
      frozenHeadOid: "a".repeat(40),
      checkpointSha256: crelioV6Sha256("checkpoint"),
      packageSha256: crelioV6Sha256("package"),
      attachmentReceiptSha256: crelioV6Sha256("attachments"),
      policySha256: crelioV6Sha256(policy),
      descriptionSha256: crelioV6Sha256(description),
    };
    await db.insert(crelioV6ApprovalSubjects).values({
      ...subjectInput,
      projectId: seeded.projectId,
      handoffFinalizedSha256: crelioV6Sha256("finalized"),
      subjectSha256: crelioV6Sha256(subjectInput),
    });

    const result = await crelioV6Service(db).decideFinalApproval({
      actor: {
        type: "board",
        source: "session",
        userId: seeded.userId,
        companyIds: [seeded.companyId],
        isInstanceAdmin: false,
      } as any,
      issueId: finalIssueId,
      decision: "approved",
      idempotencyKey: "final-approval:test:1",
      comment: "Approved for integration.",
    });
    expect(result.replayed).toBe(false);
    const [storedIssue, storedSubject, comments, decisions] = await Promise.all([
      db.select().from(issues).where(eq(issues.id, finalIssueId)).then((rows) => rows[0]),
      db.select().from(crelioV6ApprovalSubjects).where(eq(crelioV6ApprovalSubjects.issueId, finalIssueId))
        .then((rows) => rows[0]),
      db.select().from(issueComments).where(eq(issueComments.issueId, finalIssueId)),
      db.select().from(issueExecutionDecisions).where(eq(issueExecutionDecisions.issueId, finalIssueId)),
    ]);
    expect(storedIssue.status).toBe("done");
    expect(storedIssue.assigneeUserId).toBeNull();
    expect(storedSubject.decision).toBe("approved");
    expect(comments.at(-1)?.body).toContain(`Subject-SHA256: ${storedSubject.subjectSha256}`);
    expect(decisions).toHaveLength(1);

    const replay = await crelioV6Service(db).decideFinalApproval({
      actor: {
        type: "board",
        source: "session",
        userId: seeded.userId,
      } as any,
      issueId: finalIssueId,
      decision: "approved",
      idempotencyKey: "final-approval:test:1",
      comment: "Approved for integration.",
    });
    expect(replay.replayed).toBe(true);
  });

  it("reconciles only an inert terminal CRE-32 tree and releases its stale hold idempotently", async () => {
    const seeded = await base("Cre32Archive");
    const rootIssueId = randomUUID();
    const childIssueId = randomUUID();
    const holdId = randomUUID();
    await db.insert(issues).values([
      {
        id: rootIssueId,
        companyId: seeded.companyId,
        projectId: seeded.projectId,
        issueNumber: 32,
        identifier: "CRE-32",
        title: "Integrated article",
        status: "done",
        priority: "medium",
      },
      {
        id: childIssueId,
        companyId: seeded.companyId,
        projectId: seeded.projectId,
        parentId: rootIssueId,
        issueNumber: 33,
        identifier: "CRE-33",
        title: "Terminal research",
        status: "done",
        priority: "medium",
      },
    ]);
    await db.insert(issueTreeHolds).values({
      id: holdId,
      companyId: seeded.companyId,
      rootIssueId,
      mode: "pause",
      status: "active",
      reason: "stale bounded-workflow hold",
      createdByActorType: "system",
    });
    const request = {
      actor: {
        type: "board",
        source: "session",
        userId: seeded.userId,
        companyIds: [seeded.companyId],
        isInstanceAdmin: true,
      } as any,
      projectId: seeded.projectId,
      generation: "g-cre32",
      issueIdentifier: "CRE-32" as const,
      integratedCommit: "a".repeat(40),
      mainHead: "b".repeat(40),
      archivalSubjectSha256: crelioV6Sha256("cre32-archive-subject"),
    };
    const result = await crelioV6Service(db).reconcileCre32Terminal(request);
    expect(result.replayed).toBe(false);
    expect(result.releasedHoldId).toBe(holdId);
    expect(result.treeIssueCount).toBe(2);
    const stored = await db.select().from(issueTreeHolds)
      .where(eq(issueTreeHolds.id, holdId)).then((rows) => rows[0]);
    expect(stored.status).toBe("released");
    expect(stored.releaseMetadata).toMatchObject({
      operation: "crelio_v6_cre32_terminal_reconciliation",
      archivalSubjectSha256: request.archivalSubjectSha256,
    });

    const replay = await crelioV6Service(db).reconcileCre32Terminal(request);
    expect(replay.replayed).toBe(true);
    expect(replay.releasedHoldId).toBe(holdId);
    await expect(
      crelioV6Service(db).reconcileCre32Terminal({
        ...request,
        mainHead: "c".repeat(40),
      }),
    ).rejects.toThrow("no stale controller hold");
  });
});
