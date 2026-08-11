import { Router, type NextFunction, type Request, type Response } from "express";
import { z } from "zod";
import type { Db } from "@paperclipai/db";
import { executionWorkspaces, issueAttachments, projects } from "@paperclipai/db";
import { eq } from "drizzle-orm";
import { forbidden, unprocessable } from "../errors.js";
import { heartbeatService } from "../services/heartbeat.js";
import type { AuthorizationActor } from "../services/authorization.js";
import {
  CRELIO_V6_CONTROLLER_OPERATIONS,
  assertCrelioV6ControllerGrant,
  crelioV6Service,
  isCrelioV6ExecutionFrozenIssue,
  type CrelioV6ControllerOperation,
} from "../services/crelio-v6.js";

const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);
const generationSchema = z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
const positiveSafeInteger = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const uuidSchema = z.string().uuid();

export const crelioV6PrepareSchema = z.object({
  generation: generationSchema,
  controllerUserId: z.string().min(1),
  controllerApiKeyId: uuidSchema,
  allowedAgentIds: z.array(uuidSchema).length(5),
  allowedOperations: z.array(z.enum(CRELIO_V6_CONTROLLER_OPERATIONS)).min(1),
  fencingGeneration: positiveSafeInteger,
  expectedVersion: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  manifestSha256: sha256Schema,
  legacyFreezeInventorySha256: sha256Schema,
  instructionContractSha256: sha256Schema,
  budgetPolicySha256: sha256Schema,
  scopeSha256: sha256Schema,
}).strict();

export const crelioV6ActivateGenerationSchema = z.object({
  generation: generationSchema,
  fencingGeneration: positiveSafeInteger,
  expectedVersion: positiveSafeInteger,
  manifestSha256: sha256Schema,
  activationReceiptSha256: sha256Schema,
}).strict();

export const crelioV6FenceSchema = z.object({
  generation: generationSchema,
  previousFencingGeneration: positiveSafeInteger,
  nextFencingGeneration: positiveSafeInteger,
  expectedVersion: positiveSafeInteger,
}).strict();

export const crelioV6PrepareControllerKeyRotationSchema = z.object({
  generation: generationSchema,
  fencingGeneration: positiveSafeInteger,
  expectedVersion: positiveSafeInteger,
  controllerUserId: z.string().min(1),
  newControllerApiKeyId: uuidSchema,
  allowedAgentIds: z.array(uuidSchema).length(5),
  allowedOperations: z.array(z.enum(CRELIO_V6_CONTROLLER_OPERATIONS)).min(1),
  scopeSha256: sha256Schema,
}).strict();

export const crelioV6ControllerKeyProbeSchema = z.object({
  generation: generationSchema,
  fencingGeneration: positiveSafeInteger,
}).strict();

export const crelioV6ActivateControllerKeyRotationSchema = z.object({
  generation: generationSchema,
  fencingGeneration: positiveSafeInteger,
  expectedVersion: positiveSafeInteger,
  predecessorKeyId: uuidSchema,
}).strict();

export const crelioV6FreezeLegacySchema = z.object({
  generation: generationSchema,
  expectedInventorySha256: sha256Schema,
}).strict();

export const crelioV6ReconcileCre32Schema = z.object({
  generation: generationSchema,
  issueIdentifier: z.literal("CRE-32"),
  integratedCommit: z.string().regex(/^[a-f0-9]{40}([a-f0-9]{24})?$/),
  mainHead: z.string().regex(/^[a-f0-9]{40}([a-f0-9]{24})?$/),
  archivalSubjectSha256: sha256Schema,
}).strict();

export const crelioV6CreateIssueSchema = z.object({
  generation: generationSchema,
  fencingGeneration: positiveSafeInteger,
  idempotencyKey: z.string().min(1).max(200),
  issueId: uuidSchema,
  rootIssueId: uuidSchema.nullable().optional(),
  phase: z.string().min(1).max(80),
  attempt: positiveSafeInteger,
  controllerStateVersion: positiveSafeInteger,
  workspaceAnchorIssueId: uuidSchema.nullable().optional(),
  inheritExecutionWorkspaceFromIssueId: uuidSchema.nullable().optional(),
  title: z.string().min(1).max(500),
  description: z.string().min(1).max(2_500),
  parentId: uuidSchema.nullable().optional(),
  assigneeAgentId: uuidSchema.nullable().optional(),
  responsibleUserId: z.string().min(1),
  assigneeAdapterOverrides: z.record(z.string(), z.unknown()).nullable().optional(),
  executionPolicy: z.record(z.string(), z.unknown()).nullable().optional(),
}).strict();

export const crelioV6ExternalLifecycleSchema = z.object({
  schema: z.literal(6),
  owner: z.literal("crelio_controller"),
  generation: generationSchema,
  fencingGeneration: positiveSafeInteger,
  activationKind: z.enum(["activate", "reopen", "retry", "human_input_release"]),
  attempt: positiveSafeInteger,
  idempotencyKey: z.string().min(1).max(200),
  nonce: z.string().min(32).max(512),
  expectedIssueVersion: positiveSafeInteger,
  expectedControllerStateVersion: positiveSafeInteger,
  expectedStatus: z.enum(["backlog", "todo", "in_progress", "blocked", "done", "cancelled"]),
  assigneeAgentId: uuidSchema,
  expiresAt: z.string().datetime({ offset: true }).transform((value) => new Date(value)),
  forceFreshSession: z.literal(true),
  context: z.record(z.string(), z.unknown()).default({}),
}).strict();

export const crelioV6CompletionSchema = z.object({
  generation: generationSchema,
  attempt: positiveSafeInteger,
  idempotencyKey: z.string().min(1).max(200),
  comment: z.string().min(1).max(2_000),
  disposition: z.enum(["done", "blocked", "in_review"]),
  commitOid: z.string().regex(/^[a-f0-9]{40}([a-f0-9]{24})?$/),
  handoffSha256: sha256Schema,
}).strict();

export const crelioV6ProviderReceiptSchema = z.object({
  generation: generationSchema,
  fencingGeneration: positiveSafeInteger,
  expectedIssueVersion: positiveSafeInteger,
  expectedControllerStateVersion: positiveSafeInteger,
  receiptSha256: sha256Schema,
  operation: z.enum(["dataforseo", "image"]),
  outputPrefix: z.string().min(1).max(500),
  expiresAt: z.string().datetime({ offset: true }).transform((value) => new Date(value)),
}).strict();

export const crelioV6ApprovalSubjectSchema = z.object({
  generation: generationSchema,
  fencingGeneration: positiveSafeInteger,
  expectedIssueVersion: positiveSafeInteger,
  expectedControllerStateVersion: positiveSafeInteger,
  approverUserId: z.string().min(1).max(200),
  stageId: uuidSchema,
  participantId: uuidSchema,
  frozenHeadOid: z.string().regex(/^[a-f0-9]{40}([a-f0-9]{24})?$/),
  checkpointSha256: sha256Schema,
  packageSha256: sha256Schema,
  attachmentReceiptSha256: sha256Schema,
  descriptionSha256: sha256Schema,
  expectedPolicySha256: sha256Schema,
}).strict();

export const crelioV6FinalizeApprovalSubjectSchema = z.object({
  generation: generationSchema,
  fencingGeneration: positiveSafeInteger,
  subjectSha256: sha256Schema,
  handoffFinalizedSha256: sha256Schema,
}).strict();

export const crelioV6FinalDecisionSchema = z.object({
  decision: z.enum(["approved", "rejected"]),
  idempotencyKey: z.string().min(1).max(200),
  comment: z.string().min(1).max(1_200),
}).strict();

export const crelioV6CloseRootSchema = z.object({
  finalIssueId: uuidSchema,
  generation: generationSchema,
  fencingGeneration: positiveSafeInteger,
  expectedIssueVersion: positiveSafeInteger,
  integrationReceiptSha256: sha256Schema,
}).strict();

function actor(req: Request): AuthorizationActor {
  return req.actor as AuthorizationActor;
}

function parseBody<S extends z.ZodTypeAny>(schema: S, req: Request): z.output<S> {
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    throw unprocessable("Invalid V6 request", { issues: parsed.error.issues });
  }
  return parsed.data;
}

function parseFencingHeader(req: Request) {
  const raw = req.header("x-crelio-controller-generation")?.trim();
  const value = raw ? Number(raw) : NaN;
  if (!Number.isSafeInteger(value) || value < 1) {
    throw unprocessable("X-Crelio-Controller-Generation must be a positive safe integer");
  }
  return value;
}

function parseNonNegativeQueryInteger(value: unknown, fallback = 0) {
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw unprocessable("Invalid non-negative query integer");
  return parsed;
}

async function assertBoardProjectRead(
  db: Db,
  req: Request,
  projectId: string,
  policy: {
    preparedControllerUserId?: string | null;
    preparedControllerApiKeyId?: string | null;
    controllerUserId?: string | null;
    controllerApiKeyId?: string | null;
  } | null,
) {
  const current = actor(req);
  if (current.type !== "board" || !current.userId) throw forbidden("Board authentication is required");
  const project = await db.select({ companyId: projects.companyId }).from(projects)
    .where(eq(projects.id, projectId)).then((rows) => rows[0] ?? null);
  if (!project) return;
  const exactPreparedController = current.source === "board_key"
    && current.userId === policy?.preparedControllerUserId
    && current.keyId === policy?.preparedControllerApiKeyId;
  const exactActiveController = current.source === "board_key"
    && current.userId === policy?.controllerUserId
    && current.keyId === policy?.controllerApiKeyId;
  if (
    !current.isInstanceAdmin
    && !current.companyIds?.includes(project.companyId)
    && !exactPreparedController
    && !exactActiveController
  ) {
    throw forbidden("Project is outside the authenticated board user's companies");
  }
}

export function crelioV6Routes(db: Db) {
  const router = Router();
  const svc = crelioV6Service(db);
  const heartbeat = heartbeatService(db);

  router.get("/projects/:projectId/v6-generation", async (req, res) => {
    const policy = await svc.getProjectPolicy(req.params.projectId);
    await assertBoardProjectRead(db, req, req.params.projectId, policy);
    if (!policy) return res.status(404).json({ error: "V6 project policy not found" });
    res.json(policy);
  });

  router.get("/projects/:projectId/v6-budget-overview", async (req, res) => {
    const generation = generationSchema.parse(req.query.generation);
    const result = await svc.readBudgetOverview({
      actor: actor(req),
      projectId: req.params.projectId,
      generation,
      fencingGeneration: parseFencingHeader(req),
    });
    res.json(result);
  });

  router.get("/projects/:projectId/v6-diagnostics", async (req, res) => {
    const generation = generationSchema.parse(req.query.generation);
    const result = await svc.readDiagnostics({
      actor: actor(req),
      projectId: req.params.projectId,
      generation,
      fencingGeneration: parseFencingHeader(req),
    });
    res.json(result);
  });

  router.get("/projects/:projectId/v6-legacy-inventory", async (req, res) => {
    const result = await svc.inspectLegacyInventory({
      actor: actor(req),
      projectId: req.params.projectId,
    });
    res.json(result);
  });

  router.post("/projects/:projectId/v6-legacy-freeze", async (req, res) => {
    const body = parseBody(crelioV6FreezeLegacySchema, req);
    const result = await svc.freezeLegacyInventory({
      actor: actor(req),
      projectId: req.params.projectId,
      ...body,
    });
    res.status(result.replayed ? 200 : 201).json(result);
  });

  router.post("/projects/:projectId/v6-reconcile-cre32", async (req, res) => {
    const body = parseBody(crelioV6ReconcileCre32Schema, req);
    const result = await svc.reconcileCre32Terminal({
      actor: actor(req),
      projectId: req.params.projectId,
      ...body,
    });
    res.status(result.replayed ? 200 : 201).json(result);
  });

  router.post("/projects/:projectId/v6-generation/prepare", async (req, res) => {
    const body = parseBody(crelioV6PrepareSchema, req);
    const result = await svc.prepareGeneration({ actor: actor(req), projectId: req.params.projectId, ...body });
    res.status(201).json(result);
  });

  router.post("/projects/:projectId/v6-generation/activate", async (req, res) => {
    const body = parseBody(crelioV6ActivateGenerationSchema, req);
    const result = await svc.activateGeneration({ actor: actor(req), projectId: req.params.projectId, ...body });
    res.json(result);
  });

  router.post("/projects/:projectId/v6-generation/fence", async (req, res) => {
    const body = parseBody(crelioV6FenceSchema, req);
    const result = await svc.advanceFence({ actor: actor(req), projectId: req.params.projectId, ...body });
    res.json(result);
  });

  router.post("/projects/:projectId/v6-controller-key/prepare-rotation", async (req, res) => {
    const body = parseBody(crelioV6PrepareControllerKeyRotationSchema, req);
    const result = await svc.prepareControllerKeyRotation({ actor: actor(req), projectId: req.params.projectId, ...body });
    res.status(result.replayed ? 200 : 201).json(result);
  });

  router.post("/projects/:projectId/v6-controller-key/probe", async (req, res) => {
    const body = parseBody(crelioV6ControllerKeyProbeSchema, req);
    const result = await svc.probeControllerKeyRotation({ actor: actor(req), projectId: req.params.projectId, ...body });
    res.json(result);
  });

  router.post("/projects/:projectId/v6-controller-key/activate-rotation", async (req, res) => {
    const body = parseBody(crelioV6ActivateControllerKeyRotationSchema, req);
    const result = await svc.activateControllerKeyRotation({ actor: actor(req), projectId: req.params.projectId, ...body });
    res.json(result);
  });

  router.post("/projects/:projectId/v6/issues", async (req, res) => {
    const body = parseBody(crelioV6CreateIssueSchema, req);
    const fencingGeneration = parseFencingHeader(req);
    if (body.fencingGeneration !== fencingGeneration) {
      throw unprocessable("Fencing header and body do not match");
    }
    const result = await svc.createIssue({ actor: actor(req), projectId: req.params.projectId, ...body });
    res.status(result.replayed ? 200 : 201).json(result);
  });

  const activate = async (req: Request, res: Response, routeKind: "activate" | "reopen") => {
    const body = parseBody(crelioV6ExternalLifecycleSchema, req);
    if (routeKind === "activate" && body.activationKind !== "activate") {
      throw unprocessable("The activate route requires activationKind=activate");
    }
    if (routeKind === "reopen" && body.activationKind === "activate") {
      throw unprocessable("The reopen route requires a reopen, retry, or human-input activation kind");
    }
    const fencingGeneration = parseFencingHeader(req);
    if (body.fencingGeneration !== fencingGeneration) throw unprocessable("Fencing header and body do not match");
    const result = await svc.activateIssue({ actor: actor(req), issueId: String(req.params.issueId), ...body });
    await heartbeat.resumeQueuedRuns();
    res.status(result.replayed ? 200 : 201).json(result);
  };
  router.post("/issues/:issueId/v6-activate", (req, res) => activate(req, res, "activate"));
  router.post("/issues/:issueId/v6-reopen", (req, res) => activate(req, res, "reopen"));

  router.post("/issues/:issueId/v6-complete", async (req, res) => {
    const body = parseBody(crelioV6CompletionSchema, req);
    const result = await svc.completeIssue({ actor: actor(req), issueId: req.params.issueId, ...body });
    res.status(result.replayed ? 200 : 201).json(result);
  });

  router.post("/issues/:issueId/v6-provider-receipt", async (req, res) => {
    const body = parseBody(crelioV6ProviderReceiptSchema, req);
    const fencingGeneration = parseFencingHeader(req);
    if (body.fencingGeneration !== fencingGeneration) throw unprocessable("Fencing header and body do not match");
    const result = await svc.installProviderReceipt({ actor: actor(req), issueId: req.params.issueId, ...body });
    res.status(result.replayed ? 200 : 201).json(result);
  });

  router.get("/issues/:issueId/v6-provider-evidence", async (req, res) => {
    const result = await svc.readProviderEvidence({ actor: actor(req), issueId: req.params.issueId });
    res.json(result);
  });

  router.get("/projects/:projectId/v6-operator-session", async (req, res) => {
    const result = await svc.readOperatorSession({
      actor: actor(req),
      projectId: req.params.projectId,
    });
    res.json(result);
  });

  router.post("/issues/:issueId/v6-approval-subject", async (req, res) => {
    const body = parseBody(crelioV6ApprovalSubjectSchema, req);
    const fencingGeneration = parseFencingHeader(req);
    if (body.fencingGeneration !== fencingGeneration) throw unprocessable("Fencing header and body do not match");
    const result = await svc.installApprovalSubject({ actor: actor(req), issueId: req.params.issueId, ...body });
    res.status(result.replayed ? 200 : 201).json(result);
  });

  router.post("/issues/:issueId/v6-approval-subject/finalize", async (req, res) => {
    const body = parseBody(crelioV6FinalizeApprovalSubjectSchema, req);
    const fencingGeneration = parseFencingHeader(req);
    if (body.fencingGeneration !== fencingGeneration) throw unprocessable("Fencing header and body do not match");
    const result = await svc.finalizeApprovalSubject({ actor: actor(req), issueId: req.params.issueId, ...body });
    res.status(result.replayed ? 200 : 201).json(result);
  });

  router.post("/issues/:issueId/v6-decision", async (req, res) => {
    const body = parseBody(crelioV6FinalDecisionSchema, req);
    const result = await svc.decideFinalApproval({ actor: actor(req), issueId: req.params.issueId, ...body });
    res.status(result.replayed ? 200 : 201).json(result);
  });

  router.get("/issues/:issueId/v6-integration-evidence", async (req, res) => {
    const result = await svc.readIntegrationEvidence({
      actor: actor(req),
      issueId: req.params.issueId,
    });
    res.json(result);
  });

  router.post("/issues/:issueId/v6-close-root", async (req, res) => {
    const body = parseBody(crelioV6CloseRootSchema, req);
    const fencingGeneration = parseFencingHeader(req);
    if (body.fencingGeneration !== fencingGeneration) throw unprocessable("Fencing header and body do not match");
    const result = await svc.closeRoot({ actor: actor(req), issueId: req.params.issueId, ...body });
    res.status(result.replayed ? 200 : 201).json(result);
  });

  router.get("/projects/:projectId/v6-events", async (req, res) => {
    const generation = generationSchema.parse(req.query.generation);
    const result = await svc.listEvents({
      actor: actor(req),
      projectId: req.params.projectId,
      generation,
      fencingGeneration: parseFencingHeader(req),
      afterSequence: parseNonNegativeQueryInteger(req.query.afterSeq),
      limit: parseNonNegativeQueryInteger(req.query.limit, 200),
    });
    res.json(result);
  });

  router.get("/projects/:projectId/v6-snapshot", async (req, res) => {
    const generation = generationSchema.parse(req.query.generation);
    const fencingGeneration = parseFencingHeader(req);
    const token = typeof req.query.snapshotToken === "string" ? req.query.snapshotToken : null;
    if (!token) {
      const rootIssueId = uuidSchema.parse(req.query.rootIssueId);
      const created = await svc.createSnapshot({
        actor: actor(req),
        projectId: req.params.projectId,
        generation,
        fencingGeneration,
        rootIssueId,
      });
      return res.json({
        snapshotToken: created.token,
        snapshotSha256: created.snapshotSha256,
        expiresAt: created.expiresAt,
        collections: Object.keys(created.payload).filter((key) => Array.isArray((created.payload as Record<string, unknown>)[key])),
        exactCounts: (created.payload as Record<string, unknown>).exactCounts,
        journalHead: (created.payload as Record<string, unknown>).journalHead,
        projectPolicy: (created.payload as Record<string, unknown>).projectPolicy,
      });
    }
    const collection = z.string().min(1).max(80).parse(req.query.collection);
    const page = await svc.readSnapshotPage({
      actor: actor(req),
      projectId: req.params.projectId,
      generation,
      fencingGeneration,
      token,
      collection,
      after: parseNonNegativeQueryInteger(req.query.after),
      limit: parseNonNegativeQueryInteger(req.query.limit, 200),
    });
    res.json(page);
  });

  return router;
}

/**
 * Blocks stock mutation surfaces for active V6 work. Read paths remain available;
 * all runnable lifecycle changes must use the dedicated routes above.
 */
export function crelioV6StockMutationGuard(db: Db) {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
      if (/\/v6(?:-|\/|$)/.test(req.path)) return next();

      const issuePathMatch = req.path.match(/^\/issues\/([0-9a-f-]{36})(?:\/|$)/i);
      const companyAttachmentMatch = req.path.match(
        /^\/companies\/([0-9a-f-]{36})\/issues\/([0-9a-f-]{36})\/attachments(?:\/|$)/i,
      );
      const attachmentPathMatch = req.path.match(/^\/attachments\/([0-9a-f-]{36})(?:\/|$)/i);
      const attachmentIssueId = attachmentPathMatch
        ? await db.select({ issueId: issueAttachments.issueId }).from(issueAttachments)
            .where(eq(issueAttachments.id, attachmentPathMatch[1])).then((rows) => rows[0]?.issueId ?? null)
        : null;
      const issueId = issuePathMatch?.[1] ?? companyAttachmentMatch?.[2] ?? attachmentIssueId;
      if (issueId) {
        const frozen = await isCrelioV6ExecutionFrozenIssue(db, issueId);
        if (!frozen) return next();
        if ((companyAttachmentMatch && req.method === "POST" || attachmentPathMatch && req.method === "DELETE") && frozen.binding) {
          await assertCrelioV6ControllerGrant(db, {
            actor: actor(req),
            projectId: frozen.binding.projectId,
            generation: frozen.binding.generation,
            operation: "issue.attach",
            fencingGeneration: parseFencingHeader(req),
          });
          return next();
        }
        if (/\/tree-holds(?:\/|$)/.test(req.path) && req.method === "POST" && frozen.binding) {
          await assertCrelioV6ControllerGrant(db, {
            actor: actor(req),
            projectId: frozen.binding.projectId,
            generation: frozen.binding.generation,
            operation: "issue.hold",
            fencingGeneration: parseFencingHeader(req),
          });
          return next();
        }
        throw forbidden(frozen.legacy
          ? "This legacy issue is frozen by the active schema-v6 project floor"
          : "This schema-v6 issue is externally lifecycle-owned; use the V6 controller or operator surface");
      }

      const workspacePathMatch = req.path.match(/^\/execution-workspaces\/([0-9a-f-]{36})(?:\/|$)/i);
      if (workspacePathMatch) {
        const workspace = await db.select({ sourceIssueId: executionWorkspaces.sourceIssueId })
          .from(executionWorkspaces).where(eq(executionWorkspaces.id, workspacePathMatch[1]))
          .then((rows) => rows[0] ?? null);
        if (workspace?.sourceIssueId) {
          const frozen = await isCrelioV6ExecutionFrozenIssue(db, workspace.sourceIssueId);
          if (frozen) {
            const isArchive = req.method === "PATCH" && req.body?.status === "archived";
            if (!isArchive || !frozen.binding) {
              throw forbidden("This execution workspace belongs to a schema-v6 frozen chain");
            }
            await assertCrelioV6ControllerGrant(db, {
              actor: actor(req),
              projectId: frozen.binding.projectId,
              generation: frozen.binding.generation,
              operation: "workspace.close",
              fencingGeneration: parseFencingHeader(req),
            });
            return next();
          }
        }
      }

      if (req.method === "POST" && /^\/companies\/[0-9a-f-]{36}\/issues$/i.test(req.path)) {
        const projectId = typeof req.body?.projectId === "string" ? req.body.projectId : null;
        if (projectId) {
          const policy = await crelioV6Service(db).getProjectPolicy(projectId);
          if (policy?.schemaFloor && policy.schemaFloor >= 6) {
            throw forbidden("Stock issue creation is disabled for a schema-v6 project");
          }
        }
      }
      next();
    } catch (error) {
      next(error);
    }
  };
}
