import {
  bigint,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";
import { agents } from "./agents.js";
import { authUsers } from "./auth.js";
import { boardApiKeys } from "./board_api_keys.js";
import { companies } from "./companies.js";
import { heartbeatRuns } from "./heartbeat_runs.js";
import { issues } from "./issues.js";
import { projects } from "./projects.js";

/**
 * Crelio's schema-v6 article lifecycle extension.
 *
 * These records deliberately live beside Paperclip's stock issue/run tables. They
 * add an external lifecycle owner without overloading mutable issue JSON fields.
 */
export const crelioV6ProjectPolicies = pgTable("crelio_v6_project_policies", {
  projectId: uuid("project_id").primaryKey().references(() => projects.id, { onDelete: "cascade" }),
  companyId: uuid("company_id").notNull().references(() => companies.id, { onDelete: "cascade" }),
  schemaFloor: integer("schema_floor").notNull().default(0),
  preparedGeneration: text("prepared_generation"),
  activeGeneration: text("active_generation"),
  preparedControllerUserId: text("prepared_controller_user_id").references(() => authUsers.id, { onDelete: "restrict" }),
  preparedControllerApiKeyId: uuid("prepared_controller_api_key_id").references(() => boardApiKeys.id, { onDelete: "restrict" }),
  controllerUserId: text("controller_user_id").references(() => authUsers.id, { onDelete: "restrict" }),
  controllerApiKeyId: uuid("controller_api_key_id").references(() => boardApiKeys.id, { onDelete: "restrict" }),
  preparedFencingGeneration: bigint("prepared_fencing_generation", { mode: "number" }).notNull().default(0),
  activeFencingGeneration: bigint("active_fencing_generation", { mode: "number" }).notNull().default(0),
  policyVersion: integer("policy_version").notNull().default(1),
  optimisticVersion: bigint("optimistic_version", { mode: "number" }).notNull().default(1),
  preparedManifestSha256: text("prepared_manifest_sha256"),
  activationReceiptSha256: text("activation_receipt_sha256"),
  preparedLegacyFreezeInventorySha256: text("prepared_legacy_freeze_inventory_sha256"),
  preparedInstructionContractSha256: text("prepared_instruction_contract_sha256"),
  preparedBudgetPolicySha256: text("prepared_budget_policy_sha256"),
  legacyFreezeInventorySha256: text("legacy_freeze_inventory_sha256"),
  instructionContractSha256: text("instruction_contract_sha256"),
  budgetPolicySha256: text("budget_policy_sha256"),
  preparedAt: timestamp("prepared_at", { withTimezone: true }),
  activatedAt: timestamp("activated_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
  companyIdx: index("crelio_v6_project_policies_company_idx").on(table.companyId),
  activeGenerationIdx: index("crelio_v6_project_policies_active_generation_idx").on(table.activeGeneration),
}));

export const crelioV6ControllerGrants = pgTable("crelio_v6_controller_grants", {
  id: uuid("id").primaryKey().defaultRandom(),
  companyId: uuid("company_id").notNull().references(() => companies.id, { onDelete: "cascade" }),
  projectId: uuid("project_id").notNull().references(() => projects.id, { onDelete: "cascade" }),
  boardUserId: text("board_user_id").notNull().references(() => authUsers.id, { onDelete: "cascade" }),
  boardApiKeyId: uuid("board_api_key_id").notNull().references(() => boardApiKeys.id, { onDelete: "cascade" }),
  generation: text("generation").notNull(),
  allowedOperations: jsonb("allowed_operations").$type<string[]>().notNull(),
  allowedAgentIds: jsonb("allowed_agent_ids").$type<string[]>().notNull(),
  scopeSha256: text("scope_sha256").notNull(),
  validFrom: timestamp("valid_from", { withTimezone: true }).notNull().defaultNow(),
  validUntil: timestamp("valid_until", { withTimezone: true }),
  rotationPredecessorId: uuid("rotation_predecessor_id"),
  rotationGeneration: integer("rotation_generation").notNull().default(1),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
  keyProjectGenerationUq: uniqueIndex("crelio_v6_controller_grants_key_project_generation_uq")
    .on(table.boardApiKeyId, table.projectId, table.generation),
  projectGenerationIdx: index("crelio_v6_controller_grants_project_generation_idx")
    .on(table.projectId, table.generation),
}));

export const crelioV6IssueBindings = pgTable("crelio_v6_issue_bindings", {
  issueId: uuid("issue_id").primaryKey().references(() => issues.id, { onDelete: "cascade" }),
  companyId: uuid("company_id").notNull().references(() => companies.id, { onDelete: "cascade" }),
  projectId: uuid("project_id").notNull().references(() => projects.id, { onDelete: "cascade" }),
  rootIssueId: uuid("root_issue_id").notNull().references(() => issues.id, { onDelete: "cascade" }),
  generation: text("generation").notNull(),
  workflowSchema: integer("workflow_schema").notNull().default(6),
  controllerStateVersion: bigint("controller_state_version", { mode: "number" }).notNull(),
  createRequestSha256: text("create_request_sha256").notNull(),
  issueVersion: bigint("issue_version", { mode: "number" }).notNull().default(1),
  lifecycleOwner: text("lifecycle_owner").notNull().default("crelio_controller"),
  retryOwner: text("retry_owner").notNull().default("crelio_controller"),
  phase: text("phase").notNull(),
  currentAttempt: integer("current_attempt").notNull().default(1),
  workspaceAnchorIssueId: uuid("workspace_anchor_issue_id").references(() => issues.id, { onDelete: "restrict" }),
  authorizationReceiptSha256: text("authorization_receipt_sha256"),
  authorizationOperation: text("authorization_operation"),
  authorizationOutputPrefix: text("authorization_output_prefix"),
  authorizationExpiresAt: timestamp("authorization_expires_at", { withTimezone: true }),
  lifecycleState: text("lifecycle_state").notNull().default("passive"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
  rootIdx: index("crelio_v6_issue_bindings_root_idx").on(table.rootIssueId),
  projectGenerationIdx: index("crelio_v6_issue_bindings_project_generation_idx")
    .on(table.projectId, table.generation),
  rootPhaseAttemptUq: uniqueIndex("crelio_v6_issue_bindings_root_phase_attempt_uq")
    .on(table.rootIssueId, table.phase, table.currentAttempt),
}));

export const crelioV6LifecycleAuthorizations = pgTable("crelio_v6_lifecycle_authorizations", {
  id: uuid("id").primaryKey().defaultRandom(),
  companyId: uuid("company_id").notNull().references(() => companies.id, { onDelete: "cascade" }),
  projectId: uuid("project_id").notNull().references(() => projects.id, { onDelete: "cascade" }),
  rootIssueId: uuid("root_issue_id").notNull().references(() => issues.id, { onDelete: "cascade" }),
  issueId: uuid("issue_id").notNull().references(() => issues.id, { onDelete: "cascade" }),
  generation: text("generation").notNull(),
  attempt: integer("attempt").notNull(),
  activationKind: text("activation_kind").notNull(),
  idempotencyKey: text("idempotency_key").notNull(),
  requestSha256: text("request_sha256").notNull(),
  nonceSha256: text("nonce_sha256").notNull(),
  expectedIssueVersion: bigint("expected_issue_version", { mode: "number" }).notNull(),
  expectedControllerStateVersion: bigint("expected_controller_state_version", { mode: "number" }).notNull(),
  expectedStatus: text("expected_status").notNull(),
  expectedAssigneeAgentId: uuid("expected_assignee_agent_id").notNull().references(() => agents.id, { onDelete: "restrict" }),
  fencingGeneration: bigint("fencing_generation", { mode: "number" }).notNull(),
  wakeupRequestId: uuid("wakeup_request_id"),
  runId: uuid("run_id").references(() => heartbeatRuns.id, { onDelete: "set null" }),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  consumedAt: timestamp("consumed_at", { withTimezone: true }),
  consumingRunId: uuid("consuming_run_id").references(() => heartbeatRuns.id, { onDelete: "set null" }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
  idempotencyUq: uniqueIndex("crelio_v6_lifecycle_authorizations_idempotency_uq")
    .on(table.projectId, table.generation, table.idempotencyKey),
  nonceUq: uniqueIndex("crelio_v6_lifecycle_authorizations_nonce_uq").on(table.nonceSha256),
  issueAttemptIdx: index("crelio_v6_lifecycle_authorizations_issue_attempt_idx")
    .on(table.issueId, table.attempt),
}));

export const crelioV6CompletionReceipts = pgTable("crelio_v6_completion_receipts", {
  id: uuid("id").primaryKey().defaultRandom(),
  companyId: uuid("company_id").notNull().references(() => companies.id, { onDelete: "cascade" }),
  projectId: uuid("project_id").notNull().references(() => projects.id, { onDelete: "cascade" }),
  rootIssueId: uuid("root_issue_id").notNull().references(() => issues.id, { onDelete: "cascade" }),
  issueId: uuid("issue_id").notNull().references(() => issues.id, { onDelete: "cascade" }),
  runId: uuid("run_id").notNull().references(() => heartbeatRuns.id, { onDelete: "restrict" }),
  generation: text("generation").notNull(),
  attempt: integer("attempt").notNull(),
  idempotencyKey: text("idempotency_key").notNull(),
  requestSha256: text("request_sha256").notNull(),
  commentId: uuid("comment_id").notNull(),
  commentSha256: text("comment_sha256").notNull(),
  disposition: text("disposition").notNull(),
  resultingIssueVersion: bigint("resulting_issue_version", { mode: "number" }).notNull(),
  resultingPolicyVersion: bigint("resulting_policy_version", { mode: "number" }),
  commitOid: text("commit_oid").notNull(),
  handoffSha256: text("handoff_sha256").notNull(),
  journalSequence: bigint("journal_sequence", { mode: "number" }).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
  idempotencyUq: uniqueIndex("crelio_v6_completion_receipts_idempotency_uq")
    .on(table.projectId, table.generation, table.idempotencyKey),
  runIssueAttemptUq: uniqueIndex("crelio_v6_completion_receipts_run_issue_attempt_uq")
    .on(table.runId, table.issueId, table.attempt),
}));

export const crelioV6ApprovalSubjects = pgTable("crelio_v6_approval_subjects", {
  issueId: uuid("issue_id").primaryKey().references(() => issues.id, { onDelete: "cascade" }),
  projectId: uuid("project_id").notNull().references(() => projects.id, { onDelete: "cascade" }),
  generation: text("generation").notNull(),
  approverUserId: text("approver_user_id").notNull().references(() => authUsers.id, { onDelete: "restrict" }),
  frozenHeadOid: text("frozen_head_oid").notNull(),
  checkpointSha256: text("checkpoint_sha256").notNull(),
  packageSha256: text("package_sha256").notNull(),
  attachmentReceiptSha256: text("attachment_receipt_sha256").notNull(),
  policySha256: text("policy_sha256").notNull(),
  descriptionSha256: text("description_sha256").notNull(),
  handoffFinalizedSha256: text("handoff_finalized_sha256"),
  subjectSha256: text("subject_sha256").notNull(),
  decidedAt: timestamp("decided_at", { withTimezone: true }),
  decision: text("decision"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const crelioV6JournalHeads = pgTable("crelio_v6_journal_heads", {
  projectId: uuid("project_id").primaryKey().references(() => projects.id, { onDelete: "cascade" }),
  lastCommittedSequence: bigint("last_committed_sequence", { mode: "number" }).notNull().default(0),
  firstRetainedSequence: bigint("first_retained_sequence", { mode: "number" }).notNull().default(1),
  retentionWatermark: bigint("retention_watermark", { mode: "number" }).notNull().default(0),
  optimisticVersion: bigint("optimistic_version", { mode: "number" }).notNull().default(1),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const crelioV6JournalEvents = pgTable("crelio_v6_journal_events", {
  projectId: uuid("project_id").notNull().references(() => projects.id, { onDelete: "cascade" }),
  sequence: bigint("sequence", { mode: "number" }).notNull(),
  generation: text("generation").notNull(),
  entityKind: text("entity_kind").notNull(),
  entityId: text("entity_id").notNull(),
  entityVersion: bigint("entity_version", { mode: "number" }).notNull(),
  mutationKind: text("mutation_kind").notNull(),
  reductionPayload: jsonb("reduction_payload").$type<Record<string, unknown>>().notNull(),
  sourceTransactionId: uuid("source_transaction_id").notNull(),
  committedAt: timestamp("committed_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
  pk: primaryKey({ columns: [table.projectId, table.sequence], name: "crelio_v6_journal_events_pk" }),
  entityIdx: index("crelio_v6_journal_events_entity_idx")
    .on(table.projectId, table.entityKind, table.entityId, table.sequence),
  committedIdx: index("crelio_v6_journal_events_committed_idx").on(table.projectId, table.committedAt),
}));

export const crelioV6SnapshotSessions = pgTable("crelio_v6_snapshot_sessions", {
  id: uuid("id").primaryKey().defaultRandom(),
  projectId: uuid("project_id").notNull().references(() => projects.id, { onDelete: "cascade" }),
  rootIssueId: uuid("root_issue_id").notNull().references(() => issues.id, { onDelete: "cascade" }),
  generation: text("generation").notNull(),
  boardApiKeyId: uuid("board_api_key_id").notNull().references(() => boardApiKeys.id, { onDelete: "cascade" }),
  snapshotSha256: text("snapshot_sha256").notNull(),
  payload: jsonb("payload").$type<Record<string, unknown>>().notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
  expiryIdx: index("crelio_v6_snapshot_sessions_expiry_idx").on(table.expiresAt),
}));

export const crelioV6LegacyFreezes = pgTable("crelio_v6_legacy_freezes", {
  id: uuid("id").primaryKey().defaultRandom(),
  projectId: uuid("project_id").notNull().references(() => projects.id, { onDelete: "cascade" }),
  companyId: uuid("company_id").notNull().references(() => companies.id, { onDelete: "cascade" }),
  generation: text("generation").notNull(),
  status: text("status").notNull().default("started"),
  inventorySha256: text("inventory_sha256").notNull(),
  inventory: jsonb("inventory").$type<Record<string, unknown>>().notNull(),
  result: jsonb("result").$type<Record<string, unknown>>(),
  startedAt: timestamp("started_at", { withTimezone: true }).notNull().defaultNow(),
  completedAt: timestamp("completed_at", { withTimezone: true }),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
  projectGenerationUq: uniqueIndex("crelio_v6_legacy_freezes_project_generation_uq")
    .on(table.projectId, table.generation),
  projectStatusIdx: index("crelio_v6_legacy_freezes_project_status_idx")
    .on(table.projectId, table.status),
}));
