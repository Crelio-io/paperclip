CREATE TABLE "crelio_v6_approval_subjects" (
	"issue_id" uuid PRIMARY KEY NOT NULL,
	"project_id" uuid NOT NULL,
	"generation" text NOT NULL,
	"approver_user_id" text NOT NULL,
	"frozen_head_oid" text NOT NULL,
	"checkpoint_sha256" text NOT NULL,
	"package_sha256" text NOT NULL,
	"attachment_receipt_sha256" text NOT NULL,
	"policy_sha256" text NOT NULL,
	"description_sha256" text NOT NULL,
	"handoff_finalized_sha256" text,
	"subject_sha256" text NOT NULL,
	"decided_at" timestamp with time zone,
	"decision" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "crelio_v6_completion_receipts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"company_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"root_issue_id" uuid NOT NULL,
	"issue_id" uuid NOT NULL,
	"run_id" uuid NOT NULL,
	"generation" text NOT NULL,
	"attempt" integer NOT NULL,
	"idempotency_key" text NOT NULL,
	"request_sha256" text NOT NULL,
	"comment_id" uuid NOT NULL,
	"comment_sha256" text NOT NULL,
	"disposition" text NOT NULL,
	"resulting_issue_version" bigint NOT NULL,
	"resulting_policy_version" bigint,
	"commit_oid" text NOT NULL,
	"handoff_sha256" text NOT NULL,
	"journal_sequence" bigint NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "crelio_v6_controller_grants" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"company_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"board_user_id" text NOT NULL,
	"board_api_key_id" uuid NOT NULL,
	"generation" text NOT NULL,
	"allowed_operations" jsonb NOT NULL,
	"allowed_agent_ids" jsonb NOT NULL,
	"scope_sha256" text NOT NULL,
	"valid_from" timestamp with time zone DEFAULT now() NOT NULL,
	"valid_until" timestamp with time zone,
	"rotation_predecessor_id" uuid,
	"rotation_generation" integer DEFAULT 1 NOT NULL,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "crelio_v6_issue_bindings" (
	"issue_id" uuid PRIMARY KEY NOT NULL,
	"company_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"root_issue_id" uuid NOT NULL,
	"generation" text NOT NULL,
	"workflow_schema" integer DEFAULT 6 NOT NULL,
	"controller_state_version" bigint NOT NULL,
	"create_request_sha256" text NOT NULL,
	"issue_version" bigint DEFAULT 1 NOT NULL,
	"lifecycle_owner" text DEFAULT 'crelio_controller' NOT NULL,
	"retry_owner" text DEFAULT 'crelio_controller' NOT NULL,
	"phase" text NOT NULL,
	"current_attempt" integer DEFAULT 1 NOT NULL,
	"workspace_anchor_issue_id" uuid,
	"authorization_receipt_sha256" text,
	"authorization_operation" text,
	"authorization_output_prefix" text,
	"authorization_expires_at" timestamp with time zone,
	"lifecycle_state" text DEFAULT 'passive' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "crelio_v6_journal_events" (
	"project_id" uuid NOT NULL,
	"sequence" bigint NOT NULL,
	"generation" text NOT NULL,
	"entity_kind" text NOT NULL,
	"entity_id" text NOT NULL,
	"entity_version" bigint NOT NULL,
	"mutation_kind" text NOT NULL,
	"reduction_payload" jsonb NOT NULL,
	"source_transaction_id" uuid NOT NULL,
	"committed_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "crelio_v6_journal_events_pk" PRIMARY KEY("project_id","sequence")
);
--> statement-breakpoint
CREATE TABLE "crelio_v6_journal_heads" (
	"project_id" uuid PRIMARY KEY NOT NULL,
	"last_committed_sequence" bigint DEFAULT 0 NOT NULL,
	"first_retained_sequence" bigint DEFAULT 1 NOT NULL,
	"retention_watermark" bigint DEFAULT 0 NOT NULL,
	"optimistic_version" bigint DEFAULT 1 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "crelio_v6_legacy_freezes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"project_id" uuid NOT NULL,
	"company_id" uuid NOT NULL,
	"generation" text NOT NULL,
	"status" text DEFAULT 'started' NOT NULL,
	"inventory_sha256" text NOT NULL,
	"inventory" jsonb NOT NULL,
	"result" jsonb,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "crelio_v6_lifecycle_authorizations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"company_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"root_issue_id" uuid NOT NULL,
	"issue_id" uuid NOT NULL,
	"generation" text NOT NULL,
	"attempt" integer NOT NULL,
	"activation_kind" text NOT NULL,
	"idempotency_key" text NOT NULL,
	"request_sha256" text NOT NULL,
	"nonce_sha256" text NOT NULL,
	"expected_issue_version" bigint NOT NULL,
	"expected_controller_state_version" bigint NOT NULL,
	"expected_status" text NOT NULL,
	"expected_assignee_agent_id" uuid NOT NULL,
	"fencing_generation" bigint NOT NULL,
	"wakeup_request_id" uuid,
	"run_id" uuid,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"consuming_run_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "crelio_v6_project_policies" (
	"project_id" uuid PRIMARY KEY NOT NULL,
	"company_id" uuid NOT NULL,
	"schema_floor" integer DEFAULT 0 NOT NULL,
	"prepared_generation" text,
	"active_generation" text,
	"prepared_controller_user_id" text,
	"prepared_controller_api_key_id" uuid,
	"controller_user_id" text,
	"controller_api_key_id" uuid,
	"prepared_fencing_generation" bigint DEFAULT 0 NOT NULL,
	"active_fencing_generation" bigint DEFAULT 0 NOT NULL,
	"policy_version" integer DEFAULT 1 NOT NULL,
	"optimistic_version" bigint DEFAULT 1 NOT NULL,
	"prepared_manifest_sha256" text,
	"activation_receipt_sha256" text,
	"prepared_legacy_freeze_inventory_sha256" text,
	"prepared_instruction_contract_sha256" text,
	"prepared_budget_policy_sha256" text,
	"legacy_freeze_inventory_sha256" text,
	"instruction_contract_sha256" text,
	"budget_policy_sha256" text,
	"prepared_at" timestamp with time zone,
	"activated_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "crelio_v6_snapshot_sessions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"project_id" uuid NOT NULL,
	"root_issue_id" uuid NOT NULL,
	"generation" text NOT NULL,
	"board_api_key_id" uuid NOT NULL,
	"snapshot_sha256" text NOT NULL,
	"payload" jsonb NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "crelio_v6_approval_subjects" ADD CONSTRAINT "crelio_v6_approval_subjects_issue_id_issues_id_fk" FOREIGN KEY ("issue_id") REFERENCES "public"."issues"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_approval_subjects" ADD CONSTRAINT "crelio_v6_approval_subjects_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_approval_subjects" ADD CONSTRAINT "crelio_v6_approval_subjects_approver_user_id_user_id_fk" FOREIGN KEY ("approver_user_id") REFERENCES "public"."user"("id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_completion_receipts" ADD CONSTRAINT "crelio_v6_completion_receipts_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_completion_receipts" ADD CONSTRAINT "crelio_v6_completion_receipts_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_completion_receipts" ADD CONSTRAINT "crelio_v6_completion_receipts_root_issue_id_issues_id_fk" FOREIGN KEY ("root_issue_id") REFERENCES "public"."issues"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_completion_receipts" ADD CONSTRAINT "crelio_v6_completion_receipts_issue_id_issues_id_fk" FOREIGN KEY ("issue_id") REFERENCES "public"."issues"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_completion_receipts" ADD CONSTRAINT "crelio_v6_completion_receipts_run_id_heartbeat_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."heartbeat_runs"("id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_controller_grants" ADD CONSTRAINT "crelio_v6_controller_grants_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_controller_grants" ADD CONSTRAINT "crelio_v6_controller_grants_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_controller_grants" ADD CONSTRAINT "crelio_v6_controller_grants_board_user_id_user_id_fk" FOREIGN KEY ("board_user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_controller_grants" ADD CONSTRAINT "crelio_v6_controller_grants_board_api_key_id_board_api_keys_id_fk" FOREIGN KEY ("board_api_key_id") REFERENCES "public"."board_api_keys"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_issue_bindings" ADD CONSTRAINT "crelio_v6_issue_bindings_issue_id_issues_id_fk" FOREIGN KEY ("issue_id") REFERENCES "public"."issues"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_issue_bindings" ADD CONSTRAINT "crelio_v6_issue_bindings_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_issue_bindings" ADD CONSTRAINT "crelio_v6_issue_bindings_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_issue_bindings" ADD CONSTRAINT "crelio_v6_issue_bindings_root_issue_id_issues_id_fk" FOREIGN KEY ("root_issue_id") REFERENCES "public"."issues"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_issue_bindings" ADD CONSTRAINT "crelio_v6_issue_bindings_workspace_anchor_issue_id_issues_id_fk" FOREIGN KEY ("workspace_anchor_issue_id") REFERENCES "public"."issues"("id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_journal_events" ADD CONSTRAINT "crelio_v6_journal_events_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_journal_heads" ADD CONSTRAINT "crelio_v6_journal_heads_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_legacy_freezes" ADD CONSTRAINT "crelio_v6_legacy_freezes_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_legacy_freezes" ADD CONSTRAINT "crelio_v6_legacy_freezes_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_lifecycle_authorizations" ADD CONSTRAINT "crelio_v6_lifecycle_authorizations_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_lifecycle_authorizations" ADD CONSTRAINT "crelio_v6_lifecycle_authorizations_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_lifecycle_authorizations" ADD CONSTRAINT "crelio_v6_lifecycle_authorizations_root_issue_id_issues_id_fk" FOREIGN KEY ("root_issue_id") REFERENCES "public"."issues"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_lifecycle_authorizations" ADD CONSTRAINT "crelio_v6_lifecycle_authorizations_issue_id_issues_id_fk" FOREIGN KEY ("issue_id") REFERENCES "public"."issues"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_lifecycle_authorizations" ADD CONSTRAINT "crelio_v6_lifecycle_authorizations_expected_assignee_agent_id_agents_id_fk" FOREIGN KEY ("expected_assignee_agent_id") REFERENCES "public"."agents"("id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_lifecycle_authorizations" ADD CONSTRAINT "crelio_v6_lifecycle_authorizations_run_id_heartbeat_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."heartbeat_runs"("id") ON DELETE set null ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_lifecycle_authorizations" ADD CONSTRAINT "crelio_v6_lifecycle_authorizations_consuming_run_id_heartbeat_runs_id_fk" FOREIGN KEY ("consuming_run_id") REFERENCES "public"."heartbeat_runs"("id") ON DELETE set null ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_project_policies" ADD CONSTRAINT "crelio_v6_project_policies_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_project_policies" ADD CONSTRAINT "crelio_v6_project_policies_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_project_policies" ADD CONSTRAINT "crelio_v6_project_policies_controller_user_id_user_id_fk" FOREIGN KEY ("controller_user_id") REFERENCES "public"."user"("id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_project_policies" ADD CONSTRAINT "crelio_v6_project_policies_controller_api_key_id_board_api_keys_id_fk" FOREIGN KEY ("controller_api_key_id") REFERENCES "public"."board_api_keys"("id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_project_policies" ADD CONSTRAINT "crelio_v6_project_policies_prepared_controller_user_id_user_id_fk" FOREIGN KEY ("prepared_controller_user_id") REFERENCES "public"."user"("id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_project_policies" ADD CONSTRAINT "crelio_v6_project_policies_prepared_controller_api_key_id_board_api_keys_id_fk" FOREIGN KEY ("prepared_controller_api_key_id") REFERENCES "public"."board_api_keys"("id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_snapshot_sessions" ADD CONSTRAINT "crelio_v6_snapshot_sessions_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_snapshot_sessions" ADD CONSTRAINT "crelio_v6_snapshot_sessions_root_issue_id_issues_id_fk" FOREIGN KEY ("root_issue_id") REFERENCES "public"."issues"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "crelio_v6_snapshot_sessions" ADD CONSTRAINT "crelio_v6_snapshot_sessions_board_api_key_id_board_api_keys_id_fk" FOREIGN KEY ("board_api_key_id") REFERENCES "public"."board_api_keys"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
CREATE UNIQUE INDEX "crelio_v6_completion_receipts_idempotency_uq" ON "crelio_v6_completion_receipts" USING btree ("project_id","generation","idempotency_key");
--> statement-breakpoint
CREATE UNIQUE INDEX "crelio_v6_completion_receipts_run_issue_attempt_uq" ON "crelio_v6_completion_receipts" USING btree ("run_id","issue_id","attempt");
--> statement-breakpoint
CREATE UNIQUE INDEX "crelio_v6_controller_grants_key_project_generation_uq" ON "crelio_v6_controller_grants" USING btree ("board_api_key_id","project_id","generation");
--> statement-breakpoint
CREATE INDEX "crelio_v6_controller_grants_project_generation_idx" ON "crelio_v6_controller_grants" USING btree ("project_id","generation");
--> statement-breakpoint
CREATE INDEX "crelio_v6_issue_bindings_root_idx" ON "crelio_v6_issue_bindings" USING btree ("root_issue_id");
--> statement-breakpoint
CREATE INDEX "crelio_v6_issue_bindings_project_generation_idx" ON "crelio_v6_issue_bindings" USING btree ("project_id","generation");
--> statement-breakpoint
CREATE UNIQUE INDEX "crelio_v6_issue_bindings_root_phase_attempt_uq" ON "crelio_v6_issue_bindings" USING btree ("root_issue_id","phase","current_attempt");
--> statement-breakpoint
CREATE INDEX "crelio_v6_journal_events_entity_idx" ON "crelio_v6_journal_events" USING btree ("project_id","entity_kind","entity_id","sequence");
--> statement-breakpoint
CREATE INDEX "crelio_v6_journal_events_committed_idx" ON "crelio_v6_journal_events" USING btree ("project_id","committed_at");
--> statement-breakpoint
CREATE UNIQUE INDEX "crelio_v6_legacy_freezes_project_generation_uq" ON "crelio_v6_legacy_freezes" USING btree ("project_id","generation");
--> statement-breakpoint
CREATE INDEX "crelio_v6_legacy_freezes_project_status_idx" ON "crelio_v6_legacy_freezes" USING btree ("project_id","status");
--> statement-breakpoint
CREATE UNIQUE INDEX "crelio_v6_lifecycle_authorizations_idempotency_uq" ON "crelio_v6_lifecycle_authorizations" USING btree ("project_id","generation","idempotency_key");
--> statement-breakpoint
CREATE UNIQUE INDEX "crelio_v6_lifecycle_authorizations_nonce_uq" ON "crelio_v6_lifecycle_authorizations" USING btree ("nonce_sha256");
--> statement-breakpoint
CREATE INDEX "crelio_v6_lifecycle_authorizations_issue_attempt_idx" ON "crelio_v6_lifecycle_authorizations" USING btree ("issue_id","attempt");
--> statement-breakpoint
CREATE INDEX "crelio_v6_project_policies_company_idx" ON "crelio_v6_project_policies" USING btree ("company_id");
--> statement-breakpoint
CREATE INDEX "crelio_v6_project_policies_active_generation_idx" ON "crelio_v6_project_policies" USING btree ("active_generation");
--> statement-breakpoint
CREATE INDEX "crelio_v6_snapshot_sessions_expiry_idx" ON "crelio_v6_snapshot_sessions" USING btree ("expires_at");
