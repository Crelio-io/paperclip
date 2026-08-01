# Crelio V6 Paperclip hook matrix

Base: upstream `v2026.722.0` at `e55d702916c4d3ddbcac49b697f879808b160f59`.

This matrix is a release artifact. Any upstream rebase or changed execution path must
update the disposition and pass the integration suite before a new image is signed.

| Paperclip mutation or recovery path | V6 disposition | Enforcement location |
|---|---|---|
| Stock issue create and child create | Reject for a schema-floor project | `services/issues.ts`; V6 provenance is not authorization |
| Stock issue update/assignment/status/reopen | Reject for bound and frozen legacy issues | `services/issues.ts`; stock mutation middleware |
| Assignment and normal manual wakes | Suppress | `services/heartbeat.ts` external-lifecycle check |
| Wake enqueue/status/cancel | Controller activation may enqueue once; later status/cancel is journaled in the source transaction | `services/crelio-v6.ts`, `services/heartbeat.ts`, tree-control transaction hook |
| Mention, comment, interaction, approval-resolution wakes | Suppress | stock mutation middleware and heartbeat dispatch guard |
| Controller activation/reopen/fresh retry | Allow once with exact grant, generation, fence, nonce, issue version and attempt | `services/crelio-v6.ts`; V6 routes |
| Run claim | Consume the one-time lifecycle authorization atomically | `services/heartbeat.ts`; `claimCrelioV6LifecycleRun` |
| Agent checkout | Allow only for the consuming authorized run | `services/issues.ts` |
| Max-turn continuation | Suppress | heartbeat queue guard and external retry owner |
| Transient provider/native bounded retry | Suppress | heartbeat retry classification guard |
| Process-loss/zombie recovery | Release locks but create no V6 wake | heartbeat finalization/recovery guard |
| Missing-comment, successful-run handoff, review recovery | Suppress | external retry owner and atomic V6 completion |
| Scheduled monitor/retry-now/liveness repair | Reject or suppress | stock mutation middleware and heartbeat guard |
| Agent comment/status completion | Reject | stock mutation guard; use run-bound `/v6-complete` |
| Run-bound completion | Atomic issue disposition, compact comment, binding receipt and journal event | `services/crelio-v6.ts` |
| Tree hold apply/release | Controller grant only | tree-control routes/services and stock guard |
| Final Handoff attachments | Controller grant, backlog final stage only, read-back required | attachment routes and controller receipt |
| Final approval | Exact human subject, required comment, no controller-key approval | `services/crelio-v6.ts`; `/v6-decision` |
| Integration close | Exact controller receipt and final issue | `services/crelio-v6.ts` |
| Workspace archive | Exact `{status: "archived"}` controller mutation only, for the source-issue-bound V6 workspace under the active generation/key/fence and `workspace.close` grant; every broader workspace mutation retains stock `runtime:manage` authorization | execution-workspace routes/services |
| Journal event append | Same source transaction, per-project generation sequence | `services/crelio-v6.ts` plus patched source mutations |
| API-key prepare/probe/activate/revocation | Admin prepares an exact-scope successor; only harmless probe/activation works during overlap; activation revokes predecessor key and grant transactionally; stock revocation atomically revokes any V6 grant and journals the denial | `services/crelio-v6.ts`, `services/board-auth.ts`, `services/crelio-v6-key-revocation.ts`; V6 controller-key routes |
| Prepared/active generation switch | Prepared policy fields cannot change the active key/fence/contracts; exact completed freeze and prior-generation quiescence are mandatory | `services/crelio-v6.ts`; additive V6 migration |
| Snapshot | Transactional, bounded, sanitized, hash-bound | `services/crelio-v6.ts` |
| Legacy V2-V5 execution after floor | Reject all runnable paths; reads remain available | project floor guards |
| Maintenance rollback runtime | Guards remain enabled; no adapter execution | deployment/cutover contract |
