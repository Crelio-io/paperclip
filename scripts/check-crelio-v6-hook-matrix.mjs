#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const upstream = "e55d702916c4d3ddbcac49b697f879808b160f59";
const upstreamFiles = new Map([
  ["server/src/services/heartbeat.ts", "bad4820a4e035509c9bf902fc78d4d044b11c0b1954e28399d605b285cf2d893"],
  ["server/src/services/issues.ts", "a84ee50d151efcfd6c633a9dcbcec53404b8b014804537e52b86d6ca0b58eaf6"],
  ["server/src/services/recovery/service.ts", "a1008f902bb28cdf3daedaccf1551a3eca07e07607667eee3ce29cfe6afcd733"],
  ["server/src/services/productivity-review.ts", "57bd609cf5a8fa9427c684559d492125f42607136ef51871bbda1fecfa4757d2"],
  ["server/src/services/issue-tree-control.ts", "994de8d69c771a221dfcc15d902e551b449ce992ec059b645dd7f4da1bd02fc9"],
  ["server/src/routes/issue-tree-control.ts", "8282afc895031763d1f2620e7cb420b036c8746065d25ecc019733769fa9aaa6"],
  ["server/src/services/workspace-operations.ts", "0f5b4ed6c29a4e8f445cdfdb91aaf3b28ad6ef42cb363216148c99092fa1301e"],
  ["server/src/routes/execution-workspaces.ts", "4041f4528dbaedbb5b2b9ce8d9d7c14b9e698c46874c1b90c8daf6d0fa699330"],
  ["server/src/services/board-auth.ts", "54b0f3d817444bc7b791fa36bd12912ebf506a22d1c3f756825dcdb00faf5bf9"],
  ["server/src/routes/openapi.ts", "3e73e7da94d0d89cabb3ae8d94e2c12752d103e67a8cde8ac490dacf4d564bd2"],
]);

const mutationCounts = new Map([
  ["server/src/services/heartbeat.ts", 99],
  ["server/src/services/issues.ts", 17],
  ["server/src/services/recovery/service.ts", 9],
  ["server/src/services/productivity-review.ts", 3],
  ["server/src/services/issue-tree-control.ts", 8],
  ["server/src/routes/issue-tree-control.ts", 0],
  ["server/src/services/workspace-operations.ts", 4],
]);

const requiredMarkers = new Map([
  ["server/src/services/heartbeat.ts", [
    "claimCrelioV6LifecycleRun",
    "appendCrelioV6WakeStatusJournal",
    "suppressed native missing-comment retry for V6 issue",
    "suppressed native process-loss retry for V6 issue",
    "suppressed native liveness continuation for V6 issue",
    "suppressed native successful-run handoff recovery for V6 issue",
    "crelio_v6_external_retry_owner",
    "crelio_v6_external_lifecycle_owner",
  ]],
  ["server/src/services/issues.ts", [
    "Stock and internal issue creation are frozen",
    "Schema-v6 comments require the atomic completion",
    "crelioV6TransactionHook",
  ]],
  ["server/src/services/recovery/service.ts", ["isCrelioV6ExecutionFrozenIssue"]],
  ["server/src/services/productivity-review.ts", ["isCrelioV6ExecutionFrozenIssue"]],
  ["server/src/services/issue-tree-control.ts", ["transactionHook"]],
  ["server/src/routes/issue-tree-control.ts", [
    "appendCrelioV6TreeHoldJournal",
    "appendCrelioV6WakeStatusJournal",
  ]],
  ["server/src/services/workspace-operations.ts", ["appendCrelioV6WorkspaceOperationJournal"]],
  ["server/src/routes/execution-workspaces.ts", [
    "appendCrelioV6WorkspaceStatusJournal",
    "assertExactCrelioV6WorkspaceClose",
    'operation: "workspace.close"',
  ]],
  ["server/src/services/board-auth.ts", ["revokeCrelioV6ControllerGrantsForBoardKey"]],
  ["server/src/routes/openapi.ts", ["Read a complete keyset-paged transactional V6 snapshot"]],
]);

function fail(message) {
  process.stderr.write(`Crelio V6 hook-matrix check failed: ${message}\n`);
  process.exitCode = 1;
}

const ancestor = spawnSync("git", ["merge-base", "--is-ancestor", upstream, "HEAD"]);
if (ancestor.status !== 0) fail(`qualified upstream ${upstream} is not an ancestor of HEAD`);

for (const [file, expected] of upstreamFiles) {
  const result = spawnSync("git", ["show", `${upstream}:${file}`]);
  if (result.status !== 0) {
    fail(`qualified upstream file is missing: ${file}`);
    continue;
  }
  const observed = createHash("sha256").update(result.stdout).digest("hex");
  if (observed !== expected) fail(`qualified upstream blob changed for ${file}`);
}

const mutationPattern = /(insert|update)\((agentWakeupRequests|heartbeatRuns|issues|issueTreeHolds|issueComments|workspaceOperations)\)/g;
for (const [file, expected] of mutationCounts) {
  const source = readFileSync(file, "utf8");
  const observed = [...source.matchAll(mutationPattern)].length;
  if (observed !== expected) {
    fail(`${file} has ${observed} watched mutations; matrix expects ${expected}`);
  }
}

for (const [file, markers] of requiredMarkers) {
  const source = readFileSync(file, "utf8");
  for (const marker of markers) {
    if (!source.includes(marker)) fail(`${file} lacks enforcement marker: ${marker}`);
  }
}

const matrix = readFileSync("docs/CRELIO_V6_HOOK_MATRIX.md", "utf8");
for (const row of [
  "API-key prepare/probe/activate/revocation",
  "Wake enqueue/status/cancel",
  "Prepared/active generation switch",
  "Maintenance rollback runtime",
]) {
  if (!matrix.includes(row)) fail(`documentation lacks disposition row: ${row}`);
}
if (!process.exitCode) process.stdout.write("Crelio V6 hook matrix passed\n");
