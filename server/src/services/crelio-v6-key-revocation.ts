import { randomUUID } from "node:crypto";
import { and, eq, isNull, sql } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import {
  crelioV6ControllerGrants,
  crelioV6JournalEvents,
  crelioV6JournalHeads,
} from "@paperclipai/db";

type DbLike = Parameters<Parameters<Db["transaction"]>[0]>[0];

/**
 * Revoke all V6 capability grants attached to a stock board key and journal the
 * denial in the very same transaction as the board-key revocation.  Keeping
 * this hook independent of heartbeat/crelio-v6 avoids an authentication-service
 * import cycle and makes it impossible for a stock revocation route to bypass it.
 */
export async function revokeCrelioV6ControllerGrantsForBoardKey(
  tx: DbLike,
  boardApiKeyId: string,
  revokedAt: Date,
) {
  const grants = await tx
    .select()
    .from(crelioV6ControllerGrants)
    .where(and(
      eq(crelioV6ControllerGrants.boardApiKeyId, boardApiKeyId),
      isNull(crelioV6ControllerGrants.revokedAt),
    ));

  for (const grant of grants) {
    await tx
      .update(crelioV6ControllerGrants)
      .set({ revokedAt })
      .where(and(
        eq(crelioV6ControllerGrants.id, grant.id),
        isNull(crelioV6ControllerGrants.revokedAt),
      ));
    const head = await tx
      .update(crelioV6JournalHeads)
      .set({
        lastCommittedSequence: sql`${crelioV6JournalHeads.lastCommittedSequence} + 1`,
        optimisticVersion: sql`${crelioV6JournalHeads.optimisticVersion} + 1`,
        updatedAt: revokedAt,
      })
      .where(eq(crelioV6JournalHeads.projectId, grant.projectId))
      .returning({ sequence: crelioV6JournalHeads.lastCommittedSequence })
      .then((rows) => rows[0] ?? null);
    if (!head) {
      throw new Error("V6 controller grant has no project journal head");
    }
    await tx.insert(crelioV6JournalEvents).values({
      projectId: grant.projectId,
      sequence: head.sequence,
      generation: grant.generation,
      entityKind: "controller_key",
      entityId: boardApiKeyId,
      entityVersion: grant.rotationGeneration,
      mutationKind: "controller_key.revoked_external",
      reductionPayload: {
        boardApiKeyId,
        controllerUserId: grant.boardUserId,
        grantId: grant.id,
        reason: "stock_board_key_revocation",
      },
      sourceTransactionId: randomUUID(),
    });
  }
  return grants.length;
}
