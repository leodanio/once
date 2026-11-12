import { NextRequest, NextResponse } from "next/server";
import { getActiveFileRepository } from "@/lib/files/service";

async function handleCleanup(request: NextRequest) {
  try {
    const cronSecret = process.env.CRON_SECRET?.trim();
    if (!cronSecret) {
      return NextResponse.json(
        { error: "service_unavailable", message: "CRON_SECRET is not configured on server." },
        { status: 503 }
      );
    }

    const authHeader = request.headers.get("authorization");
    if (!authHeader || authHeader !== `Bearer ${cronSecret}`) {
      return NextResponse.json({ error: "unauthorized", message: "Invalid or missing Bearer token." }, { status: 401 });
    }

    const repo = getActiveFileRepository();
    const cleanupStats = await repo.cleanupExpiredFiles();

    // Claim a batch of deletion queue items with a 5-minute lease using SKIP LOCKED
    const claimedBatch = await repo.claimDeletionQueueBatch(50, 5);
    let successfullyDeletedCount = 0;
    let failedCount = 0;

    if (claimedBatch.length > 0) {
      for (const item of claimedBatch) {
        try {
          await repo.deleteStorageObjects([item.storagePath]);
          await repo.finalizeDeletionQueueSuccess([item.id]);
          successfullyDeletedCount++;
        } catch (delError) {
          const errMsg = delError instanceof Error ? delError.message : String(delError);
          await repo.recordDeletionQueueFailure(item.id, errMsg);
          failedCount++;
        }
      }
    }

    return NextResponse.json({
      success: true,
      stats: cleanupStats,
      storageDeletion: {
        claimed: claimedBatch.length,
        deleted: successfullyDeletedCount,
        failed: failedCount,
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ error: "server_error", message }, { status: 500 });
  }
}

export async function GET(request: NextRequest) {
  return handleCleanup(request);
}

export async function POST(request: NextRequest) {
  return handleCleanup(request);
}
