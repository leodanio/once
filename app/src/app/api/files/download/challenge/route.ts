import { NextRequest, NextResponse } from "next/server";
import { getActiveFileRepository } from "@/lib/files/service";
import { extractClientIp } from "@/lib/utils/ip";
import { isPrefetchOrPreviewBotRequest } from "@/lib/utils/bot-detection";

export async function POST(request: NextRequest) {
  try {
    // Block bots and prefetchers from requesting challenges
    if (isPrefetchOrPreviewBotRequest(request.headers)) {
      return NextResponse.json(
        { error: "preview_bot_blocked", message: "Preview bots cannot request download challenges." },
        { status: 403 }
      );
    }

    const clientIp = extractClientIp(request);
    const repo = getActiveFileRepository();

    const body = await request.json().catch(() => null);
    if (!body || typeof body !== "object") {
      return NextResponse.json({ error: "invalid_json" }, { status: 400 });
    }

    const { transferToken } = body;
    if (!transferToken || typeof transferToken !== "string") {
      return NextResponse.json({ error: "missing_transfer_token" }, { status: 400 });
    }

    // Rate limiting: 10/min per IP, 15/min per token
    const [ipLimit, tokenLimit] = await Promise.all([
      repo.checkRateLimit(`file_chal_ip:${clientIp}`, 10, 60),
      repo.checkRateLimit(`file_chal_tok:${transferToken}`, 15, 60),
    ]);

    if (!ipLimit.allowed || !tokenLimit.allowed) {
      return NextResponse.json(
        { error: "rate_limited", message: "Too many download challenge requests. Please wait." },
        { status: 429, headers: { "Retry-After": "60" } }
      );
    }

    const challengeRes = await repo.generateDownloadChallenge(transferToken, clientIp);
    if (!challengeRes.ok) {
      const statusMap: Record<string, number> = {
        file_not_found: 404,
        file_not_ready: 400,
        file_expired: 410,
        max_downloads_reached: 410,
        too_many_pending_ip_challenges: 429,
        too_many_concurrent_challenges: 429,
      };
      const status = statusMap[challengeRes.reason] ?? 400;
      return NextResponse.json({ error: challengeRes.reason }, { status });
    }

    // Also fetch the encrypted metadata to display file info to the user
    const file = await repo.getTransferByToken(transferToken);

    return NextResponse.json({
      challengeId: challengeRes.challengeId,
      challengeNonce: challengeRes.challengeNonce,
      fileId: challengeRes.fileId,
      popPublicKeySpki: challengeRes.popPublicKeySpki,
      encryptedMeta: file?.encryptedMeta ? JSON.parse(file.encryptedMeta) : null,
      maxDownloads: file?.maxDownloads,
      downloadCount: file?.downloadCount,
      expiresAt: file?.expiresAt,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ error: "server_error", message }, { status: 500 });
  }
}
