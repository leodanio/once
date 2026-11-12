import { NextRequest, NextResponse } from "next/server";
import { getActiveFileRepository } from "@/lib/files/service";
import { importPopPublicKeySpki, verifyDownloadChallenge } from "@/lib/files/crypto";
import { isPrefetchOrPreviewBotRequest } from "@/lib/utils/bot-detection";
import { extractClientIp } from "@/lib/utils/ip";

export async function POST(request: NextRequest) {
  try {
    if (isPrefetchOrPreviewBotRequest(request.headers)) {
      return NextResponse.json(
        { error: "preview_bot_blocked", message: "Preview bots cannot consume downloads." },
        { status: 403 }
      );
    }

    const clientIp = extractClientIp(request);
    const body = await request.json().catch(() => null);
    if (!body || typeof body !== "object") {
      return NextResponse.json({ error: "invalid_json" }, { status: 400 });
    }

    const { transferToken, challengeId, signatureB64Url } = body;
    if (!transferToken || !challengeId || !signatureB64Url) {
      return NextResponse.json({ error: "missing_parameters" }, { status: 400 });
    }

    const repo = getActiveFileRepository();

    const [ipLimit, tokenLimit] = await Promise.all([
      repo.checkRateLimit(`file_consume_ip:${clientIp}`, 10, 60),
      repo.checkRateLimit(`file_consume_tok:${transferToken}`, 15, 60),
    ]);

    if (!ipLimit.allowed || !tokenLimit.allowed) {
      return NextResponse.json(
        { error: "rate_limited", message: "Too many download consume requests. Please wait." },
        { status: 429, headers: { "Retry-After": "60" } }
      );
    }

    // 1. Fetch file
    const file = await repo.getTransferByToken(transferToken);
    if (!file) {
      return NextResponse.json({ error: "file_not_found" }, { status: 404 });
    }

    if (file.status === "completed" || file.downloadCount >= file.maxDownloads) {
      return NextResponse.json({ error: "max_downloads_reached" }, { status: 410 });
    }

    if (file.status !== "ready") {
      return NextResponse.json({ error: "file_not_ready" }, { status: 400 });
    }

    if (new Date(file.expiresAt).getTime() <= Date.now()) {
      return NextResponse.json({ error: "file_expired" }, { status: 410 });
    }

    if (file.downloadCount >= file.maxDownloads) {
      return NextResponse.json({ error: "max_downloads_reached" }, { status: 410 });
    }

    // 2. Fetch challenge
    const chal = await repo.getChallengeById(challengeId);
    if (!chal || chal.fileId !== file.id) {
      return NextResponse.json({ error: "challenge_not_found" }, { status: 404 });
    }

    if (chal.status !== "pending") {
      return NextResponse.json({ error: "challenge_already_consumed" }, { status: 409 });
    }

    if (new Date(chal.expiresAt).getTime() <= Date.now()) {
      return NextResponse.json({ error: "challenge_expired" }, { status: 410 });
    }

    // 3. Cryptographic Verification: ECDSA P-256 Proof of Possession
    const publicKey = await importPopPublicKeySpki(file.popPublicKeySpki);
    const isSignatureValid = await verifyDownloadChallenge(
      publicKey,
      file.id,
      chal.id,
      chal.challengeNonce,
      signatureB64Url
    );

    if (!isSignatureValid) {
      return NextResponse.json(
        { error: "invalid_pop_signature", message: "Proof of Possession signature verification failed." },
        { status: 401 }
      );
    }

    // 4. Generate 60-second Signed Download URL
    const signedUrl = await repo.createSignedDownloadUrl(file.storagePath, 60);

    // 5. Invocate atomic database consumption RPC
    const consumeRes = await repo.consumeDownload(file.id, chal.id, 10);
    if (!consumeRes.ok) {
      // Discard signed URL and return error
      return NextResponse.json({ error: consumeRes.reason }, { status: 409 });
    }

    // 6. Return authorized signed download URL
    return NextResponse.json({
      success: true,
      downloadUrl: signedUrl,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ error: "server_error", message }, { status: 500 });
  }
}
