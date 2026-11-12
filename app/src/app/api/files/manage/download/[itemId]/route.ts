import { NextRequest, NextResponse } from "next/server";
import { getActiveFileRepository } from "@/lib/files/service";
import { sha256Digest } from "@/lib/files/crypto";
import { bytesToBase64Url } from "@/lib/secrets/crypto";
import { extractOwnerToken } from "@/lib/files/auth";
import { extractClientIp } from "@/lib/utils/ip";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ itemId: string }> }
) {
  try {
    const ownerToken = extractOwnerToken(request);
    if (!ownerToken) {
      return NextResponse.json({ error: "missing_owner_token" }, { status: 401 });
    }

    const { itemId } = await params;
    if (!itemId) {
      return NextResponse.json({ error: "missing_item_id" }, { status: 400 });
    }

    const clientIp = extractClientIp(request);
    const repo = getActiveFileRepository();

    const hashBytes = await sha256Digest(new TextEncoder().encode(ownerToken));
    const ownerTokenHash = bytesToBase64Url(hashBytes);

    // Rate limiting: max 30 download link requests per minute
    const [ipLimit, tokenLimit] = await Promise.all([
      repo.checkRateLimit(`file_managedown_ip:${clientIp}`, 30, 60),
      repo.checkRateLimit(`file_managedown_hash:${ownerTokenHash}`, 30, 60),
    ]);

    if (!ipLimit.allowed || !tokenLimit.allowed) {
      return NextResponse.json(
        { error: "rate_limited", message: "Too many download attempts. Please wait." },
        { status: 429, headers: { "Retry-After": "60" } }
      );
    }

    const req = await repo.getFileRequestByOwnerHash(ownerTokenHash);
    if (!req) {
      return NextResponse.json({ error: "request_not_found" }, { status: 404 });
    }

    const item = await repo.getRequestItemById(itemId);
    if (!item || item.requestId !== req.id || item.status !== "ready") {
      return NextResponse.json({ error: "item_not_found" }, { status: 404 });
    }

    const downloadUrl = await repo.createSignedDownloadUrl(item.storagePath, 60);

    return NextResponse.json({ downloadUrl });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ error: "server_error", message }, { status: 500 });
  }
}
