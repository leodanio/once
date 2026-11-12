import { NextRequest, NextResponse } from "next/server";
import { getActiveFileRepository } from "@/lib/files/service";
import { sha256Digest } from "@/lib/files/crypto";
import { bytesToBase64Url } from "@/lib/secrets/crypto";
import { extractOwnerToken } from "@/lib/files/auth";
import { extractClientIp } from "@/lib/utils/ip";

export async function GET(request: NextRequest) {
  try {
    const ownerToken = extractOwnerToken(request);
    if (!ownerToken) {
      return NextResponse.json({ error: "missing_owner_token" }, { status: 401 });
    }

    const clientIp = extractClientIp(request);
    const repo = getActiveFileRepository();

    const hashBytes = await sha256Digest(new TextEncoder().encode(ownerToken));
    const ownerTokenHash = bytesToBase64Url(hashBytes);

    // Rate limiting: max 40 requests per minute per IP and token
    const [ipLimit, tokenLimit] = await Promise.all([
      repo.checkRateLimit(`file_manage_ip:${clientIp}`, 40, 60),
      repo.checkRateLimit(`file_manage_hash:${ownerTokenHash}`, 40, 60),
    ]);

    if (!ipLimit.allowed || !tokenLimit.allowed) {
      return NextResponse.json(
        { error: "rate_limited", message: "Too many manage requests. Please wait." },
        { status: 429, headers: { "Retry-After": "60" } }
      );
    }

    const req = await repo.getFileRequestByOwnerHash(ownerTokenHash);
    if (!req) {
      return NextResponse.json({ error: "request_not_found" }, { status: 404 });
    }

    const items = await repo.getRequestItems(req.id);

    return NextResponse.json({
      request: {
        id: req.id,
        title: req.title,
        requestToken: req.requestToken,
        maxFiles: req.maxFiles,
        filesCount: req.filesCount,
        maxBytesPerFile: req.maxBytesPerFile,
        status: new Date(req.expiresAt).getTime() <= Date.now() ? "expired" : req.status,
        expiresAt: req.expiresAt,
        createdAt: req.createdAt,
      },
      items: items.map((item) => ({
        id: item.id,
        sizeBytes: item.sizeBytes,
        guestPublicKeySpki: item.guestPublicKeySpki,
        wrappedKeyBundle: typeof item.wrappedKeyBundle === "string" ? JSON.parse(item.wrappedKeyBundle) : item.wrappedKeyBundle,
        encryptedMeta: typeof item.encryptedMeta === "string" ? JSON.parse(item.encryptedMeta) : item.encryptedMeta,
        createdAt: item.createdAt,
      })),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ error: "server_error", message }, { status: 500 });
  }
}
