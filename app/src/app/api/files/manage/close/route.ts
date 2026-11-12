import { NextRequest, NextResponse } from "next/server";
import { getActiveFileRepository } from "@/lib/files/service";
import { sha256Digest } from "@/lib/files/crypto";
import { bytesToBase64Url } from "@/lib/secrets/crypto";
import { extractOwnerToken } from "@/lib/files/auth";
import { extractClientIp } from "@/lib/utils/ip";

export async function POST(request: NextRequest) {
  try {
    const ownerToken = extractOwnerToken(request);
    if (!ownerToken) {
      return NextResponse.json({ error: "missing_owner_token" }, { status: 401 });
    }

    const clientIp = extractClientIp(request);
    const repo = getActiveFileRepository();

    const hashBytes = await sha256Digest(new TextEncoder().encode(ownerToken));
    const ownerTokenHash = bytesToBase64Url(hashBytes);

    // Rate limiting: max 20 close attempts per minute
    const [ipLimit, tokenLimit] = await Promise.all([
      repo.checkRateLimit(`file_close_ip:${clientIp}`, 20, 60),
      repo.checkRateLimit(`file_close_hash:${ownerTokenHash}`, 20, 60),
    ]);

    if (!ipLimit.allowed || !tokenLimit.allowed) {
      return NextResponse.json(
        { error: "rate_limited", message: "Too many requests. Please wait." },
        { status: 429, headers: { "Retry-After": "60" } }
      );
    }

    const result = await repo.closeFileRequest(ownerTokenHash);
    if (!result.ok) {
      return NextResponse.json({ error: result.reason }, { status: 400 });
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ error: "server_error", message }, { status: 500 });
  }
}
