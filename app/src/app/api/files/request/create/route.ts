import { NextRequest, NextResponse } from "next/server";
import {
  computeFileExpirationDate,
  FILE_UPLOAD_MAX_BYTES,
  getActiveFileRepository,
} from "@/lib/files/service";
import { extractClientIp } from "@/lib/utils/ip";
import { generateRandomSlug } from "@/lib/utils/url";
import { sha256Digest } from "@/lib/files/crypto";
import { bytesToBase64Url } from "@/lib/secrets/crypto";
import type { FileExpirationPreset } from "@/types/files";

const FORBIDDEN_FIELDS = ["privateKey", "creatorPrivateKey", "key", "password"];

export async function POST(request: NextRequest) {
  try {
    const clientIp = extractClientIp(request);
    const repo = getActiveFileRepository();

    // Rate limit: max 10 requests created per minute per IP
    const rl = await repo.checkRateLimit(`file_req_create_ip:${clientIp}`, 10, 60);
    if (!rl.allowed) {
      return NextResponse.json(
        { error: "rate_limited", message: "Too many file requests created. Please wait." },
        { status: 429, headers: { "Retry-After": "60" } }
      );
    }

    const body = await request.json().catch(() => null);
    if (!body || typeof body !== "object") {
      return NextResponse.json({ error: "invalid_json" }, { status: 400 });
    }

    for (const field of FORBIDDEN_FIELDS) {
      if (field in body) {
        return NextResponse.json(
          { error: "security_violation", message: `Forbidden parameter '${field}' sent to server.` },
          { status: 400 }
        );
      }
    }

    const { title, creatorPublicKeySpki, maxFiles, maxBytesPerFile, expiration } = body;

    if (!title || typeof title !== "string") {
      return NextResponse.json({ error: "missing_title" }, { status: 400 });
    }

    if (!creatorPublicKeySpki || typeof creatorPublicKeySpki !== "string") {
      return NextResponse.json({ error: "missing_creator_public_key" }, { status: 400 });
    }

    const filesLimit = Math.max(1, Math.min(Number(maxFiles) || 5, 50));
    const bytesLimit = Math.min(
      Math.max(1024 * 1024, Number(maxBytesPerFile) || FILE_UPLOAD_MAX_BYTES),
      FILE_UPLOAD_MAX_BYTES
    );

    const validPresets: FileExpirationPreset[] = ["10m", "1h", "24h", "7d"];
    const expPreset: FileExpirationPreset = validPresets.includes(expiration) ? expiration : "7d";
    const expiresAt = computeFileExpirationDate(expPreset);

    const requestToken = generateRandomSlug(24);
    const ownerToken = generateRandomSlug(32);

    // Hash ownerToken with SHA-256
    const ownerHashBytes = await sha256Digest(new TextEncoder().encode(ownerToken));
    const ownerTokenHash = bytesToBase64Url(ownerHashBytes);

    const result = await repo.createFileRequest({
      requestToken,
      ownerTokenHash,
      title: title.slice(0, 100),
      creatorPublicKeySpki,
      maxFiles: filesLimit,
      maxBytesPerFile: bytesLimit,
      expiresAt,
    });

    if (!result.ok) {
      return NextResponse.json({ error: result.reason }, { status: 500 });
    }

    return NextResponse.json(
      {
        requestToken,
        ownerToken,
        expiresAt,
      },
      { status: 201 }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ error: "server_error", message }, { status: 500 });
  }
}
