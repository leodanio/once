import { NextRequest, NextResponse } from "next/server";
import {
  computeFileExpirationDate,
  FILE_UPLOAD_MAX_BYTES,
  getActiveFileRepository,
} from "@/lib/files/service";
import { extractClientIp } from "@/lib/utils/ip";
import { generateRandomSlug } from "@/lib/utils/url";
import type { FileExpirationPreset } from "@/types/files";

const FORBIDDEN_FIELDS = [
  "fileKey",
  "key",
  "plaintext",
  "password",
  "popPrivateKey",
  "privateKey",
];

export async function POST(request: NextRequest) {
  try {
    const clientIp = extractClientIp(request);
    const repo = getActiveFileRepository();

    // Rate limit: max 10 transfer creations per minute per IP
    const rl = await repo.checkRateLimit(`file_create_ip:${clientIp}`, 10, 60);
    if (!rl.allowed) {
      return NextResponse.json(
        { error: "rate_limited", message: "Too many file transfers created recently. Please wait." },
        { status: 429, headers: { "Retry-After": "60" } }
      );
    }

    const body = await request.json().catch(() => null);
    if (!body || typeof body !== "object") {
      return NextResponse.json({ error: "invalid_json" }, { status: 400 });
    }

    // Security check: ensure no raw secrets were sent
    for (const field of FORBIDDEN_FIELDS) {
      if (field in body) {
        return NextResponse.json(
          { error: "security_violation", message: `Forbidden parameter '${field}' sent to server.` },
          { status: 400 }
        );
      }
    }

    const { popPublicKeySpki, encryptedMeta, sizeBytes, maxDownloads, expiration } = body;

    if (!popPublicKeySpki || typeof popPublicKeySpki !== "string") {
      return NextResponse.json({ error: "missing_pop_public_key" }, { status: 400 });
    }

    if (!encryptedMeta || typeof encryptedMeta !== "object") {
      return NextResponse.json({ error: "missing_encrypted_meta" }, { status: 400 });
    }

    const size = Number(sizeBytes);
    if (isNaN(size) || size <= 0 || size > FILE_UPLOAD_MAX_BYTES) {
      return NextResponse.json(
        { error: "invalid_file_size", message: `File size must be between 1 and ${FILE_UPLOAD_MAX_BYTES} bytes.` },
        { status: 400 }
      );
    }

    const downloads = Math.max(1, Math.min(Number(maxDownloads) || 1, 100));
    const validPresets: FileExpirationPreset[] = ["10m", "1h", "24h", "7d"];
    const expPreset: FileExpirationPreset = validPresets.includes(expiration) ? expiration : "24h";
    const expiresAt = computeFileExpirationDate(expPreset);

    // Generate random 24-character token
    const transferToken = generateRandomSlug(24);
    const storagePath = `transfers/${transferToken}.enc`;

    const signedUploadUrl = await repo.createSignedUploadUrl(storagePath);

    const result = await repo.createTransfer({
      transferToken,
      storagePath,
      encryptedMeta,
      popPublicKeySpki,
      maxDownloads: downloads,
      expiresAt,
    });

    if (!result.ok) {
      return NextResponse.json({ error: result.reason }, { status: 500 });
    }

    return NextResponse.json(
      {
        transferToken,
        signedUploadUrl,
        storagePath,
        expiresAt,
      },
      { status: 201 }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ error: "server_error", message }, { status: 500 });
  }
}
