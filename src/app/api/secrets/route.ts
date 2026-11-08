import { NextResponse, type NextRequest } from "next/server";
import {
  createEncryptedSecret,
  hasForbiddenSecretFields,
} from "@/lib/secrets/service";
import { extractClientIp } from "@/lib/utils/ip";
import type { CreateSecretRequest } from "@/types/secret";

export const dynamic = "force-dynamic";

const NO_STORE_HEADERS = {
  "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
  Pragma: "no-cache",
};

export async function POST(request: NextRequest) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { errorCode: "invalid_payload" },
      { status: 400, headers: NO_STORE_HEADERS }
    );
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return NextResponse.json(
      { errorCode: "invalid_payload" },
      { status: 400, headers: NO_STORE_HEADERS }
    );
  }

  const record = body as Record<string, unknown>;

  // Security guard: immediately reject any request attempting to send plaintext, keys, or passwords
  if (hasForbiddenSecretFields(record)) {
    return NextResponse.json(
      { errorCode: "forbidden_plaintext_or_key_field" },
      { status: 400, headers: NO_STORE_HEADERS }
    );
  }

  const payload: CreateSecretRequest = {
    ciphertext: typeof record.ciphertext === "string" ? record.ciphertext : "",
    iv: typeof record.iv === "string" ? record.iv : "",
    passwordProtected:
      typeof record.passwordProtected === "boolean"
        ? record.passwordProtected
        : (undefined as unknown as boolean),
    kdfSalt:
      record.kdfSalt === null || typeof record.kdfSalt === "string"
        ? record.kdfSalt
        : undefined,
    kdfIterations:
      record.kdfIterations === null || typeof record.kdfIterations === "number"
        ? record.kdfIterations
        : undefined,
    expiration:
      typeof record.expiration === "string"
        ? (record.expiration as CreateSecretRequest["expiration"])
        : undefined,
  };

  const clientIp = extractClientIp(request);
  const result = await createEncryptedSecret(payload, { clientIp });

  if (!result.ok) {
    const headers: Record<string, string> = { ...NO_STORE_HEADERS };
    if (result.status === 429 && result.resetAt) {
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil((Date.parse(result.resetAt) - Date.now()) / 1000)
      );
      headers["Retry-After"] = String(retryAfterSeconds);
    }

    return NextResponse.json(
      {
        errorCode: result.errorCode,
        resetAt: result.resetAt,
      },
      { status: result.status, headers }
    );
  }

  return NextResponse.json(
    { secret: result.secret },
    { status: 201, headers: NO_STORE_HEADERS }
  );
}
