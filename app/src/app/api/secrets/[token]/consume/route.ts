import { NextResponse, type NextRequest } from "next/server";
import {
  consumeEncryptedSecret,
  isPrefetchOrPreviewBotRequest,
} from "@/lib/secrets/service";
import { extractClientIp } from "@/lib/utils/ip";

export const dynamic = "force-dynamic";

const NO_STORE_HEADERS = {
  "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
  Pragma: "no-cache",
};

interface RouteContext {
  params: Promise<{ token: string }>;
}

export async function POST(request: NextRequest, context: RouteContext) {
  // 1. Refuse prefetch or automated link-preview bot requests without consuming
  if (isPrefetchOrPreviewBotRequest(request.headers)) {
    return NextResponse.json(
      { errorCode: "prefetch_blocked" },
      { status: 400, headers: NO_STORE_HEADERS }
    );
  }

  // 2. Require explicit user-initiated consumption intent header
  if (request.headers.get("x-once-consume-intent") !== "1") {
    return NextResponse.json(
      { errorCode: "missing_consume_intent" },
      { status: 400, headers: NO_STORE_HEADERS }
    );
  }

  const { token } = await context.params;
  const clientIp = extractClientIp(request);

  const outcome = await consumeEncryptedSecret(token, { clientIp });

  if (!outcome.ok) {
    const headers: Record<string, string> = { ...NO_STORE_HEADERS };
    if (outcome.status === 429 && outcome.resetAt) {
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil((Date.parse(outcome.resetAt) - Date.now()) / 1000)
      );
      headers["Retry-After"] = String(retryAfterSeconds);
    }

    return NextResponse.json(
      { errorCode: outcome.errorCode, resetAt: outcome.resetAt },
      { status: outcome.status, headers }
    );
  }

  const { result } = outcome;
  const httpStatus =
    result.status === "valid"
      ? 200
      : result.status === "not_found"
        ? 404
        : 410;

  return NextResponse.json(
    { result },
    { status: httpStatus, headers: NO_STORE_HEADERS }
  );
}
