import { NextResponse, type NextRequest } from "next/server";
import { checkSecretMetadata } from "@/lib/secrets/service";
import { extractClientIp } from "@/lib/utils/ip";

export const dynamic = "force-dynamic";

const NO_STORE_HEADERS = {
  "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
  Pragma: "no-cache",
};

interface RouteContext {
  params: Promise<{ token: string }>;
}

export async function GET(request: NextRequest, context: RouteContext) {
  const { token } = await context.params;
  const clientIp = extractClientIp(request);

  const result = await checkSecretMetadata(token, { clientIp });

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
      { errorCode: result.errorCode, resetAt: result.resetAt },
      { status: result.status, headers }
    );
  }

  return NextResponse.json(
    { metadata: result.metadata },
    { status: 200, headers: NO_STORE_HEADERS }
  );
}
