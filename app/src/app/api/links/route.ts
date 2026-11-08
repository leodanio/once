import { NextResponse, type NextRequest } from "next/server";
import { createOnceLink } from "@/lib/links/service";
import { extractClientIp } from "@/lib/utils/ip";
import type { CreateLinkRequest } from "@/types/link";

export const dynamic = "force-dynamic";

function resolveAppBaseUrl(request: NextRequest): string {
  const configured = process.env.NEXT_PUBLIC_APP_URL?.trim();
  if (configured) {
    return configured.replace(/\/+$/, "");
  }

  try {
    const reqUrl = new URL(request.url);
    return reqUrl.origin;
  } catch {
    return "http://localhost:3000";
  }
}

export async function POST(request: NextRequest) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { errorCode: "invalid_url" },
      {
        status: 400,
        headers: { "Cache-Control": "no-store, max-age=0" },
      }
    );
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return NextResponse.json(
      { errorCode: "invalid_url" },
      {
        status: 400,
        headers: { "Cache-Control": "no-store, max-age=0" },
      }
    );
  }

  const record = body as Record<string, unknown>;
  const payload: CreateLinkRequest = {
    destinationUrl:
      typeof record.destinationUrl === "string" ? record.destinationUrl : "",
    customSlug:
      typeof record.customSlug === "string" ? record.customSlug : undefined,
    expiration:
      typeof record.expiration === "string"
        ? (record.expiration as CreateLinkRequest["expiration"])
        : undefined,
    maxViews:
      typeof record.maxViews === "number" ? record.maxViews : undefined,
    expiredMessage:
      typeof record.expiredMessage === "string"
        ? record.expiredMessage
        : undefined,
  };

  const clientIp = extractClientIp(request);
  const appBaseUrl = resolveAppBaseUrl(request);

  const result = await createOnceLink(payload, {
    clientIp,
    appBaseUrl,
  });

  if (!result.ok) {
    const headers: Record<string, string> = {
      "Cache-Control": "no-store, max-age=0",
    };

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
      {
        status: result.status,
        headers,
      }
    );
  }

  return NextResponse.json(
    { link: result.link },
    {
      status: 201,
      headers: {
        "Cache-Control": "no-store, max-age=0",
      },
    }
  );
}
