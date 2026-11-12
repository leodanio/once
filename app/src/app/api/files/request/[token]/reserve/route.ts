import { NextRequest, NextResponse } from "next/server";
import { getActiveFileRepository } from "@/lib/files/service";
import { extractClientIp } from "@/lib/utils/ip";
import { generateRandomSlug } from "@/lib/utils/url";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ token: string }> }
) {
  try {
    const { token } = await params;
    if (!token) {
      return NextResponse.json({ error: "missing_token" }, { status: 400 });
    }

    const clientIp = extractClientIp(request);
    const repo = getActiveFileRepository();

    // Rate limit: max 10 reserve calls per minute per IP, 20 per token
    const [ipLimit, tokLimit] = await Promise.all([
      repo.checkRateLimit(`file_req_reserve_ip:${clientIp}`, 10, 60),
      repo.checkRateLimit(`file_req_reserve_tok:${token}`, 20, 60),
    ]);
    if (!ipLimit.allowed || !tokLimit.allowed) {
      return NextResponse.json(
        { error: "rate_limited", message: "Too many upload attempts. Please wait." },
        { status: 429, headers: { "Retry-After": "60" } }
      );
    }

    const body = await request.json().catch(() => null);
    if (!body || typeof body !== "object") {
      return NextResponse.json({ error: "invalid_json" }, { status: 400 });
    }

    const sizeBytes = Number(body.sizeBytes);
    if (isNaN(sizeBytes) || sizeBytes <= 0) {
      return NextResponse.json({ error: "invalid_size" }, { status: 400 });
    }

    const itemToken = generateRandomSlug(24);
    const storagePath = `requests/${token}/${itemToken}.enc`;

    const reserveRes = await repo.reserveRequestItem(token, storagePath, sizeBytes);
    if (!reserveRes.ok) {
      const statusMap: Record<string, number> = {
        request_not_found: 404,
        request_not_active: 400,
        request_expired: 410,
        request_max_files_reached: 409,
        file_too_large: 400,
      };
      const status = statusMap[reserveRes.reason] ?? 400;
      return NextResponse.json({ error: reserveRes.reason }, { status });
    }

    const signedUploadUrl = await repo.createSignedUploadUrl(storagePath);

    return NextResponse.json(
      {
        slotId: reserveRes.itemId,
        storagePath,
        signedUploadUrl,
      },
      { status: 201 }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ error: "server_error", message }, { status: 500 });
  }
}
