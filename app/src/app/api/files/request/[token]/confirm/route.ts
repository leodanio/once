import { NextRequest, NextResponse } from "next/server";
import { getActiveFileRepository } from "@/lib/files/service";
import { extractClientIp } from "@/lib/utils/ip";

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

    // Rate limiting: max 30 confirm calls per minute per IP and token
    const [ipLimit, tokLimit] = await Promise.all([
      repo.checkRateLimit(`file_req_confirm_ip:${clientIp}`, 30, 60),
      repo.checkRateLimit(`file_req_confirm_tok:${token}`, 30, 60),
    ]);

    if (!ipLimit.allowed || !tokLimit.allowed) {
      return NextResponse.json(
        { error: "rate_limited", message: "Too many confirmation attempts. Please wait." },
        { status: 429, headers: { "Retry-After": "60" } }
      );
    }

    const body = await request.json().catch(() => null);
    if (!body || typeof body !== "object") {
      return NextResponse.json({ error: "invalid_json" }, { status: 400 });
    }

    const { slotId, guestPublicKeySpki, wrappedKeyBundle, encryptedMeta } = body;

    if (!slotId || !guestPublicKeySpki || !wrappedKeyBundle || !encryptedMeta) {
      return NextResponse.json({ error: "missing_parameters" }, { status: 400 });
    }

    const confirmRes = await repo.confirmRequestItem(
      slotId,
      guestPublicKeySpki,
      wrappedKeyBundle,
      encryptedMeta
    );

    if (!confirmRes.ok) {
      return NextResponse.json({ error: confirmRes.reason }, { status: 400 });
    }

    return NextResponse.json({ success: true }, { status: 200 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ error: "server_error", message }, { status: 500 });
  }
}
