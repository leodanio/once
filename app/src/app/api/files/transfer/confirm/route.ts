import { NextRequest, NextResponse } from "next/server";
import { getActiveFileRepository } from "@/lib/files/service";
import { extractClientIp } from "@/lib/utils/ip";

export async function POST(request: NextRequest) {
  try {
    const clientIp = extractClientIp(request);
    const repo = getActiveFileRepository();

    // Rate limit: max 30 confirmations per minute per IP
    const rl = await repo.checkRateLimit(`file_confirm_ip:${clientIp}`, 30, 60);
    if (!rl.allowed) {
      return NextResponse.json(
        { error: "rate_limited", message: "Too many confirmation attempts. Please wait." },
        { status: 429, headers: { "Retry-After": "60" } }
      );
    }

    const body = await request.json().catch(() => null);
    if (!body || typeof body !== "object") {
      return NextResponse.json({ error: "invalid_json" }, { status: 400 });
    }

    const { transferToken } = body;
    if (!transferToken || typeof transferToken !== "string") {
      return NextResponse.json({ error: "missing_transfer_token" }, { status: 400 });
    }

    const result = await repo.confirmTransfer(transferToken);
    if (!result.ok) {
      if (result.reason === "file_not_found") {
        return NextResponse.json({ error: "file_not_found" }, { status: 404 });
      }
      if (result.reason === "invalid_file_status") {
        return NextResponse.json({ error: "invalid_file_status" }, { status: 400 });
      }
      if (result.reason === "file_expired") {
        return NextResponse.json({ error: "file_expired" }, { status: 410 });
      }
      return NextResponse.json({ error: result.reason }, { status: 500 });
    }

    return NextResponse.json({ ok: true, status: "ready" });
  } catch (error) {
    console.error("Error confirming file transfer upload:", error);
    return NextResponse.json({ error: "internal_server_error" }, { status: 500 });
  }
}
