import { NextRequest, NextResponse } from "next/server";
import { getActiveFileRepository } from "@/lib/files/service";
import { extractClientIp } from "@/lib/utils/ip";

export async function GET(
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

    const [ipLimit, tokenLimit] = await Promise.all([
      repo.checkRateLimit(`file_req_get_ip:${clientIp}`, 60, 60),
      repo.checkRateLimit(`file_req_get_tok:${token}`, 60, 60),
    ]);

    if (!ipLimit.allowed || !tokenLimit.allowed) {
      return NextResponse.json(
        { error: "rate_limited", message: "Too many requests. Please wait." },
        { status: 429, headers: { "Retry-After": "60" } }
      );
    }
    const req = await repo.getFileRequestByToken(token);

    if (!req) {
      return NextResponse.json({ error: "request_not_found" }, { status: 404 });
    }

    const isExpired = new Date(req.expiresAt).getTime() <= Date.now();
    const effectiveStatus = isExpired ? "expired" : req.status;

    return NextResponse.json({
      title: req.title,
      creatorPublicKeySpki: req.creatorPublicKeySpki,
      maxFiles: req.maxFiles,
      filesCount: req.filesCount,
      maxBytesPerFile: req.maxBytesPerFile,
      status: effectiveStatus,
      expiresAt: req.expiresAt,
      createdAt: req.createdAt,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ error: "server_error", message }, { status: 500 });
  }
}
