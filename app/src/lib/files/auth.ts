import { NextRequest } from "next/server";

export function extractOwnerToken(request: NextRequest): string | null {
  const customHeader = request.headers.get("x-owner-token")?.trim();
  if (customHeader) return customHeader;

  const authHeader = request.headers.get("authorization")?.trim();
  if (authHeader && authHeader.toLowerCase().startsWith("bearer ")) {
    return authHeader.slice(7).trim();
  }
  return null;
}
