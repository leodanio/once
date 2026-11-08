import { headers } from "next/headers";
import { notFound, redirect } from "next/navigation";
import { consumeOnceLink } from "@/lib/links/service";
import { ExpiredLinkView } from "@/components/links/ExpiredLinkView";
import {
  isPrefetchOrPreviewBotRequest,
  isPreviewBotUserAgent,
} from "@/lib/utils/bot-detection";

export const dynamic = "force-dynamic";
export const revalidate = 0;

interface SlugPageProps {
  params: Promise<{ slug: string }>;
}

export default async function SlugRedirectPage({ params }: SlugPageProps) {
  const { slug } = await params;
  const headersList = await headers();

  // 1. Never consume single-use links on browser/router prefetch requests
  const userAgent = headersList.get("user-agent");
  if (isPrefetchOrPreviewBotRequest(headersList)) {
    // If request comes from a social/chat preview crawler (WhatsApp, Telegram, Slack, etc.),
    // return a lightweight metadata response WITHOUT consuming the link.
    if (isPreviewBotUserAgent(userAgent)) {
      return (
        <div className="min-h-dvh flex items-center justify-center p-6 bg-background text-foreground text-center">
          <div className="max-w-md space-y-2">
            <p className="text-xs uppercase tracking-widest font-mono text-foreground-muted">
              ONCE
            </p>
            <h1 className="text-lg font-medium tracking-tight">Link temporaneo</h1>
            <p className="text-sm text-foreground-muted">
              Questo link ad accesso limitato si aprirà alla visita diretta nel browser.
            </p>
          </div>
        </div>
      );
    }

    return null;
  }

  // 2. Real human visit: atomically consume one view and immediately redirect
  const result = await consumeOnceLink(slug);

  if (result.status === "not_found") {
    notFound();
  }

  if (result.status === "valid" && result.destinationUrl) {
    redirect(result.destinationUrl);
  }

  // Status is "expired" or "max_views_reached"
  return <ExpiredLinkView customMessage={result.customMessage} />;
}
