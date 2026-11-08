/**
 * ONCE — Crawler and Prefetch Detection Utility
 *
 * Detects automated link-preview crawlers (e.g. WhatsApp, Telegram, Slack, Discord)
 * and browser/framework speculative prefetch requests so that single-use links
 * and secrets are never consumed prematurely by bots.
 */

export const PREVIEW_BOT_USER_AGENT_REGEX =
  /bot|crawler|spider|slackbot|whatsapp|telegrambot|twitterbot|facebookexternalhit|facebot|discordbot|linkedinbot|skypeuripreview|iframely|embedly|pinterest|vkshare|applebot|google-structured-data-testing-tool|google-inspectiontool|bingbot|yandexbot|duckduckbot|baiduspider/i;

/**
 * Checks if the User-Agent belongs to a known link preview bot or search crawler.
 */
export function isPreviewBotUserAgent(userAgent: string | null | undefined): boolean {
  if (!userAgent || typeof userAgent !== "string") return false;
  return PREVIEW_BOT_USER_AGENT_REGEX.test(userAgent);
}

/**
 * Checks if incoming request headers indicate a browser prefetch or crawler bot.
 */
export function isPrefetchOrPreviewBotRequest(headersList: Headers): boolean {
  const purpose = headersList.get("purpose")?.toLowerCase() ?? "";
  const secPurpose = headersList.get("sec-purpose")?.toLowerCase() ?? "";
  const nextRouterPrefetch = headersList.get("next-router-prefetch");
  const moz = headersList.get("x-moz")?.toLowerCase() ?? "";
  const userAgent = headersList.get("user-agent") ?? "";

  // Browser / CDN speculative prefetching
  if (
    purpose.includes("prefetch") ||
    purpose.includes("preview") ||
    secPurpose.includes("prefetch") ||
    secPurpose.includes("preview") ||
    nextRouterPrefetch === "1" ||
    moz.includes("prefetch")
  ) {
    return true;
  }

  // Social / chat application link-preview crawlers
  if (isPreviewBotUserAgent(userAgent)) {
    return true;
  }

  return false;
}
