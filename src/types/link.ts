export type ExpirationPreset = "never" | "15m" | "1h" | "24h" | "7d";

export interface AdvancedLinkOptions {
  customSlug: string;
  expiration: ExpirationPreset;
  maxViews: number;
  expiredMessage: string;
}

export interface CreateLinkRequest {
  destinationUrl: string;
  customSlug?: string;
  expiration?: ExpirationPreset;
  maxViews?: number;
  expiredMessage?: string;
}

export interface GeneratedLink {
  id: string;
  slug: string;
  shortUrl: string;
  destinationUrl: string;
  maxViews: number;
  viewsCount: number;
  remainingViews: number;
  expiration: ExpirationPreset;
  expiresAt: string | null;
  expiredMessage: string | null;
  createdAt: string;
}

export type ConsumeLinkStatus =
  | "valid"
  | "expired"
  | "max_views_reached"
  | "not_found";

export interface ConsumeLinkResult {
  status: ConsumeLinkStatus;
  destinationUrl: string | null;
  customMessage: string | null;
  viewsCount: number;
  maxViews: number;
  expiresAt: string | null;
}
