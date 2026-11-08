import type { SupabaseClient } from "@supabase/supabase-js";
import {
  getServerSupabaseClient,
  isSupabaseConfigured,
  type ConsumeLinkRpcRow,
  type CheckRateLimitRpcRow,
  type DatabaseLinkRow,
} from "@/lib/supabase/server";
import type {
  ConsumeLinkResult,
  CreateLinkRequest,
  ExpirationPreset,
  GeneratedLink,
} from "@/types/link";
import {
  computeExpirationDate,
  DEFAULT_RANDOM_SLUG_LENGTH,
  generateRandomSlug,
  isValidExpirationPreset,
  isValidSlugParam,
  MAX_MAX_VIEWS,
  MIN_MAX_VIEWS,
  validateCustomMessage,
  validateCustomSlug,
  validateDestinationUrl,
  type SlugValidationErrorCode,
  type UrlValidationErrorCode,
} from "@/lib/utils/url";

export const RATE_LIMIT_MAX_REQUESTS = 20;
export const RATE_LIMIT_WINDOW_SECONDS = 60;

export interface InsertLinkParams {
  slug: string;
  destinationUrl: string;
  customMessage: string | null;
  maxViews: number;
  expiresAt: string | null;
}

export type InsertLinkResult =
  | { ok: true; record: DatabaseLinkRow }
  | { ok: false; reason: "slug_conflict" | "db_error"; message?: string };

export interface RateLimitCheckResult {
  allowed: boolean;
  currentCount: number;
  resetAt: string;
}

export interface LinkRepository {
  insertLink(params: InsertLinkParams): Promise<InsertLinkResult>;
  consumeLink(slug: string): Promise<ConsumeLinkResult>;
  checkRateLimit(
    key: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<RateLimitCheckResult>;
}

/**
 * Production repository backed by Supabase PostgreSQL (`service_role`).
 * Uses the `public.consume_link` and `public.check_rate_limit` atomic SQL functions.
 */
export class SupabaseLinkRepository implements LinkRepository {
  private readonly client: SupabaseClient;

  constructor(client: SupabaseClient) {
    this.client = client;
  }

  async insertLink(params: InsertLinkParams): Promise<InsertLinkResult> {
    const { data, error } = await this.client
      .from("links")
      .insert({
        slug: params.slug,
        destination_url: params.destinationUrl,
        custom_message: params.customMessage,
        max_views: params.maxViews,
        views_count: 0,
        expires_at: params.expiresAt,
      })
      .select("*")
      .single();

    if (error) {
      // PostgreSQL unique_violation code is 23505
      if (
        error.code === "23505" ||
        error.message?.toLowerCase().includes("duplicate key") ||
        error.message?.toLowerCase().includes("unique")
      ) {
        return { ok: false, reason: "slug_conflict" };
      }
      return { ok: false, reason: "db_error", message: error.message };
    }

    return { ok: true, record: data as DatabaseLinkRow };
  }

  async consumeLink(slug: string): Promise<ConsumeLinkResult> {
    const { data, error } = await this.client.rpc("consume_link", {
      p_slug: slug,
    });

    if (error || !data) {
      throw new Error(
        `Failed to execute consume_link RPC: ${error?.message ?? "No data returned"}`
      );
    }

    const row: ConsumeLinkRpcRow | undefined = Array.isArray(data)
      ? data[0]
      : (data as ConsumeLinkRpcRow);

    if (!row) {
      return {
        status: "not_found",
        destinationUrl: null,
        customMessage: null,
        viewsCount: 0,
        maxViews: 0,
        expiresAt: null,
      };
    }

    return {
      status: row.status,
      destinationUrl: row.destination_url,
      customMessage: row.custom_message,
      viewsCount: row.views_count,
      maxViews: row.max_views,
      expiresAt: row.expires_at,
    };
  }

  async checkRateLimit(
    key: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<RateLimitCheckResult> {
    const { data, error } = await this.client.rpc("check_rate_limit", {
      p_key: key,
      p_max_requests: maxRequests,
      p_window_seconds: windowSeconds,
    });

    if (error || !data) {
      // Fail closed if rate-limit RPC fails unexpectedly
      throw new Error(
        `Failed to execute check_rate_limit RPC: ${error?.message ?? "No data"}`
      );
    }

    const row: CheckRateLimitRpcRow | undefined = Array.isArray(data)
      ? data[0]
      : (data as CheckRateLimitRpcRow);

    return {
      allowed: Boolean(row?.allowed),
      currentCount: row?.current_count ?? 1,
      resetAt: row?.reset_at ?? new Date(Date.now() + windowSeconds * 1000).toISOString(),
    };
  }
}

/**
 * Atomic in-memory repository that mirrors PostgreSQL `SELECT ... FOR UPDATE`
 * row-level locking and constraints. Used for automated concurrency tests and
 * local fallback when Supabase env vars are not yet populated.
 */
export class AtomicMemoryLinkRepository implements LinkRepository {
  private readonly linksBySlug = new Map<string, DatabaseLinkRow>();
  private readonly rateLimits = new Map<
    string,
    { requestCount: number; windowStartMs: number }
  >();
  private mutexChain: Promise<void> = Promise.resolve();
  private nowFn: () => number;

  constructor(nowFn: () => number = () => Date.now()) {
    this.nowFn = nowFn;
  }

  private async withLock<T>(fn: () => T | Promise<T>): Promise<T> {
    let release!: () => void;
    const nextLock = new Promise<void>((resolve) => {
      release = resolve;
    });
    const previousLock = this.mutexChain;
    this.mutexChain = previousLock.then(() => nextLock);
    await previousLock;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  async insertLink(params: InsertLinkParams): Promise<InsertLinkResult> {
    return this.withLock(() => {
      if (this.linksBySlug.has(params.slug)) {
        return { ok: false, reason: "slug_conflict" };
      }

      if (params.maxViews < MIN_MAX_VIEWS || params.maxViews > MAX_MAX_VIEWS) {
        return {
          ok: false,
          reason: "db_error",
          message: "max_views out of bounds",
        };
      }

      const nowIso = new Date(this.nowFn()).toISOString();
      const record: DatabaseLinkRow = {
        id: globalThis.crypto.randomUUID(),
        slug: params.slug,
        destination_url: params.destinationUrl,
        custom_message: params.customMessage,
        max_views: params.maxViews,
        views_count: 0,
        expires_at: params.expiresAt,
        created_at: nowIso,
        used_at: null,
      };

      this.linksBySlug.set(params.slug, record);
      return { ok: true, record: { ...record } };
    });
  }

  async consumeLink(slug: string): Promise<ConsumeLinkResult> {
    return this.withLock(() => {
      const trimmed = slug?.trim();
      if (!trimmed) {
        return {
          status: "not_found",
          destinationUrl: null,
          customMessage: null,
          viewsCount: 0,
          maxViews: 0,
          expiresAt: null,
        };
      }

      const link = this.linksBySlug.get(trimmed);
      if (!link) {
        return {
          status: "not_found",
          destinationUrl: null,
          customMessage: null,
          viewsCount: 0,
          maxViews: 0,
          expiresAt: null,
        };
      }

      const nowMs = this.nowFn();
      if (link.expires_at !== null && Date.parse(link.expires_at) <= nowMs) {
        return {
          status: "expired",
          destinationUrl: null,
          customMessage: link.custom_message,
          viewsCount: link.views_count,
          maxViews: link.max_views,
          expiresAt: link.expires_at,
        };
      }

      if (link.views_count >= link.max_views) {
        return {
          status: "max_views_reached",
          destinationUrl: null,
          customMessage: link.custom_message,
          viewsCount: link.views_count,
          maxViews: link.max_views,
          expiresAt: link.expires_at,
        };
      }

      link.views_count += 1;
      const nowIso = new Date(nowMs).toISOString();
      if (link.views_count >= link.max_views || !link.used_at) {
        link.used_at = nowIso;
      }

      return {
        status: "valid",
        destinationUrl: link.destination_url,
        customMessage: link.custom_message,
        viewsCount: link.views_count,
        maxViews: link.max_views,
        expiresAt: link.expires_at,
      };
    });
  }

  async checkRateLimit(
    key: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<RateLimitCheckResult> {
    return this.withLock(() => {
      const nowMs = this.nowFn();
      const windowMs = windowSeconds * 1000;
      const existing = this.rateLimits.get(key);

      if (!existing || existing.windowStartMs + windowMs <= nowMs) {
        const fresh = { requestCount: 1, windowStartMs: nowMs };
        this.rateLimits.set(key, fresh);
        return {
          allowed: 1 <= maxRequests,
          currentCount: 1,
          resetAt: new Date(nowMs + windowMs).toISOString(),
        };
      }

      existing.requestCount += 1;
      return {
        allowed: existing.requestCount <= maxRequests,
        currentCount: existing.requestCount,
        resetAt: new Date(existing.windowStartMs + windowMs).toISOString(),
      };
    });
  }

  inspectStoredRowForTests(slug: string): DatabaseLinkRow | undefined {
    if (process.env.NODE_ENV === "production") {
      throw new Error("SECURITY VIOLATION: Cannot inspect rows in production.");
    }
    const row = this.linksBySlug.get(slug);
    return row ? { ...row } : undefined;
  }

  clear(): void {
    this.linksBySlug.clear();
    this.rateLimits.clear();
  }
}

let testRepositoryOverride: LinkRepository | null = null;

export function setLinkRepositoryForTests(repo: LinkRepository | null): void {
  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "SECURITY VIOLATION: Cannot override LinkRepository in production environment."
    );
  }
  testRepositoryOverride = repo;
}

export function getActiveLinkRepository(): LinkRepository {
  if (process.env.NODE_ENV !== "production" && testRepositoryOverride) {
    return testRepositoryOverride;
  }

  if (!isSupabaseConfigured()) {
    throw new Error(
      "Supabase credentials (NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY) are required."
    );
  }

  return new SupabaseLinkRepository(getServerSupabaseClient());
}

export type CreateLinkErrorCode =
  | UrlValidationErrorCode
  | SlugValidationErrorCode
  | "invalid_max_views"
  | "invalid_expiration"
  | "message_too_long"
  | "rate_limited"
  | "server_error";

export type CreateLinkServiceResult =
  | {
      ok: true;
      status: 201;
      link: GeneratedLink;
    }
  | {
      ok: false;
      status: 400 | 409 | 429 | 500;
      errorCode: CreateLinkErrorCode;
      resetAt?: string;
    };

/**
 * Validates input, checks rate limits, handles random or custom slug creation
 * with collision retries, and persists the link.
 */
export async function createOnceLink(
  payload: CreateLinkRequest,
  options: {
    clientIp: string;
    appBaseUrl: string;
    repository?: LinkRepository;
  }
): Promise<CreateLinkServiceResult> {
  const repo = options.repository ?? getActiveLinkRepository();

  // 1. Persistent rate limit check
  try {
    const rl = await repo.checkRateLimit(
      `create_link:${options.clientIp}`,
      RATE_LIMIT_MAX_REQUESTS,
      RATE_LIMIT_WINDOW_SECONDS
    );

    if (!rl.allowed) {
      return {
        ok: false,
        status: 429,
        errorCode: "rate_limited",
        resetAt: rl.resetAt,
      };
    }
  } catch {
    return {
      ok: false,
      status: 500,
      errorCode: "server_error",
    };
  }

  // 2. Validate and normalize destination URL
  const urlCheck = validateDestinationUrl(
    payload.destinationUrl,
    options.appBaseUrl
  );
  if (!urlCheck.isValid || !urlCheck.normalizedUrl) {
    return {
      ok: false,
      status: 400,
      errorCode: urlCheck.errorCode ?? "invalid_url",
    };
  }

  // 3. Validate maxViews
  const rawMaxViews = payload.maxViews ?? 1;
  if (
    typeof rawMaxViews !== "number" ||
    !Number.isInteger(rawMaxViews) ||
    rawMaxViews < MIN_MAX_VIEWS ||
    rawMaxViews > MAX_MAX_VIEWS
  ) {
    return {
      ok: false,
      status: 400,
      errorCode: "invalid_max_views",
    };
  }

  // 4. Validate expiration preset
  const rawExpiration: ExpirationPreset = payload.expiration ?? "never";
  if (!isValidExpirationPreset(rawExpiration)) {
    return {
      ok: false,
      status: 400,
      errorCode: "invalid_expiration",
    };
  }

  // 5. Validate custom expired message
  const messageCheck = validateCustomMessage(payload.expiredMessage);
  if (!messageCheck.isValid) {
    return {
      ok: false,
      status: 400,
      errorCode: "message_too_long",
    };
  }

  // 6. Validate custom slug if provided
  const rawCustomSlug = payload.customSlug ?? "";
  const slugCheck = validateCustomSlug(rawCustomSlug);
  if (!slugCheck.isValid) {
    return {
      ok: false,
      status: 400,
      errorCode: slugCheck.errorCode ?? "slug_invalid",
    };
  }

  const expiresAt = computeExpirationDate(rawExpiration);
  const cleanBaseUrl = options.appBaseUrl.replace(/\/+$/, "");

  // 7a. User-defined custom slug: single insert attempt, 409 on collision
  if (slugCheck.normalizedSlug) {
    try {
      const insertResult = await repo.insertLink({
        slug: slugCheck.normalizedSlug,
        destinationUrl: urlCheck.normalizedUrl,
        customMessage: messageCheck.sanitized,
        maxViews: rawMaxViews,
        expiresAt,
      });

      if (!insertResult.ok) {
        if (insertResult.reason === "slug_conflict") {
          return {
            ok: false,
            status: 409,
            errorCode: "slug_taken",
          };
        }
        return {
          ok: false,
          status: 500,
          errorCode: "server_error",
        };
      }

      const record = insertResult.record;
      return {
        ok: true,
        status: 201,
        link: {
          id: record.id,
          slug: record.slug,
          shortUrl: `${cleanBaseUrl}/${record.slug}`,
          destinationUrl: record.destination_url,
          maxViews: record.max_views,
          viewsCount: record.views_count,
          remainingViews: Math.max(0, record.max_views - record.views_count),
          expiration: rawExpiration,
          expiresAt: record.expires_at,
          expiredMessage: record.custom_message,
          createdAt: record.created_at,
        },
      };
    } catch {
      return {
        ok: false,
        status: 500,
        errorCode: "server_error",
      };
    }
  }

  // 7b. Cryptographically random slug with collision retries
  const maxAttempts = 5;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const slugLength =
      attempt >= 3 ? DEFAULT_RANDOM_SLUG_LENGTH + 1 : DEFAULT_RANDOM_SLUG_LENGTH;
    const candidateSlug = generateRandomSlug(slugLength);

    try {
      const insertResult = await repo.insertLink({
        slug: candidateSlug,
        destinationUrl: urlCheck.normalizedUrl,
        customMessage: messageCheck.sanitized,
        maxViews: rawMaxViews,
        expiresAt,
      });

      if (insertResult.ok) {
        const record = insertResult.record;
        return {
          ok: true,
          status: 201,
          link: {
            id: record.id,
            slug: record.slug,
            shortUrl: `${cleanBaseUrl}/${record.slug}`,
            destinationUrl: record.destination_url,
            maxViews: record.max_views,
            viewsCount: record.views_count,
            remainingViews: Math.max(0, record.max_views - record.views_count),
            expiration: rawExpiration,
            expiresAt: record.expires_at,
            expiredMessage: record.custom_message,
            createdAt: record.created_at,
          },
        };
      }

      if (insertResult.reason !== "slug_conflict") {
        return {
          ok: false,
          status: 500,
          errorCode: "server_error",
        };
      }
    } catch {
      return {
        ok: false,
        status: 500,
        errorCode: "server_error",
      };
    }
  }

  return {
    ok: false,
    status: 500,
    errorCode: "server_error",
  };
}

/**
 * Atomically consumes one view of a link by slug.
 */
export async function consumeOnceLink(
  slug: string,
  repository?: LinkRepository
): Promise<ConsumeLinkResult> {
  if (!isValidSlugParam(slug)) {
    return {
      status: "not_found",
      destinationUrl: null,
      customMessage: null,
      viewsCount: 0,
      maxViews: 0,
      expiresAt: null,
    };
  }

  const repo = repository ?? getActiveLinkRepository();
  return repo.consumeLink(slug);
}
