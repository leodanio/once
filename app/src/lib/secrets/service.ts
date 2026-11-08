import type { SupabaseClient } from "@supabase/supabase-js";
import {
  getServerSupabaseClient,
  isSupabaseConfigured,
  type CheckRateLimitRpcRow,
} from "@/lib/supabase/server";
import type { ExpirationPreset } from "@/types/link";
import type {
  ConsumeSecretResult,
  ConsumeSecretStatus,
  CreatedSecretMetadata,
  CreateSecretRequest,
  SecretMetadataResult,
  SecretMetadataStatus,
} from "@/types/secret";
import {
  computeExpirationDate,
  generateRandomSlug,
  isValidExpirationPreset,
} from "@/lib/utils/url";
import {
  AES_GCM_IV_BYTE_LENGTH,
  isValidBase64UrlPayload,
  MAX_PBKDF2_ITERATIONS,
  MIN_PBKDF2_ITERATIONS,
  PBKDF2_SALT_BYTE_LENGTH,
} from "@/lib/secrets/crypto";

export const DEFAULT_SECRET_TOKEN_LENGTH = 21;
export const SECRET_CREATE_RATE_LIMIT_MAX = 20;
export const SECRET_CONSUME_RATE_LIMIT_MAX = 30;
export const SECRET_RATE_LIMIT_WINDOW_SECONDS = 60;

const SECRET_TOKEN_REGEX = /^[a-zA-Z0-9_-]{16,64}$/;

const FORBIDDEN_REQUEST_FIELDS = new Set([
  "plaintext",
  "message",
  "secret",
  "key",
  "fragmentkey",
  "fragment_key",
  "fragment",
  "password",
  "passphrase",
  "rawpassword",
]);

import {
  isPrefetchOrPreviewBotRequest,
  PREVIEW_BOT_USER_AGENT_REGEX,
} from "@/lib/utils/bot-detection";

export { isPrefetchOrPreviewBotRequest, PREVIEW_BOT_USER_AGENT_REGEX };

export interface DatabaseSecretRow {
  id: string;
  token: string;
  ciphertext: string;
  iv: string;
  password_protected: boolean;
  kdf_salt: string | null;
  kdf_iterations: number | null;
  created_at: string;
  expires_at: string | null;
  is_consumed: boolean;
  consumed_at: string | null;
}

interface GetSecretMetadataRpcRow {
  status: SecretMetadataStatus;
  password_protected: boolean;
  expires_at: string | null;
}

interface ConsumeSecretRpcRow {
  status: ConsumeSecretStatus;
  ciphertext: string | null;
  iv: string | null;
  password_protected: boolean;
  kdf_salt: string | null;
  kdf_iterations: number | null;
  expires_at: string | null;
  consumed_at: string | null;
}

export interface InsertSecretParams {
  token: string;
  ciphertext: string;
  iv: string;
  passwordProtected: boolean;
  kdfSalt: string | null;
  kdfIterations: number | null;
  expiresAt: string | null;
}

export type InsertSecretResult =
  | { ok: true; record: DatabaseSecretRow }
  | { ok: false; reason: "token_conflict" | "db_error"; message?: string };

export interface SecretRateLimitCheckResult {
  allowed: boolean;
  currentCount: number;
  resetAt: string;
}

export interface SecretRepository {
  insertSecret(params: InsertSecretParams): Promise<InsertSecretResult>;
  getSecretMetadata(token: string): Promise<SecretMetadataResult>;
  consumeSecret(token: string): Promise<ConsumeSecretResult>;
  checkRateLimit(
    key: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<SecretRateLimitCheckResult>;
}

/**
 * Generates a cryptographically random, unpredictable secret token (21 chars ~ 121 bits of entropy).
 */
export function generateSecretToken(
  length: number = DEFAULT_SECRET_TOKEN_LENGTH
): string {
  return generateRandomSlug(length);
}

/**
 * Validates that a token from a URL parameter matches the expected secret token format.
 */
export function isValidSecretToken(token: unknown): token is string {
  return typeof token === "string" && SECRET_TOKEN_REGEX.test(token);
}

/**
 * Detects whether a request body contains any forbidden plaintext, key, or password fields
 * that must never be transmitted to the backend.
 */
export function hasForbiddenSecretFields(
  body: Record<string, unknown>
): boolean {
  for (const key of Object.keys(body)) {
    if (FORBIDDEN_REQUEST_FIELDS.has(key.toLowerCase())) {
      return true;
    }
  }
  return false;
}


/**
 * Production repository backed by Supabase PostgreSQL (`service_role`).
 * Uses `public.get_secret_metadata`, `public.consume_secret`, and `public.check_rate_limit`.
 */
export class SupabaseSecretRepository implements SecretRepository {
  private readonly client: SupabaseClient;

  constructor(client: SupabaseClient) {
    this.client = client;
  }

  async insertSecret(params: InsertSecretParams): Promise<InsertSecretResult> {
    const { data, error } = await this.client
      .from("secrets")
      .insert({
        token: params.token,
        ciphertext: params.ciphertext,
        iv: params.iv,
        password_protected: params.passwordProtected,
        kdf_salt: params.kdfSalt,
        kdf_iterations: params.kdfIterations,
        expires_at: params.expiresAt,
        is_consumed: false,
        consumed_at: null,
      })
      .select("*")
      .single();

    if (error) {
      if (
        error.code === "23505" ||
        error.message?.toLowerCase().includes("duplicate key") ||
        error.message?.toLowerCase().includes("unique")
      ) {
        return { ok: false, reason: "token_conflict" };
      }
      // Never log ciphertext or sensitive parameters
      return { ok: false, reason: "db_error" };
    }

    return { ok: true, record: data as DatabaseSecretRow };
  }

  async getSecretMetadata(token: string): Promise<SecretMetadataResult> {
    const { data, error } = await this.client.rpc("get_secret_metadata", {
      p_token: token,
    });

    if (error || !data) {
      throw new Error("Failed to execute get_secret_metadata RPC");
    }

    const row: GetSecretMetadataRpcRow | undefined = Array.isArray(data)
      ? data[0]
      : (data as GetSecretMetadataRpcRow);

    if (!row) {
      return {
        status: "not_found",
        passwordProtected: false,
        expiresAt: null,
      };
    }

    return {
      status: row.status,
      passwordProtected: Boolean(row.password_protected),
      expiresAt: row.expires_at,
    };
  }

  async consumeSecret(token: string): Promise<ConsumeSecretResult> {
    const { data, error } = await this.client.rpc("consume_secret", {
      p_token: token,
    });

    if (error || !data) {
      throw new Error("Failed to execute consume_secret RPC");
    }

    const row: ConsumeSecretRpcRow | undefined = Array.isArray(data)
      ? data[0]
      : (data as ConsumeSecretRpcRow);

    if (!row) {
      return {
        status: "not_found",
        ciphertext: null,
        iv: null,
        passwordProtected: false,
        kdfSalt: null,
        kdfIterations: null,
        expiresAt: null,
        consumedAt: null,
      };
    }

    return {
      status: row.status,
      ciphertext: row.ciphertext,
      iv: row.iv,
      passwordProtected: Boolean(row.password_protected),
      kdfSalt: row.kdf_salt,
      kdfIterations: row.kdf_iterations,
      expiresAt: row.expires_at,
      consumedAt: row.consumed_at,
    };
  }

  async checkRateLimit(
    key: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<SecretRateLimitCheckResult> {
    const { data, error } = await this.client.rpc("check_rate_limit", {
      p_key: key,
      p_max_requests: maxRequests,
      p_window_seconds: windowSeconds,
    });

    if (error || !data) {
      throw new Error("Failed to execute check_rate_limit RPC");
    }

    const row: CheckRateLimitRpcRow | undefined = Array.isArray(data)
      ? data[0]
      : (data as CheckRateLimitRpcRow);

    return {
      allowed: Boolean(row?.allowed),
      currentCount: row?.current_count ?? 1,
      resetAt:
        row?.reset_at ??
        new Date(Date.now() + windowSeconds * 1000).toISOString(),
    };
  }
}

/**
 * Atomic in-memory repository mirroring PostgreSQL `SELECT ... FOR UPDATE` row-level locking
 * and immediate ciphertext scrubbing upon consumption.
 */
export class AtomicMemorySecretRepository implements SecretRepository {
  private readonly secretsByToken = new Map<string, DatabaseSecretRow>();
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

  async insertSecret(params: InsertSecretParams): Promise<InsertSecretResult> {
    return this.withLock(() => {
      if (this.secretsByToken.has(params.token)) {
        return { ok: false, reason: "token_conflict" };
      }

      const nowIso = new Date(this.nowFn()).toISOString();
      const record: DatabaseSecretRow = {
        id: globalThis.crypto.randomUUID(),
        token: params.token,
        ciphertext: params.ciphertext,
        iv: params.iv,
        password_protected: params.passwordProtected,
        kdf_salt: params.kdfSalt,
        kdf_iterations: params.kdfIterations,
        created_at: nowIso,
        expires_at: params.expiresAt,
        is_consumed: false,
        consumed_at: null,
      };

      this.secretsByToken.set(params.token, record);
      return { ok: true, record: { ...record } };
    });
  }

  async getSecretMetadata(token: string): Promise<SecretMetadataResult> {
    return this.withLock(() => {
      const trimmed = token?.trim();
      if (!trimmed) {
        return {
          status: "not_found",
          passwordProtected: false,
          expiresAt: null,
        };
      }

      const secret = this.secretsByToken.get(trimmed);
      if (!secret) {
        return {
          status: "not_found",
          passwordProtected: false,
          expiresAt: null,
        };
      }

      if (secret.is_consumed || secret.consumed_at !== null) {
        return {
          status: "consumed",
          passwordProtected: false,
          expiresAt: secret.expires_at,
        };
      }

      const nowMs = this.nowFn();
      if (
        secret.expires_at !== null &&
        Date.parse(secret.expires_at) <= nowMs
      ) {
        return {
          status: "expired",
          passwordProtected: false,
          expiresAt: secret.expires_at,
        };
      }

      return {
        status: "available",
        passwordProtected: secret.password_protected,
        expiresAt: secret.expires_at,
      };
    });
  }

  async consumeSecret(token: string): Promise<ConsumeSecretResult> {
    return this.withLock(() => {
      const trimmed = token?.trim();
      if (!trimmed) {
        return {
          status: "not_found",
          ciphertext: null,
          iv: null,
          passwordProtected: false,
          kdfSalt: null,
          kdfIterations: null,
          expiresAt: null,
          consumedAt: null,
        };
      }

      const secret = this.secretsByToken.get(trimmed);
      if (!secret) {
        return {
          status: "not_found",
          ciphertext: null,
          iv: null,
          passwordProtected: false,
          kdfSalt: null,
          kdfIterations: null,
          expiresAt: null,
          consumedAt: null,
        };
      }

      if (secret.is_consumed || secret.consumed_at !== null) {
        return {
          status: "consumed",
          ciphertext: null,
          iv: null,
          passwordProtected: false,
          kdfSalt: null,
          kdfIterations: null,
          expiresAt: secret.expires_at,
          consumedAt: secret.consumed_at,
        };
      }

      const nowMs = this.nowFn();
      if (
        secret.expires_at !== null &&
        Date.parse(secret.expires_at) <= nowMs
      ) {
        return {
          status: "expired",
          ciphertext: null,
          iv: null,
          passwordProtected: false,
          kdfSalt: null,
          kdfIterations: null,
          expiresAt: secret.expires_at,
          consumedAt: null,
        };
      }

      const originalCiphertext = secret.ciphertext;
      const nowIso = new Date(nowMs).toISOString();

      // Atomically mark consumed and scrub stored ciphertext
      secret.is_consumed = true;
      secret.consumed_at = nowIso;
      secret.ciphertext = "[CONSUMED]";

      return {
        status: "valid",
        ciphertext: originalCiphertext,
        iv: secret.iv,
        passwordProtected: secret.password_protected,
        kdfSalt: secret.kdf_salt,
        kdfIterations: secret.kdf_iterations,
        expiresAt: secret.expires_at,
        consumedAt: secret.consumed_at,
      };
    });
  }

  async checkRateLimit(
    key: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<SecretRateLimitCheckResult> {
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

  /**
   * Test-only helper to inspect stored database state without exposing via API.
   */
  inspectStoredRowForTests(token: string): DatabaseSecretRow | undefined {
    if (process.env.NODE_ENV === "production") {
      throw new Error("SECURITY VIOLATION: Cannot inspect rows in production.");
    }
    const row = this.secretsByToken.get(token);
    return row ? { ...row } : undefined;
  }

  clear(): void {
    this.secretsByToken.clear();
    this.rateLimits.clear();
  }
}

let testSecretRepositoryOverride: SecretRepository | null = null;

export function setSecretRepositoryForTests(
  repo: SecretRepository | null
): void {
  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "SECURITY VIOLATION: Cannot override SecretRepository in production environment."
    );
  }
  testSecretRepositoryOverride = repo;
}

export function getActiveSecretRepository(): SecretRepository {
  if (process.env.NODE_ENV !== "production" && testSecretRepositoryOverride) {
    return testSecretRepositoryOverride;
  }

  if (!isSupabaseConfigured()) {
    throw new Error(
      "Supabase credentials (NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY) are required."
    );
  }

  return new SupabaseSecretRepository(getServerSupabaseClient());
}

export type CreateSecretErrorCode =
  | "invalid_payload"
  | "forbidden_plaintext_or_key_field"
  | "invalid_ciphertext"
  | "invalid_iv"
  | "invalid_kdf_params"
  | "invalid_expiration"
  | "rate_limited"
  | "server_error";

export type CreateSecretServiceResult =
  | {
      ok: true;
      status: 201;
      secret: CreatedSecretMetadata;
    }
  | {
      ok: false;
      status: 400 | 429 | 500;
      errorCode: CreateSecretErrorCode;
      resetAt?: string;
    };

/**
 * Validates encrypted payload, enforces rate limiting, generates a random token,
 * and persists the ciphertext record without ever seeing plaintext or keys.
 */
export async function createEncryptedSecret(
  payload: CreateSecretRequest,
  options: {
    clientIp: string;
    repository?: SecretRepository;
  }
): Promise<CreateSecretServiceResult> {
  const repo = options.repository ?? getActiveSecretRepository();

  // 1. Rate limit check
  try {
    const rl = await repo.checkRateLimit(
      `create_secret:${options.clientIp}`,
      SECRET_CREATE_RATE_LIMIT_MAX,
      SECRET_RATE_LIMIT_WINDOW_SECONDS
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

  // 2. Validate ciphertext (minimum 1 byte plaintext + 16 byte GCM tag = 17 bytes; max ~12KB)
  if (!isValidBase64UrlPayload(payload.ciphertext, 17, 12000)) {
    return {
      ok: false,
      status: 400,
      errorCode: "invalid_ciphertext",
    };
  }

  // 3. Validate 96-bit (12-byte) IV
  if (
    !isValidBase64UrlPayload(
      payload.iv,
      AES_GCM_IV_BYTE_LENGTH,
      AES_GCM_IV_BYTE_LENGTH
    )
  ) {
    return {
      ok: false,
      status: 400,
      errorCode: "invalid_iv",
    };
  }

  // 4. Validate KDF parameters consistency
  if (typeof payload.passwordProtected !== "boolean") {
    return {
      ok: false,
      status: 400,
      errorCode: "invalid_kdf_params",
    };
  }

  let normalizedSalt: string | null = null;
  let normalizedIterations: number | null = null;

  if (payload.passwordProtected) {
    if (
      !isValidBase64UrlPayload(
        payload.kdfSalt,
        PBKDF2_SALT_BYTE_LENGTH,
        PBKDF2_SALT_BYTE_LENGTH
      ) ||
      typeof payload.kdfIterations !== "number" ||
      !Number.isInteger(payload.kdfIterations) ||
      payload.kdfIterations < MIN_PBKDF2_ITERATIONS ||
      payload.kdfIterations > MAX_PBKDF2_ITERATIONS
    ) {
      return {
        ok: false,
        status: 400,
        errorCode: "invalid_kdf_params",
      };
    }
    normalizedSalt = payload.kdfSalt;
    normalizedIterations = payload.kdfIterations;
  } else {
    if (
      (payload.kdfSalt !== undefined && payload.kdfSalt !== null) ||
      (payload.kdfIterations !== undefined && payload.kdfIterations !== null)
    ) {
      return {
        ok: false,
        status: 400,
        errorCode: "invalid_kdf_params",
      };
    }
  }

  // 5. Validate expiration preset
  const rawExpiration: ExpirationPreset = payload.expiration ?? "never";
  if (!isValidExpirationPreset(rawExpiration)) {
    return {
      ok: false,
      status: 400,
      errorCode: "invalid_expiration",
    };
  }

  const expiresAt = computeExpirationDate(rawExpiration);

  // 6. Generate random unpredictable token with collision retry
  const maxAttempts = 5;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const token = generateSecretToken(DEFAULT_SECRET_TOKEN_LENGTH);

    try {
      const insertResult = await repo.insertSecret({
        token,
        ciphertext: payload.ciphertext,
        iv: payload.iv,
        passwordProtected: payload.passwordProtected,
        kdfSalt: normalizedSalt,
        kdfIterations: normalizedIterations,
        expiresAt,
      });

      if (insertResult.ok) {
        const record = insertResult.record;
        return {
          ok: true,
          status: 201,
          secret: {
            id: record.id,
            token: record.token,
            expiration: rawExpiration,
            expiresAt: record.expires_at,
            passwordProtected: record.password_protected,
            createdAt: record.created_at,
          },
        };
      }

      if (insertResult.reason !== "token_conflict") {
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
 * Checks non-consuming secret status and whether password derivation is needed.
 */
export async function checkSecretMetadata(
  token: string,
  options?: {
    clientIp?: string;
    repository?: SecretRepository;
  }
): Promise<
  | { ok: true; metadata: SecretMetadataResult }
  | { ok: false; status: 429 | 500; errorCode: "rate_limited" | "server_error"; resetAt?: string }
> {
  if (!isValidSecretToken(token)) {
    return {
      ok: true,
      metadata: {
        status: "not_found",
        passwordProtected: false,
        expiresAt: null,
      },
    };
  }

  const repo = options?.repository ?? getActiveSecretRepository();

  if (options?.clientIp) {
    try {
      const rl = await repo.checkRateLimit(
        `meta_secret:${options.clientIp}`,
        SECRET_CONSUME_RATE_LIMIT_MAX,
        SECRET_RATE_LIMIT_WINDOW_SECONDS
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
  }

  try {
    const metadata = await repo.getSecretMetadata(token);
    return { ok: true, metadata };
  } catch {
    return {
      ok: false,
      status: 500,
      errorCode: "server_error",
    };
  }
}

/**
 * Atomically consumes a secret, scrubs its stored ciphertext to '[CONSUMED]' in the database,
 * and returns the original ciphertext only to the single winning request.
 */
export async function consumeEncryptedSecret(
  token: string,
  options?: {
    clientIp?: string;
    repository?: SecretRepository;
  }
): Promise<
  | { ok: true; result: ConsumeSecretResult }
  | { ok: false; status: 429 | 500; errorCode: "rate_limited" | "server_error"; resetAt?: string }
> {
  if (!isValidSecretToken(token)) {
    return {
      ok: true,
      result: {
        status: "not_found",
        ciphertext: null,
        iv: null,
        passwordProtected: false,
        kdfSalt: null,
        kdfIterations: null,
        expiresAt: null,
        consumedAt: null,
      },
    };
  }

  const repo = options?.repository ?? getActiveSecretRepository();

  if (options?.clientIp) {
    try {
      const rl = await repo.checkRateLimit(
        `consume_secret:${options.clientIp}`,
        SECRET_CONSUME_RATE_LIMIT_MAX,
        SECRET_RATE_LIMIT_WINDOW_SECONDS
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
  }

  try {
    const result = await repo.consumeSecret(token);
    return { ok: true, result };
  } catch {
    return {
      ok: false,
      status: 500,
      errorCode: "server_error",
    };
  }
}
