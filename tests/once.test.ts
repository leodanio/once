import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import {
  AtomicMemoryLinkRepository,
  SupabaseLinkRepository,
  createOnceLink,
  consumeOnceLink,
  getActiveLinkRepository,
  setLinkRepositoryForTests,
  RATE_LIMIT_MAX_REQUESTS,
  type InsertLinkParams,
  type InsertLinkResult,
} from "@/lib/links/service";
import {
  validateDestinationUrl,
  validateCustomSlug,
  generateRandomSlug,
  RESERVED_SLUGS,
} from "@/lib/utils/url";
import { generateQrMatrix } from "@/lib/utils/qrcode";
import {
  CIRCULAR_REVEAL_DURATION_MS,
  PAGE_TRANSITION_DURATION_MS,
  CIRCULAR_REVEAL_EASING,
  computeMaxRevealRadius,
  isUnmodifiedPrimaryClick,
  resolveTransitionOrigin,
} from "@/lib/utils/theme-transition";
import { POST as createLinkPostHandler } from "@/app/api/links/route";
import { POST as createSecretPostHandler } from "@/app/api/secrets/route";
import { GET as getSecretMetadataGetHandler } from "@/app/api/secrets/[token]/route";
import { POST as consumeSecretPostHandler } from "@/app/api/secrets/[token]/consume/route";
import { extractClientIp, isValidIp } from "@/lib/utils/ip";
import { isPreviewBotUserAgent } from "@/lib/utils/bot-detection";
import {
  DEFAULT_PBKDF2_ITERATIONS,
  MIN_SECRET_PASSWORD_LENGTH,
  SecretCryptoError,
  bytesToBase64Url,
  base64UrlToBytes,
  decryptSecretMessage,
  encryptSecretMessage,
  evaluatePasswordStrength,
  isValidFragmentKey,
  parseFragmentKeyFromHash,
} from "@/lib/secrets/crypto";
import {
  AtomicMemorySecretRepository,
  SECRET_CREATE_RATE_LIMIT_MAX,
  SECRET_CONSUME_RATE_LIMIT_MAX,
  SupabaseSecretRepository,
  checkSecretMetadata,
  consumeEncryptedSecret,
  createEncryptedSecret,
  hasForbiddenSecretFields,
  isPrefetchOrPreviewBotRequest,
  setSecretRepositoryForTests,
} from "@/lib/secrets/service";
import type { SupabaseClient } from "@supabase/supabase-js";

const APP_BASE_URL = "https://once.sh";

describe("ONCE — URL & Slug Security Validation", () => {
  it("validates and normalizes valid HTTP and HTTPS URLs", () => {
    const res1 = validateDestinationUrl("https://linear.app/features", APP_BASE_URL);
    assert.equal(res1.isValid, true);
    assert.equal(res1.normalizedUrl, "https://linear.app/features");

    const res2 = validateDestinationUrl("vercel.com/docs?ref=once", APP_BASE_URL);
    assert.equal(res2.isValid, true);
    assert.equal(res2.normalizedUrl, "https://vercel.com/docs?ref=once");

    const res3 = validateDestinationUrl("http://localhost:3000/test", APP_BASE_URL);
    assert.equal(res3.isValid, true);
    assert.equal(res3.normalizedUrl, "http://localhost:3000/test");
  });

  it("rejects invalid and malformed URLs", () => {
    assert.equal(validateDestinationUrl("", APP_BASE_URL).errorCode, "empty");
    assert.equal(validateDestinationUrl("   ", APP_BASE_URL).errorCode, "empty");
    assert.equal(
      validateDestinationUrl("https://example.com/with space", APP_BASE_URL).errorCode,
      "spaces"
    );
    assert.equal(
      validateDestinationUrl("invalid-domain", APP_BASE_URL).errorCode,
      "domain"
    );
    assert.equal(
      validateDestinationUrl("https://.com", APP_BASE_URL).errorCode,
      "domain"
    );
    assert.equal(
      validateDestinationUrl(
        `https://example.com/${"a".repeat(2050)}`,
        APP_BASE_URL
      ).errorCode,
      "url_too_long"
    );
  });

  it("rejects unsupported and dangerous protocols (XSS / SSRF / Open Redirect protection)", () => {
    const dangerousUrls = [
      "javascript:alert(1)",
      "JAVASCRIPT:alert(document.cookie)",
      "data:text/html,<script>alert(1)</script>",
      "vbscript:msgbox(1)",
      "file:///etc/passwd",
      "ftp://ftp.example.com/file.zip",
      "mailto:user@example.com",
      "ws://example.com/socket",
    ];

    for (const url of dangerousUrls) {
      const result = validateDestinationUrl(url, APP_BASE_URL);
      assert.equal(
        result.isValid,
        false,
        `Expected ${url} to be rejected`
      );
      assert.equal(result.errorCode, "protocol");
    }
  });

  it("rejects open redirect vectors (embedded credentials, backslashes, self-redirects)", () => {
    const credUrl = validateDestinationUrl(
      "https://trusted.com:pass@evil.com/login",
      APP_BASE_URL
    );
    assert.equal(credUrl.isValid, false);

    const backslashUrl = validateDestinationUrl(
      "https://trusted.com\\@evil.com",
      APP_BASE_URL
    );
    assert.equal(backslashUrl.isValid, false);

    const selfRedirect = validateDestinationUrl(
      "https://once.sh/some-slug",
      APP_BASE_URL
    );
    assert.equal(selfRedirect.isValid, false);
    assert.equal(selfRedirect.errorCode, "self_redirect");
  });

  it("generates cryptographically random slugs with valid format", () => {
    const slugs = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const s = generateRandomSlug(7);
      assert.equal(s.length, 7);
      assert.match(s, /^[23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ]{7}$/);
      slugs.add(s);
    }
    assert.equal(slugs.size, 100);
  });

  it("validates custom slugs and blocks reserved route names", () => {
    assert.equal(validateCustomSlug("my-custom_link1").isValid, true);
    assert.equal(validateCustomSlug("ab").errorCode, "slug_short");
    assert.equal(validateCustomSlug("a".repeat(33)).errorCode, "slug_long");
    assert.equal(validateCustomSlug("bad/slug").errorCode, "slug_invalid");
    assert.equal(validateCustomSlug("api").errorCode, "slug_reserved");
    assert.equal(validateCustomSlug("about").errorCode, "slug_reserved");
    assert.equal(validateCustomSlug("secrets").errorCode, "slug_reserved");
    assert.equal(validateCustomSlug("SECRETS").errorCode, "slug_reserved");
    assert.equal(validateCustomSlug("secret").errorCode, "slug_reserved");
    assert.equal(validateCustomSlug("link").errorCode, "slug_reserved");
    assert.equal(validateCustomSlug("links").errorCode, "slug_reserved");
    assert.equal(validateCustomSlug("edulink").errorCode, "slug_reserved");
    assert.equal(validateCustomSlug("admin").errorCode, "slug_reserved");
    assert.equal(RESERVED_SLUGS.has("secrets"), true);
  });
});

describe("ONCE — Link Creation, Consumption, Expiration & Concurrency", () => {
  let currentTimeMs = Date.parse("2026-11-07T12:00:00.000Z");
  let repo: AtomicMemoryLinkRepository;

  beforeEach(() => {
    currentTimeMs = Date.parse("2026-11-07T12:00:00.000Z");
    repo = new AtomicMemoryLinkRepository(() => currentTimeMs);
    setLinkRepositoryForTests(repo);
  });

  it("creates a valid link via POST /api/links and returns 201 with generated shortUrl", async () => {
    const req = new NextRequest("https://once.sh/api/links", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-forwarded-for": "203.0.113.10",
      },
      body: JSON.stringify({
        destinationUrl: "https://github.com/vercel/next.js",
        maxViews: 1,
        expiration: "1h",
      }),
    });

    const res = await createLinkPostHandler(req);
    assert.equal(res.status, 201);
    assert.match(res.headers.get("Cache-Control") ?? "", /no-store/);

    const data = (await res.json()) as { link: Record<string, unknown> };
    assert.ok(data.link);
    assert.equal(data.link.destinationUrl, "https://github.com/vercel/next.js");
    assert.equal(data.link.maxViews, 1);
    assert.equal(data.link.viewsCount, 0);
    assert.equal(data.link.remainingViews, 1);
    assert.match(String(data.link.shortUrl), /^https?:\/\/[^/]+\/[a-zA-Z0-9_-]{7}$/);
  });

  it("supports custom slugs and rejects duplicate custom slugs with 409 Conflict", async () => {
    const first = await createOnceLink(
      {
        destinationUrl: "https://linear.app",
        customSlug: "secret-drop",
      },
      { clientIp: "10.0.0.1", appBaseUrl: APP_BASE_URL, repository: repo }
    );
    assert.equal(first.ok, true);
    if (first.ok) {
      assert.equal(first.link.slug, "secret-drop");
      assert.equal(first.link.shortUrl, "https://once.sh/secret-drop");
    }

    const duplicate = await createOnceLink(
      {
        destinationUrl: "https://raycast.com",
        customSlug: "secret-drop",
      },
      { clientIp: "10.0.0.1", appBaseUrl: APP_BASE_URL, repository: repo }
    );
    assert.equal(duplicate.ok, false);
    if (!duplicate.ok) {
      assert.equal(duplicate.status, 409);
      assert.equal(duplicate.errorCode, "slug_taken");
    }
  });

  it("retries automatically when a random slug collision occurs", async () => {
    let attempts = 0;
    const collidingRepo = new AtomicMemoryLinkRepository();
    const origInsert = collidingRepo.insertLink.bind(collidingRepo);
    collidingRepo.insertLink = async (
      params: InsertLinkParams
    ): Promise<InsertLinkResult> => {
      attempts += 1;
      if (attempts === 1) {
        return { ok: false, reason: "slug_conflict" };
      }
      return origInsert(params);
    };

    const created = await createOnceLink(
      { destinationUrl: "https://example.com" },
      {
        clientIp: "10.0.0.2",
        appBaseUrl: APP_BASE_URL,
        repository: collidingRepo,
      }
    );

    assert.equal(created.ok, true);
    assert.equal(attempts, 2);
  });

  it("enforces single-use link consumption (max_views = 1)", async () => {
    const created = await createOnceLink(
      {
        destinationUrl: "https://example.com/private-doc",
        maxViews: 1,
        expiredMessage: "Document link self-destructed.",
      },
      { clientIp: "10.0.0.3", appBaseUrl: APP_BASE_URL, repository: repo }
    );
    assert.equal(created.ok, true);
    if (!created.ok) return;

    // 1st visit -> valid redirect
    const visit1 = await consumeOnceLink(created.link.slug, repo);
    assert.equal(visit1.status, "valid");
    assert.equal(visit1.destinationUrl, "https://example.com/private-doc");
    assert.equal(visit1.viewsCount, 1);

    // 2nd visit -> exhausted, never reveals destinationUrl, returns customMessage
    const visit2 = await consumeOnceLink(created.link.slug, repo);
    assert.equal(visit2.status, "max_views_reached");
    assert.equal(visit2.destinationUrl, null);
    assert.equal(visit2.customMessage, "Document link self-destructed.");
    assert.equal(visit2.viewsCount, 1);
  });

  it("enforces multiple-use link consumption (max_views = 3)", async () => {
    const created = await createOnceLink(
      {
        destinationUrl: "https://example.com/team-invite",
        maxViews: 3,
      },
      { clientIp: "10.0.0.4", appBaseUrl: APP_BASE_URL, repository: repo }
    );
    assert.equal(created.ok, true);
    if (!created.ok) return;

    for (let i = 1; i <= 3; i++) {
      const visit = await consumeOnceLink(created.link.slug, repo);
      assert.equal(visit.status, "valid");
      assert.equal(visit.destinationUrl, "https://example.com/team-invite");
      assert.equal(visit.viewsCount, i);
    }

    const visit4 = await consumeOnceLink(created.link.slug, repo);
    assert.equal(visit4.status, "max_views_reached");
    assert.equal(visit4.destinationUrl, null);
    assert.equal(visit4.viewsCount, 3);
  });

  it("enforces time-based expiration and returns custom expired message", async () => {
    const created = await createOnceLink(
      {
        destinationUrl: "https://example.com/time-sensitive",
        maxViews: 5,
        expiration: "15m",
        expiredMessage: "Window closed after 15 minutes.",
      },
      { clientIp: "10.0.0.5", appBaseUrl: APP_BASE_URL, repository: repo }
    );
    assert.equal(created.ok, true);
    if (!created.ok) return;

    // Advance clock past 15 minutes
    currentTimeMs = Date.now() + 16 * 60 * 1000;

    const expiredVisit = await consumeOnceLink(created.link.slug, repo);
    assert.equal(expiredVisit.status, "expired");
    assert.equal(expiredVisit.destinationUrl, null);
    assert.equal(
      expiredVisit.customMessage,
      "Window closed after 15 minutes."
    );
    assert.equal(expiredVisit.viewsCount, 0);
  });

  it("returns not_found for unknown or malformed slugs", async () => {
    const unknown = await consumeOnceLink("nonexistent99", repo);
    assert.equal(unknown.status, "not_found");
    assert.equal(unknown.destinationUrl, null);

    const invalid = await consumeOnceLink("../etc/passwd", repo);
    assert.equal(invalid.status, "not_found");
    assert.equal(invalid.destinationUrl, null);
  });

  it("CRITICAL CONCURRENCY TEST 1: max_views = 1 under 25 simultaneous requests allows EXACTLY ONE redirect", async () => {
    const created = await createOnceLink(
      {
        destinationUrl: "https://example.com/atomic-one-time-secret",
        maxViews: 1,
        expiredMessage: "Already claimed by another request.",
      },
      { clientIp: "10.0.0.6", appBaseUrl: APP_BASE_URL, repository: repo }
    );
    assert.equal(created.ok, true);
    if (!created.ok) return;

    const totalConcurrent = 25;
    const responses = await Promise.all(
      Array.from({ length: totalConcurrent }, () =>
        consumeOnceLink(created.link.slug, repo)
      )
    );

    const validResponses = responses.filter((r) => r.status === "valid");
    const expiredResponses = responses.filter(
      (r) => r.status === "max_views_reached"
    );

    assert.equal(
      validResponses.length,
      1,
      "Exactly ONE request must receive the destination URL"
    );
    assert.equal(
      validResponses[0].destinationUrl,
      "https://example.com/atomic-one-time-secret"
    );

    assert.equal(
      expiredResponses.length,
      totalConcurrent - 1,
      "Every other simultaneous request must receive max_views_reached"
    );
    for (const exp of expiredResponses) {
      assert.equal(exp.destinationUrl, null);
      assert.equal(exp.customMessage, "Already claimed by another request.");
    }
  });

  it("CRITICAL CONCURRENCY TEST 2: max_views = 5 under 30 simultaneous requests allows EXACTLY FIVE redirects", async () => {
    const created = await createOnceLink(
      {
        destinationUrl: "https://example.com/atomic-five-seats",
        maxViews: 5,
        expiredMessage: "All 5 seats have been claimed.",
      },
      { clientIp: "10.0.0.7", appBaseUrl: APP_BASE_URL, repository: repo }
    );
    assert.equal(created.ok, true);
    if (!created.ok) return;

    const totalConcurrent = 30;
    const responses = await Promise.all(
      Array.from({ length: totalConcurrent }, () =>
        consumeOnceLink(created.link.slug, repo)
      )
    );

    const validResponses = responses.filter((r) => r.status === "valid");
    const expiredResponses = responses.filter(
      (r) => r.status === "max_views_reached"
    );

    assert.equal(
      validResponses.length,
      5,
      "Exactly FIVE requests must succeed"
    );
    for (const valid of validResponses) {
      assert.equal(
        valid.destinationUrl,
        "https://example.com/atomic-five-seats"
      );
    }

    assert.equal(
      expiredResponses.length,
      totalConcurrent - 5,
      "Remaining 25 simultaneous requests must receive expired response"
    );
    for (const exp of expiredResponses) {
      assert.equal(exp.destinationUrl, null);
      assert.equal(exp.customMessage, "All 5 seats have been claimed.");
    }
  });

  it("enforces rate limiting on link creation and resets after window expires", async () => {
    const clientIp = "198.51.100.42";

    for (let i = 0; i < RATE_LIMIT_MAX_REQUESTS; i++) {
      const res = await createOnceLink(
        { destinationUrl: `https://example.com/page-${i}` },
        { clientIp, appBaseUrl: APP_BASE_URL, repository: repo }
      );
      assert.equal(res.ok, true);
    }

    // 21st request within the same 60-second window must be blocked with 429
    const blocked = await createOnceLink(
      { destinationUrl: "https://example.com/blocked" },
      { clientIp, appBaseUrl: APP_BASE_URL, repository: repo }
    );
    assert.equal(blocked.ok, false);
    if (!blocked.ok) {
      assert.equal(blocked.status, 429);
      assert.equal(blocked.errorCode, "rate_limited");
      assert.ok(blocked.resetAt);
    }

    // Advance clock by 61 seconds -> rate limit window resets
    currentTimeMs += 61 * 1000;
    const allowedAgain = await createOnceLink(
      { destinationUrl: "https://example.com/allowed-again" },
      { clientIp, appBaseUrl: APP_BASE_URL, repository: repo }
    );
    assert.equal(allowedAgain.ok, true);
  });

  it("verifies SupabaseLinkRepository delegates atomically to consume_link and check_rate_limit RPCs", async () => {
    const rpcCalls: Array<{ fn: string; args: Record<string, unknown> }> = [];

    const mockSupabaseClient = {
      from(table: string) {
        assert.equal(table, "links");
        return {
          insert(row: Record<string, unknown>) {
            return {
              select() {
                return {
                  async single() {
                    if (row.slug === "taken-slug") {
                      return {
                        data: null,
                        error: {
                          code: "23505",
                          message: "duplicate key value violates unique constraint",
                        },
                      };
                    }
                    return {
                      data: {
                        id: "11111111-2222-3333-4444-555555555555",
                        slug: row.slug,
                        destination_url: row.destination_url,
                        custom_message: row.custom_message,
                        max_views: row.max_views,
                        views_count: 0,
                        expires_at: row.expires_at,
                        created_at: "2026-11-07T12:00:00.000Z",
                        used_at: null,
                      },
                      error: null,
                    };
                  },
                };
              },
            };
          },
        };
      },
      async rpc(fn: string, args: Record<string, unknown>) {
        rpcCalls.push({ fn, args });
        if (fn === "consume_link") {
          return {
            data: [
              {
                status: "valid",
                destination_url: "https://supabase.com",
                custom_message: null,
                views_count: 1,
                max_views: 1,
                expires_at: null,
              },
            ],
            error: null,
          };
        }
        if (fn === "check_rate_limit") {
          return {
            data: [
              {
                allowed: true,
                current_count: 1,
                reset_at: "2026-11-07T12:01:00.000Z",
              },
            ],
            error: null,
          };
        }
        return { data: null, error: { message: "Unknown RPC" } };
      },
    } as unknown as SupabaseClient;

    const supaRepo = new SupabaseLinkRepository(mockSupabaseClient);

    const conflict = await supaRepo.insertLink({
      slug: "taken-slug",
      destinationUrl: "https://supabase.com",
      customMessage: null,
      maxViews: 1,
      expiresAt: null,
    });
    assert.equal(conflict.ok, false);
    if (!conflict.ok) {
      assert.equal(conflict.reason, "slug_conflict");
    }

    const consumed = await supaRepo.consumeLink("valid-slug");
    assert.equal(consumed.status, "valid");
    assert.equal(consumed.destinationUrl, "https://supabase.com");
    assert.equal(rpcCalls[0].fn, "consume_link");
    assert.deepEqual(rpcCalls[0].args, { p_slug: "valid-slug" });
  });

  it("generates a valid ISO/IEC 18004 QR code matrix for generated short URLs", () => {
    const matrix = generateQrMatrix("https://once.sh/x9k2m7a");
    assert.equal(matrix.length, 25); // Version 2 (25x25) fits 23-byte URL
    assert.equal(matrix[0].length, 25);
    // Top-left finder pattern corner and center must be dark
    assert.equal(matrix[0][0], true);
    assert.equal(matrix[3][3], true);
  });

  it("refuses in-memory repository fallback in production or when Supabase credentials are missing", () => {
    const prevNodeEnv = process.env.NODE_ENV;
    const prevUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const prevServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    const prevSecretKey = process.env.SUPABASE_SECRET_KEY;

    try {
      setLinkRepositoryForTests(null);
      delete process.env.NEXT_PUBLIC_SUPABASE_URL;
      delete process.env.SUPABASE_SERVICE_ROLE_KEY;
      delete process.env.SUPABASE_SECRET_KEY;

      // Without credentials, getActiveLinkRepository must throw and never fall back to memory
      assert.throws(
        () => getActiveLinkRepository(),
        /Supabase credentials .* are required/
      );

      // In production, attempting to inject a test repository must throw a security error
      (process.env as Record<string, string | undefined>).NODE_ENV = "production";
      assert.throws(
        () => setLinkRepositoryForTests(repo),
        /SECURITY VIOLATION/
      );
      assert.throws(
        () => getActiveLinkRepository(),
        /Supabase credentials .* are required/
      );
    } finally {
      (process.env as Record<string, string | undefined>).NODE_ENV = prevNodeEnv;
      if (prevUrl !== undefined) process.env.NEXT_PUBLIC_SUPABASE_URL = prevUrl;
      if (prevServiceKey !== undefined) {
        process.env.SUPABASE_SERVICE_ROLE_KEY = prevServiceKey;
      }
      if (prevSecretKey !== undefined) {
        process.env.SUPABASE_SECRET_KEY = prevSecretKey;
      }
      setLinkRepositoryForTests(repo);
    }
  });

  it("computes exact Circular Reveal radius to cover the entire viewport from any click/tap point", () => {
    // Origin at top-left (0, 0) on a 300x400 viewport -> farthest corner is (300, 400) -> radius = 500
    assert.equal(computeMaxRevealRadius(0, 0, 300, 400), 500);

    // Origin near bottom-center footer on mobile (195, 800) on 390x844 viewport
    const mobileRadius = computeMaxRevealRadius(195, 800, 390, 844);
    assert.ok(mobileRadius > 800);
    assert.equal(mobileRadius, Math.hypot(195, 800));

    // Origin near bottom-right on desktop (1400, 860) on 1440x900 viewport
    const desktopRadius = computeMaxRevealRadius(1400, 860, 1440, 900);
    assert.equal(desktopRadius, Math.hypot(1400, 860));

    // Center-viewport origin (720, 450) on 1440x900 viewport for ONCE <-> SEGRETI navigation
    const centerRadius = computeMaxRevealRadius(720, 450, 1440, 900);
    assert.equal(centerRadius, Math.hypot(720, 450));
  });

  it("validates Circular Reveal timings (620ms theme, 850ms page navigation) and click guards", () => {
    assert.equal(CIRCULAR_REVEAL_DURATION_MS, 620);
    assert.equal(PAGE_TRANSITION_DURATION_MS, 850);
    assert.equal(CIRCULAR_REVEAL_EASING, "cubic-bezier(0.22, 1, 0.36, 1)");
    assert.deepEqual(resolveTransitionOrigin({ x: 640, y: 360 }), {
      x: 640,
      y: 360,
    });

    assert.equal(
      isUnmodifiedPrimaryClick({
        button: 0,
        metaKey: false,
        ctrlKey: false,
        shiftKey: false,
        altKey: false,
        defaultPrevented: false,
      }),
      true
    );
    assert.equal(
      isUnmodifiedPrimaryClick({
        button: 0,
        metaKey: true,
        ctrlKey: false,
        shiftKey: false,
        altKey: false,
        defaultPrevented: false,
      }),
      false
    );
    assert.equal(
      isUnmodifiedPrimaryClick({
        button: 1,
        metaKey: false,
        ctrlKey: false,
        shiftKey: false,
        altKey: false,
        defaultPrevented: false,
      }),
      false
    );
  });
});

describe("ONCE — SEGRETI End-to-End Encryption & Atomic Single-Read", () => {
  let secretRepo: AtomicMemorySecretRepository;
  let currentNowMs: number;

  beforeEach(() => {
    currentNowMs = Date.now();
    secretRepo = new AtomicMemorySecretRepository(() => currentNowMs);
    setSecretRepositoryForTests(secretRepo);
  });

  it("encrypts and decrypts secret messages client-side with AES-256-GCM and random 256-bit fragment keys", async () => {
    const plaintext =
      "Chiave API di produzione: sk_live_98a7b6c5d4e3f2g1 — da leggere una sola volta 🔐";
    const bundle = await encryptSecretMessage(plaintext);

    assert.equal(isValidFragmentKey(bundle.fragmentKey), true);
    assert.equal(bundle.passwordProtected, false);
    assert.equal(bundle.kdfSalt, null);
    assert.equal(bundle.kdfIterations, null);
    assert.ok(!bundle.ciphertext.includes("sk_live_"));
    assert.equal(
      parseFragmentKeyFromHash(`#${bundle.fragmentKey}`),
      bundle.fragmentKey
    );

    // Ensure every encryption produces a unique random IV and key
    const second = await encryptSecretMessage(plaintext);
    assert.notEqual(second.fragmentKey, bundle.fragmentKey);
    assert.notEqual(second.iv, bundle.iv);
    assert.notEqual(second.ciphertext, bundle.ciphertext);

    const decrypted = await decryptSecretMessage({
      ciphertext: bundle.ciphertext,
      iv: bundle.iv,
      fragmentKey: bundle.fragmentKey,
      passwordProtected: bundle.passwordProtected,
      kdfSalt: bundle.kdfSalt,
      kdfIterations: bundle.kdfIterations,
    });

    assert.equal(decrypted, plaintext);
  });

  it("derives hybrid key with PBKDF2-SHA-256 + HKDF-SHA-256 when password is provided and rejects wrong or missing passwords", async () => {
    const plaintext =
      "Payload di test riservato: alpha-beta_12345! [Simboli & Caratteri Speciali: #$*+=?~%/{}^]";
    const password = "Correct-Horse-Battery-Staple-99!";

    const bundle = await encryptSecretMessage(plaintext, {
      password,
      kdfIterations: DEFAULT_PBKDF2_ITERATIONS,
    });

    assert.equal(bundle.passwordProtected, true);
    assert.ok(bundle.kdfSalt);
    assert.equal(bundle.kdfIterations, DEFAULT_PBKDF2_ITERATIONS);

    // Missing password must fail with password_required
    await assert.rejects(
      async () => {
        await decryptSecretMessage({
          ciphertext: bundle.ciphertext,
          iv: bundle.iv,
          fragmentKey: bundle.fragmentKey,
          passwordProtected: true,
          kdfSalt: bundle.kdfSalt,
          kdfIterations: bundle.kdfIterations,
        });
      },
      (err: unknown) =>
        err instanceof SecretCryptoError && err.code === "password_required"
    );

    // Wrong password must fail AES-GCM authentication tag verification
    await assert.rejects(
      async () => {
        await decryptSecretMessage({
          ciphertext: bundle.ciphertext,
          iv: bundle.iv,
          fragmentKey: bundle.fragmentKey,
          password: "Wrong-Password-Attempt",
          passwordProtected: true,
          kdfSalt: bundle.kdfSalt,
          kdfIterations: bundle.kdfIterations,
        });
      },
      (err: unknown) =>
        err instanceof SecretCryptoError && err.code === "decryption_failed"
    );

    // Correct password + fragmentKey succeeds
    const decrypted = await decryptSecretMessage({
      ciphertext: bundle.ciphertext,
      iv: bundle.iv,
      fragmentKey: bundle.fragmentKey,
      password,
      passwordProtected: true,
      kdfSalt: bundle.kdfSalt,
      kdfIterations: bundle.kdfIterations,
    });

    assert.equal(decrypted, plaintext);
  });

  it("detects tampering on ciphertext, IV, or AAD metadata and rejects wrong fragment keys", async () => {
    const plaintext = "Messaggio riservato";
    const bundle = await encryptSecretMessage(plaintext, {
      password: "MySecretPassword",
      kdfIterations: 120_000,
    });

    // 1. Tamper with ciphertext bytes
    const rawCiphertext = base64UrlToBytes(bundle.ciphertext);
    rawCiphertext[0] ^= 0xff;
    const tamperedCiphertext = bytesToBase64Url(rawCiphertext);

    await assert.rejects(
      async () =>
        decryptSecretMessage({
          ciphertext: tamperedCiphertext,
          iv: bundle.iv,
          fragmentKey: bundle.fragmentKey,
          password: "MySecretPassword",
          passwordProtected: true,
          kdfSalt: bundle.kdfSalt,
          kdfIterations: bundle.kdfIterations,
        }),
      (err: unknown) =>
        err instanceof SecretCryptoError && err.code === "decryption_failed"
    );

    // 2. Tamper with IV
    const rawIv = base64UrlToBytes(bundle.iv);
    rawIv[0] ^= 0x01;
    const tamperedIv = bytesToBase64Url(rawIv);

    await assert.rejects(
      async () =>
        decryptSecretMessage({
          ciphertext: bundle.ciphertext,
          iv: tamperedIv,
          fragmentKey: bundle.fragmentKey,
          password: "MySecretPassword",
          passwordProtected: true,
          kdfSalt: bundle.kdfSalt,
          kdfIterations: bundle.kdfIterations,
        }),
      (err: unknown) =>
        err instanceof SecretCryptoError && err.code === "decryption_failed"
    );

    // 3. Wrong 256-bit fragment key
    const wrongFragmentKey = bytesToBase64Url(
      globalThis.crypto.getRandomValues(new Uint8Array(32))
    );
    await assert.rejects(
      async () =>
        decryptSecretMessage({
          ciphertext: bundle.ciphertext,
          iv: bundle.iv,
          fragmentKey: wrongFragmentKey,
          password: "MySecretPassword",
          passwordProtected: true,
          kdfSalt: bundle.kdfSalt,
          kdfIterations: bundle.kdfIterations,
        }),
      (err: unknown) =>
        err instanceof SecretCryptoError && err.code === "decryption_failed"
    );

    // 4. Malformed fragment key
    await assert.rejects(
      async () =>
        decryptSecretMessage({
          ciphertext: bundle.ciphertext,
          iv: bundle.iv,
          fragmentKey: "too-short",
          password: "MySecretPassword",
          passwordProtected: true,
          kdfSalt: bundle.kdfSalt,
          kdfIterations: bundle.kdfIterations,
        }),
      (err: unknown) =>
        err instanceof SecretCryptoError && err.code === "invalid_fragment_key"
    );
  });

  it("rejects any API payload that accidentally includes plaintext, password, or fragmentKey", async () => {
    const bundle = await encryptSecretMessage("Top secret");

    assert.equal(
      hasForbiddenSecretFields({
        ciphertext: bundle.ciphertext,
        iv: bundle.iv,
        passwordProtected: false,
        expiration: "24h",
        plaintext: "Top secret",
      }),
      true
    );

    const badRequest = new NextRequest("http://localhost:3000/api/secrets", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-forwarded-for": "198.51.100.77",
      },
      body: JSON.stringify({
        ciphertext: bundle.ciphertext,
        iv: bundle.iv,
        passwordProtected: false,
        kdfSalt: null,
        kdfIterations: null,
        expiration: "24h",
        fragmentKey: bundle.fragmentKey, // Forbidden field!
      }),
    });

    const response = await createSecretPostHandler(badRequest);
    assert.equal(response.status, 400);
    const body = (await response.json()) as { errorCode: string };
    assert.equal(body.errorCode, "forbidden_plaintext_or_key_field");
  });

  it("creates, checks metadata without consuming, and atomically consumes a secret once via Route Handlers", async () => {
    const plaintext = "Codice di recupero: 4419-8821-0092";
    const bundle = await encryptSecretMessage(plaintext, {
      password: "VaultPassword!",
      kdfIterations: 100_000,
    });

    // 1. Create secret via POST /api/secrets
    const createReq = new NextRequest("http://localhost:3000/api/secrets", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-forwarded-for": "203.0.113.10",
      },
      body: JSON.stringify({
        ciphertext: bundle.ciphertext,
        iv: bundle.iv,
        passwordProtected: bundle.passwordProtected,
        kdfSalt: bundle.kdfSalt,
        kdfIterations: bundle.kdfIterations,
        expiration: "1h",
      }),
    });

    const createRes = await createSecretPostHandler(createReq);
    assert.equal(createRes.status, 201);
    const createJson = (await createRes.json()) as {
      secret: {
        token: string;
        expiresAt: string;
        passwordProtected: boolean;
        createdAt: string;
      };
    };
    const created = createJson.secret;
    assert.ok(created.token.length >= 16);
    assert.equal(created.passwordProtected, true);

    // Verify stored row in repository has only ciphertext and not plaintext
    const rawRowBefore = secretRepo.inspectStoredRowForTests(created.token);
    assert.ok(rawRowBefore);
    assert.equal(rawRowBefore.ciphertext, bundle.ciphertext);
    assert.ok(!rawRowBefore.ciphertext.includes("4419-8821-0092"));
    assert.equal(rawRowBefore.is_consumed, false);

    // 2. Check metadata multiple times via GET /api/secrets/[token] -> must NOT consume
    for (let i = 0; i < 3; i++) {
      const metaReq = new NextRequest(
        `http://localhost:3000/api/secrets/${created.token}`,
        { method: "GET" }
      );
      const metaRes = await getSecretMetadataGetHandler(metaReq, {
        params: Promise.resolve({ token: created.token }),
      });
      assert.equal(metaRes.status, 200);
      const metaBody = (await metaRes.json()) as {
        metadata: {
          status: string;
          passwordProtected: boolean;
        };
      };
      assert.equal(metaBody.metadata.status, "available");
      assert.equal(metaBody.metadata.passwordProtected, true);
    }

    assert.equal(
      secretRepo.inspectStoredRowForTests(created.token)?.is_consumed,
      false
    );

    // 3. Prefetch or bot request to POST /api/secrets/[token]/consume must be rejected without consuming
    const botConsumeReq = new NextRequest(
      `http://localhost:3000/api/secrets/${created.token}/consume`,
      {
        method: "POST",
        headers: {
          "user-agent": "TelegramBot (like TwitterBot)",
          "x-once-consume-intent": "1",
        },
      }
    );
    const botConsumeRes = await consumeSecretPostHandler(botConsumeReq, {
      params: Promise.resolve({ token: created.token }),
    });
    assert.equal(botConsumeRes.status, 400);
    assert.equal(
      secretRepo.inspectStoredRowForTests(created.token)?.is_consumed,
      false
    );

    // Missing X-Once-Consume-Intent header must also be rejected without consuming
    const missingHeaderReq = new NextRequest(
      `http://localhost:3000/api/secrets/${created.token}/consume`,
      {
        method: "POST",
        headers: {
          "user-agent": "Mozilla/5.0",
        },
      }
    );
    const missingHeaderRes = await consumeSecretPostHandler(missingHeaderReq, {
      params: Promise.resolve({ token: created.token }),
    });
    assert.equal(missingHeaderRes.status, 400);
    assert.equal(
      secretRepo.inspectStoredRowForTests(created.token)?.is_consumed,
      false
    );

    // 4. Legitimate user consumption via POST /api/secrets/[token]/consume
    const consumeReq = new NextRequest(
      `http://localhost:3000/api/secrets/${created.token}/consume`,
      {
        method: "POST",
        headers: {
          "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
          "x-once-consume-intent": "1",
          "x-forwarded-for": "203.0.113.25",
        },
      }
    );
    const consumeRes = await consumeSecretPostHandler(consumeReq, {
      params: Promise.resolve({ token: created.token }),
    });
    assert.equal(consumeRes.status, 200);
    const consumeJson = (await consumeRes.json()) as {
      result: {
        status: string;
        ciphertext: string;
        iv: string;
        passwordProtected: boolean;
        kdfSalt: string | null;
        kdfIterations: number | null;
      };
    };
    const consumedPayload = consumeJson.result;
    assert.equal(consumedPayload.status, "valid");
    assert.equal(consumedPayload.ciphertext, bundle.ciphertext);

    // Verify stored row is marked consumed and ciphertext is scrubbed in storage
    const rawRowAfter = secretRepo.inspectStoredRowForTests(created.token);
    assert.equal(rawRowAfter?.is_consumed, true);
    assert.equal(rawRowAfter?.ciphertext, "[CONSUMED]");
    assert.ok(rawRowAfter?.consumed_at);

    // Client decrypts the returned ciphertext
    const decrypted = await decryptSecretMessage({
      ciphertext: consumedPayload.ciphertext,
      iv: consumedPayload.iv,
      fragmentKey: bundle.fragmentKey,
      password: "VaultPassword!",
      passwordProtected: consumedPayload.passwordProtected,
      kdfSalt: consumedPayload.kdfSalt,
      kdfIterations: consumedPayload.kdfIterations,
    });
    assert.equal(decrypted, plaintext);

    // 5. Second consumption attempt must return 410 Gone with no ciphertext
    const secondConsumeRes = await consumeSecretPostHandler(consumeReq, {
      params: Promise.resolve({ token: created.token }),
    });
    assert.equal(secondConsumeRes.status, 410);
    const secondBody = (await secondConsumeRes.json()) as {
      result: {
        status: string;
        ciphertext: string | null;
      };
    };
    assert.equal(secondBody.result.status, "consumed");
    assert.equal(secondBody.result.ciphertext, null);
  });

  it("enforces time-based expiration on secrets for both metadata checks and consumption", async () => {
    const bundle = await encryptSecretMessage("Segreto a tempo");

    const createResult = await createEncryptedSecret(
      {
        ciphertext: bundle.ciphertext,
        iv: bundle.iv,
        passwordProtected: bundle.passwordProtected,
        kdfSalt: bundle.kdfSalt,
        kdfIterations: bundle.kdfIterations,
        expiration: "15m",
      },
      { clientIp: "203.0.113.50" }
    );
    assert.equal(createResult.ok, true);
    if (!createResult.ok) return;

    // Fast-forward clock by 16 minutes
    currentNowMs += 16 * 60 * 1000;

    const meta = await checkSecretMetadata(createResult.secret.token);
    assert.equal(meta.ok, true);
    if (meta.ok) {
      assert.equal(meta.metadata.status, "expired");
    }

    const consumed = await consumeEncryptedSecret(createResult.secret.token, {
      clientIp: "203.0.113.51",
    });
    assert.equal(consumed.ok, true);
    if (consumed.ok) {
      assert.equal(consumed.result.status, "expired");
      assert.equal(consumed.result.ciphertext, null);
    }
  });

  it("guarantees atomic single-read under 25 concurrent consumption requests", async () => {
    const bundle = await encryptSecretMessage("Concurrency test secret payload");

    const created = await createEncryptedSecret(
      {
        ciphertext: bundle.ciphertext,
        iv: bundle.iv,
        passwordProtected: bundle.passwordProtected,
        kdfSalt: bundle.kdfSalt,
        kdfIterations: bundle.kdfIterations,
        expiration: "24h",
      },
      { clientIp: "198.51.100.1" }
    );
    assert.equal(created.ok, true);
    if (!created.ok) return;

    const token = created.secret.token;

    // Fire 25 concurrent consumption requests from distinct client IPs
    const results = await Promise.all(
      Array.from({ length: 25 }, (_, idx) =>
        consumeEncryptedSecret(token, { clientIp: `198.51.100.${idx + 10}` })
      )
    );

    const validReads = results.filter(
      (r) => r.ok && r.result.status === "valid"
    );
    const consumedReads = results.filter(
      (r) => r.ok && r.result.status === "consumed"
    );

    assert.equal(
      validReads.length,
      1,
      "Exactly one concurrent reader may obtain the ciphertext"
    );
    assert.equal(
      consumedReads.length,
      24,
      "All other 24 concurrent readers must receive consumed status"
    );

    if (validReads[0]?.ok) {
      assert.equal(validReads[0].result.ciphertext, bundle.ciphertext);
    }
    for (const r of consumedReads) {
      if (r.ok) {
        assert.equal(r.result.ciphertext, null);
      }
    }
  });

  it("enforces rate limiting on both secret creation and secret consumption", async () => {
    const bundle = await encryptSecretMessage("Rate limit secret");
    const clientIp = "192.0.2.99";

    for (let i = 0; i < SECRET_CREATE_RATE_LIMIT_MAX; i++) {
      const res = await createEncryptedSecret(
        {
          ciphertext: bundle.ciphertext,
          iv: bundle.iv,
          passwordProtected: bundle.passwordProtected,
          kdfSalt: bundle.kdfSalt,
          kdfIterations: bundle.kdfIterations,
          expiration: "1h",
        },
        { clientIp }
      );
      assert.equal(res.ok, true);
    }

    const blockedCreate = await createEncryptedSecret(
      {
        ciphertext: bundle.ciphertext,
        iv: bundle.iv,
        passwordProtected: bundle.passwordProtected,
        kdfSalt: bundle.kdfSalt,
        kdfIterations: bundle.kdfIterations,
        expiration: "1h",
      },
      { clientIp }
    );
    assert.equal(blockedCreate.ok, false);
    if (!blockedCreate.ok) {
      assert.equal(blockedCreate.errorCode, "rate_limited");
    }

    // Consumption rate limit check
    const consumeIp = "192.0.2.100";
    for (let i = 0; i < SECRET_CONSUME_RATE_LIMIT_MAX; i++) {
      const res = await consumeEncryptedSecret("nonexistenttoken1234", {
        clientIp: consumeIp,
      });
      assert.equal(res.ok, true);
    }

    const blockedConsume = await consumeEncryptedSecret(
      "nonexistenttoken1234",
      { clientIp: consumeIp }
    );
    assert.equal(blockedConsume.ok, false);
    if (!blockedConsume.ok) {
      assert.equal(blockedConsume.errorCode, "rate_limited");
    }
  });

  it("detects prefetch headers and link preview bots accurately", () => {
    const nextPrefetchReq = new Request("https://once.sh/api/secrets/abc/consume", {
      method: "POST",
      headers: {
        "next-router-prefetch": "1",
      },
    });
    assert.equal(isPrefetchOrPreviewBotRequest(nextPrefetchReq.headers), true);

    const whatsappBotReq = new Request("https://once.sh/api/secrets/abc/consume", {
      method: "POST",
      headers: {
        "user-agent": "WhatsApp/2.23.20.0",
      },
    });
    assert.equal(isPrefetchOrPreviewBotRequest(whatsappBotReq.headers), true);

    const normalBrowserReq = new Request("https://once.sh/api/secrets/abc/consume", {
      method: "POST",
      headers: {
        "user-agent":
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
      },
    });
    assert.equal(isPrefetchOrPreviewBotRequest(normalBrowserReq.headers), false);
  });

  it("delegates SupabaseSecretRepository calls to get_secret_metadata, consume_secret, and check_rate_limit RPCs", async () => {
    const rpcCalls: Array<{ fn: string; args: Record<string, unknown> }> = [];

    const mockSupabase = {
      from(table: string) {
        assert.equal(table, "secrets");
        return {
          insert(payload: Record<string, unknown>) {
            return {
              select() {
                return {
                  async single() {
                    return {
                      data: {
                        token: payload.token as string,
                        expires_at: payload.expires_at as string,
                        password_protected: payload.password_protected as boolean,
                        created_at: "2026-11-07T16:00:00.000Z",
                      },
                      error: null,
                    };
                  },
                };
              },
            };
          },
        };
      },
      async rpc(fn: string, args: Record<string, unknown>) {
        rpcCalls.push({ fn, args });
        if (fn === "get_secret_metadata") {
          return {
            data: [
              {
                status: "available",
                password_protected: true,
                expires_at: "2026-11-08T16:00:00.000Z",
              },
            ],
            error: null,
          };
        }
        if (fn === "consume_secret") {
          return {
            data: [
              {
                status: "valid",
                ciphertext: "mockCiphertextBase64Url",
                iv: "mockIvBase64Url",
                password_protected: true,
                kdf_salt: "mockSaltBase64Url",
                kdf_iterations: 600000,
                expires_at: "2026-11-08T16:00:00.000Z",
                consumed_at: "2026-11-07T16:05:00.000Z",
              },
            ],
            error: null,
          };
        }
        if (fn === "check_rate_limit") {
          return {
            data: [
              {
                allowed: true,
                current_count: 1,
                reset_at: "2026-11-07T16:01:00.000Z",
              },
            ],
            error: null,
          };
        }
        throw new Error(`Unexpected RPC: ${fn}`);
      },
    } as unknown as SupabaseClient;

    const supaSecretRepo = new SupabaseSecretRepository(mockSupabase);

    const rl = await supaSecretRepo.checkRateLimit("secret:ip", 20, 60);
    assert.equal(rl.allowed, true);

    const meta = await supaSecretRepo.getSecretMetadata("tok_1234567890abcdef");
    assert.equal(meta.status, "available");
    assert.equal(meta.passwordProtected, true);

    const consumed = await supaSecretRepo.consumeSecret("tok_1234567890abcdef");
    assert.equal(consumed.status, "valid");
    assert.equal(consumed.ciphertext, "mockCiphertextBase64Url");
    assert.equal(consumed.kdfIterations, 600000);

    assert.equal(rpcCalls.length, 3);
    assert.equal(rpcCalls[0]?.fn, "check_rate_limit");
    assert.equal(rpcCalls[1]?.fn, "get_secret_metadata");
    assert.equal(rpcCalls[2]?.fn, "consume_secret");
  });

  it("handles post-consumption wrong-password retry in memory while server copy stays permanently burned, and handles repository errors cleanly", async () => {
    const plaintext = "Messaggio unico con password";
    const bundle = await encryptSecretMessage(plaintext, {
      password: "RightPassword123",
      kdfIterations: 100_000,
    });

    const created = await createEncryptedSecret(
      {
        ciphertext: bundle.ciphertext,
        iv: bundle.iv,
        passwordProtected: true,
        kdfSalt: bundle.kdfSalt,
        kdfIterations: bundle.kdfIterations,
        expiration: "1h",
      },
      { clientIp: "198.51.100.200" }
    );
    assert.equal(created.ok, true);
    if (!created.ok) return;

    // 1. Recipient clicks "Mostra segreto" -> server consumes atomically
    const consumeOutcome = await consumeEncryptedSecret(created.secret.token, {
      clientIp: "198.51.100.201",
    });
    assert.equal(consumeOutcome.ok, true);
    if (!consumeOutcome.ok) return;
    const inMemoryBundle = consumeOutcome.result;
    assert.equal(inMemoryBundle.status, "valid");

    // 2. Server copy is now permanently burned; any reload or second request returns "consumed"
    const secondServerAttempt = await consumeEncryptedSecret(
      created.secret.token,
      { clientIp: "198.51.100.201" }
    );
    assert.equal(secondServerAttempt.ok, true);
    if (secondServerAttempt.ok) {
      assert.equal(secondServerAttempt.result.status, "consumed");
      assert.equal(secondServerAttempt.result.ciphertext, null);
    }

    // 3. Recipient typed wrong password initially -> local AES-GCM decryption fails
    await assert.rejects(
      async () =>
        decryptSecretMessage({
          ciphertext: inMemoryBundle.ciphertext!,
          iv: inMemoryBundle.iv!,
          fragmentKey: bundle.fragmentKey,
          password: "WrongPasswordFirstTry",
          passwordProtected: inMemoryBundle.passwordProtected,
          kdfSalt: inMemoryBundle.kdfSalt,
          kdfIterations: inMemoryBundle.kdfIterations,
        }),
      (err: unknown) =>
        err instanceof SecretCryptoError && err.code === "decryption_failed"
    );

    // 4. Without reloading the page, recipient retries with the right password against in-memory ciphertext
    const recoveredPlaintext = await decryptSecretMessage({
      ciphertext: inMemoryBundle.ciphertext!,
      iv: inMemoryBundle.iv!,
      fragmentKey: bundle.fragmentKey,
      password: "RightPassword123",
      passwordProtected: inMemoryBundle.passwordProtected,
      kdfSalt: inMemoryBundle.kdfSalt,
      kdfIterations: inMemoryBundle.kdfIterations,
    });
    assert.equal(recoveredPlaintext, plaintext);

    // 5. Simulate database/network failure during consumption -> returns 500 server_error
    const failingRepo = {
      async insertSecret() {
        throw new Error("DB connection lost");
      },
      async getSecretMetadata() {
        throw new Error("DB connection lost");
      },
      async consumeSecret() {
        throw new Error("Network drop after request");
      },
      async checkRateLimit() {
        return {
          allowed: true,
          currentCount: 1,
          resetAt: new Date(Date.now() + 60_000).toISOString(),
        };
      },
    };

    const failedConsume = await consumeEncryptedSecret(created.secret.token, {
      clientIp: "198.51.100.202",
      repository: failingRepo,
    });
    assert.equal(failedConsume.ok, false);
    if (!failedConsume.ok) {
      assert.equal(failedConsume.status, 500);
      assert.equal(failedConsume.errorCode, "server_error");
    }
  });
});

describe("ONCE — Security Fixes: Link Preview Bots, Trusted IP & Password Strength", () => {
  let linkRepo: AtomicMemoryLinkRepository;

  beforeEach(() => {
    linkRepo = new AtomicMemoryLinkRepository();
    setLinkRepositoryForTests(linkRepo);
  });

  it("protects single-use links from premature consumption by preview bots (WhatsApp, Telegram, Slack, Discord, Twitter, Facebook, LinkedIn)", async () => {
    // 1. Create a link with max_views = 1
    const createRes = await createOnceLink(
      {
        destinationUrl: "https://example.com/target",
        maxViews: 1,
        expiration: "24h",
      },
      {
        clientIp: "203.0.113.1",
        appBaseUrl: "https://once.sh",
      }
    );
    assert.equal(createRes.ok, true);
    if (!createRes.ok) return;
    const slug = createRes.link.slug;

    // 2. Simulate preview bot User-Agents hitting the link
    const previewBotAgents = [
      "WhatsApp/2.23.20.0 A",
      "TelegramBot (like TwitterBot)",
      "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
      "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
      "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
      "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)",
      "Twitterbot/1.0",
    ];

    for (const botAgent of previewBotAgents) {
      const botHeaders = new Headers({ "user-agent": botAgent });
      assert.equal(
        isPreviewBotUserAgent(botAgent),
        true,
        `Expected ${botAgent} to be detected as a preview bot`
      );
      assert.equal(
        isPrefetchOrPreviewBotRequest(botHeaders),
        true,
        `Expected bot headers to match isPrefetchOrPreviewBotRequest`
      );
    }

    // Because the bot is detected, the link route bypasses consumeOnceLink.
    // Verify that the link still has 0 views and has NOT been consumed.
    const rowBeforeHuman = linkRepo.inspectStoredRowForTests(slug);
    assert.equal(rowBeforeHuman?.views_count, 0);

    // 3. Now simulate the actual human recipient clicking the link from a standard browser
    const humanHeaders = new Headers({
      "user-agent":
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    });
    assert.equal(
      isPrefetchOrPreviewBotRequest(humanHeaders),
      false,
      "Real human browser must not be flagged as bot or prefetch"
    );

    // Real human visit consumes the single view
    const humanResult = await consumeOnceLink(slug);
    assert.equal(humanResult.status, "valid");
    assert.equal(humanResult.destinationUrl, "https://example.com/target");
    assert.equal(humanResult.viewsCount, 1);

    // Subsequent human visit is now max_views_reached
    const secondVisit = await consumeOnceLink(slug);
    assert.equal(secondVisit.status, "max_views_reached");
  });

  it("rejects attempt to register reserved slug 'secrets' via POST /api/links", async () => {
    const req = new NextRequest("https://once.sh/api/links", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-vercel-ip": "203.0.113.15",
      },
      body: JSON.stringify({
        destinationUrl: "https://example.com",
        customSlug: "secrets",
      }),
    });

    const res = await createLinkPostHandler(req);
    assert.equal(res.status, 400);
    const body = (await res.json()) as { errorCode: string };
    assert.equal(body.errorCode, "slug_reserved");
  });

  it("extracts trusted client IP and prevents header spoofing across Vercel, Cloudflare, and proxy environments", () => {
    // 1. Vercel edge authoritative header overrides attacker's spoofed X-Forwarded-For
    const vercelReq = new Headers({
      "x-forwarded-for": "1.2.3.4, 5.6.7.8",
      "x-vercel-ip": "203.0.113.90",
    });
    assert.equal(extractClientIp(vercelReq), "203.0.113.90");

    // 2. Cloudflare connecting IP overrides attacker's spoofed X-Forwarded-For
    const cfReq = new Headers({
      "x-forwarded-for": "1.2.3.4",
      "cf-connecting-ip": "198.51.100.42",
    });
    assert.equal(extractClientIp(cfReq), "198.51.100.42");

    // 3. X-Real-IP reverse proxy header overrides attacker's spoofed X-Forwarded-For
    const realIpReq = new Headers({
      "x-forwarded-for": "1.2.3.4",
      "x-real-ip": "198.51.100.55",
    });
    assert.equal(extractClientIp(realIpReq), "198.51.100.55");

    // 4. In pure X-Forwarded-For proxy chain, rightmost valid IP is taken (appended by edge)
    const multiHopReq = new Headers({
      "x-forwarded-for": "10.0.0.1, 172.16.0.1, 203.0.113.195",
    });
    assert.equal(extractClientIp(multiHopReq), "203.0.113.195");

    // 5. Malformed or script injection headers are safely rejected to 127.0.0.1
    const xssReq = new Headers({
      "x-forwarded-for": "<script>alert(1)</script>",
    });
    assert.equal(extractClientIp(xssReq), "127.0.0.1");

    // 6. Validates IPv4 and IPv6 syntax helper
    assert.equal(isValidIp("203.0.113.1"), true);
    assert.equal(isValidIp("::1"), true);
    assert.equal(isValidIp("2001:db8::1"), true);
    assert.equal(isValidIp("999.999.999.999"), false);
    assert.equal(isValidIp("invalid-ip-string"), false);
  });

  it("evaluates secret password strength accurately and enforces minimum 8 characters length", () => {
    assert.equal(MIN_SECRET_PASSWORD_LENGTH, 8);

    // Below 8 characters is always too_short
    assert.equal(evaluatePasswordStrength(""), "too_short");
    assert.equal(evaluatePasswordStrength("abc"), "too_short");
    assert.equal(evaluatePasswordStrength("1234567"), "too_short");

    // 8+ characters with low variety is medium
    assert.equal(evaluatePasswordStrength("password"), "medium");
    assert.equal(evaluatePasswordStrength("12345678"), "medium");
    assert.equal(evaluatePasswordStrength("abcdefgh"), "medium");

    // 8+ characters with variety (mixed case, numbers, symbols) or 12+ length is strong
    assert.equal(evaluatePasswordStrength("Passw0rd"), "strong");
    assert.equal(evaluatePasswordStrength("Secret-Key!9"), "strong");
    assert.equal(evaluatePasswordStrength("longpassphrasehere"), "strong");
  });
});
