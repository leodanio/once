import type { ExpirationPreset } from "@/types/link";

export const MAX_URL_LENGTH = 2048;
export const MAX_CUSTOM_MESSAGE_LENGTH = 140;
export const MIN_SLUG_LENGTH = 3;
export const MAX_SLUG_LENGTH = 32;
export const MIN_MAX_VIEWS = 1;
export const MAX_MAX_VIEWS = 1000;
export const DEFAULT_RANDOM_SLUG_LENGTH = 7;

const SLUG_REGEX = /^[a-zA-Z0-9-_]{3,32}$/;

export const RESERVED_SLUGS = new Set([
  "api",
  "about",
  "_next",
  "favicon.ico",
  "robots.txt",
  "sitemap.xml",
  "static",
  "public",
  "admin",
  "health",
  "status",
  "secrets",
  "secret",
  "link",
  "links",
  "files",
  "file",
  "edulink",
  "terms",
  "privacy",
  "auth",
  "login",
  "signin",
  "signup",
  "settings",
  "app",
]);

const VALID_EXPIRATION_PRESETS = new Set<ExpirationPreset>([
  "never",
  "15m",
  "1h",
  "24h",
  "7d",
]);

export type UrlValidationErrorCode =
  | "empty"
  | "url_too_long"
  | "spaces"
  | "protocol"
  | "domain"
  | "self_redirect"
  | "invalid_url";

export type SlugValidationErrorCode =
  | "slug_short"
  | "slug_long"
  | "slug_invalid"
  | "slug_reserved"
  | "slug_taken";

export interface UrlValidationResult {
  isValid: boolean;
  normalizedUrl?: string;
  errorCode?: UrlValidationErrorCode;
}

/**
 * Validates and normalizes a user-entered destination URL.
 * - Enforces MAX_URL_LENGTH (2048)
 * - Allows only HTTP and HTTPS protocols
 * - Rejects malformed URLs, embedded credentials (open-redirect phishing), backslashes, and control chars
 * - Prevents self-redirect loops when appBaseUrl is provided
 */
export function validateDestinationUrl(
  rawInput: string,
  appBaseUrl?: string
): UrlValidationResult {
  if (typeof rawInput !== "string") {
    return { isValid: false, errorCode: "invalid_url" };
  }

  const trimmed = rawInput.trim();

  if (!trimmed) {
    return {
      isValid: false,
      errorCode: "empty",
    };
  }

  if (trimmed.length > MAX_URL_LENGTH) {
    return {
      isValid: false,
      errorCode: "url_too_long",
    };
  }

  // Reject whitespace or ASCII control characters
  if (/\s/.test(trimmed) || /[\x00-\x1F\x7F]/.test(trimmed)) {
    return {
      isValid: false,
      errorCode: "spaces",
    };
  }

  // Reject backslashes in authority/scheme to prevent parser-differential open redirects
  const authorityCandidate = trimmed.split(/[?#]/)[0] ?? "";
  if (authorityCandidate.includes("\\")) {
    return {
      isValid: false,
      errorCode: "invalid_url",
    };
  }

  // Check if input specifies an explicit URI scheme (e.g. "javascript:", "ftp://", "data:", "mailto:")
  const explicitSchemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$/);
  if (explicitSchemeMatch) {
    const scheme = explicitSchemeMatch[1].toLowerCase();
    const rest = explicitSchemeMatch[2];
    const isLocalhostWithPort =
      scheme === "localhost" && /^\d+(\/.*)?$/.test(rest);

    if (!isLocalhostWithPort && scheme !== "http" && scheme !== "https") {
      return {
        isValid: false,
        errorCode: "protocol",
      };
    }

    // If scheme is http or https, require "//" after colon (reject "http:example.com" relative ambiguity)
    if (
      (scheme === "http" || scheme === "https") &&
      !rest.startsWith("//")
    ) {
      return {
        isValid: false,
        errorCode: "invalid_url",
      };
    }
  }

  const withProtocol = /^https?:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  try {
    const parsed = new URL(withProtocol);

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return {
        isValid: false,
        errorCode: "protocol",
      };
    }

    // Reject embedded credentials (e.g., https://trusted.com@attacker.com)
    if (parsed.username || parsed.password) {
      return {
        isValid: false,
        errorCode: "invalid_url",
      };
    }

    const hostname = parsed.hostname.toLowerCase();
    const isLocalhost = hostname === "localhost";
    const labels = hostname.split(".");
    const tld = labels[labels.length - 1] ?? "";
    const hasValidDomain =
      hostname.includes(".") &&
      !hostname.startsWith(".") &&
      !hostname.endsWith(".") &&
      labels.every(
        (part) =>
          part.length > 0 &&
          part.length <= 63 &&
          /^[a-z0-9-]+$/i.test(part) &&
          !part.startsWith("-") &&
          !part.endsWith("-")
      ) &&
      tld.length >= 2 &&
      !/^\d+$/.test(tld);

    if (!isLocalhost && !hasValidDomain) {
      return {
        isValid: false,
        errorCode: "domain",
      };
    }

    // Prevent self-redirect loops if appBaseUrl is known
    const effectiveAppUrl =
      appBaseUrl ??
      (typeof process !== "undefined"
        ? process.env.NEXT_PUBLIC_APP_URL
        : undefined);

    if (effectiveAppUrl) {
      try {
        const appParsed = new URL(effectiveAppUrl);
        if (
          parsed.host.toLowerCase() === appParsed.host.toLowerCase() &&
          parsed.hostname.toLowerCase() !== "localhost"
        ) {
          return {
            isValid: false,
            errorCode: "self_redirect",
          };
        }
      } catch {
        // Ignore invalid NEXT_PUBLIC_APP_URL when checking self-redirect
      }
    }

    return {
      isValid: true,
      normalizedUrl: parsed.toString(),
    };
  } catch {
    return {
      isValid: false,
      errorCode: "invalid_url",
    };
  }
}

/**
 * Validates an optional custom slug.
 */
export function validateCustomSlug(slug: string): {
  isValid: boolean;
  normalizedSlug?: string;
  errorCode?: SlugValidationErrorCode;
} {
  if (typeof slug !== "string") {
    return { isValid: false, errorCode: "slug_invalid" };
  }

  const trimmed = slug.trim();
  if (!trimmed) {
    return { isValid: true, normalizedSlug: "" };
  }

  if (trimmed.length < MIN_SLUG_LENGTH) {
    return {
      isValid: false,
      errorCode: "slug_short",
    };
  }

  if (trimmed.length > MAX_SLUG_LENGTH) {
    return {
      isValid: false,
      errorCode: "slug_long",
    };
  }

  if (!SLUG_REGEX.test(trimmed)) {
    return {
      isValid: false,
      errorCode: "slug_invalid",
    };
  }

  if (RESERVED_SLUGS.has(trimmed.toLowerCase())) {
    return {
      isValid: false,
      errorCode: "slug_reserved",
    };
  }

  return { isValid: true, normalizedSlug: trimmed };
}

/**
 * Validates that a slug from a URL route parameter is syntactically valid before querying DB.
 */
export function isValidSlugParam(slug: string): boolean {
  if (!slug || typeof slug !== "string") return false;
  return SLUG_REGEX.test(slug) && !RESERVED_SLUGS.has(slug.toLowerCase());
}

/**
 * Validates expiration preset.
 */
export function isValidExpirationPreset(
  value: unknown
): value is ExpirationPreset {
  return (
    typeof value === "string" &&
    VALID_EXPIRATION_PRESETS.has(value as ExpirationPreset)
  );
}

/**
 * Sanitizes and validates custom expired message.
 */
export function validateCustomMessage(message: unknown): {
  isValid: boolean;
  sanitized: string | null;
} {
  if (message === undefined || message === null || message === "") {
    return { isValid: true, sanitized: null };
  }
  if (typeof message !== "string") {
    return { isValid: false, sanitized: null };
  }
  const cleaned = message.replace(/[\x00-\x1F\x7F]/g, "").trim();
  if (cleaned.length > MAX_CUSTOM_MESSAGE_LENGTH) {
    return { isValid: false, sanitized: null };
  }
  return {
    isValid: true,
    sanitized: cleaned.length > 0 ? cleaned : null,
  };
}

/**
 * Extracts a clean hostname from a valid URL string.
 */
export function getDestinationHostname(urlString: string): string {
  try {
    const parsed = new URL(urlString);
    return parsed.hostname.replace(/^www\./i, "");
  } catch {
    return urlString;
  }
}

/**
 * Generates a cryptographically secure random alphanumeric slug using Web Crypto API.
 * Uses rejection sampling to eliminate modulo bias.
 */
export function generateRandomSlug(
  length: number = DEFAULT_RANDOM_SLUG_LENGTH
): string {
  const alphabet =
    "23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
  const alphabetLen = alphabet.length; // 55 characters
  // Largest multiple of 55 <= 256 is 220 (55 * 4)
  const maxUnbiasedByte = 220;

  let result = "";
  const buffer = new Uint8Array(length * 2);

  while (result.length < length) {
    globalThis.crypto.getRandomValues(buffer);
    for (let i = 0; i < buffer.length && result.length < length; i++) {
      const byte = buffer[i];
      if (byte < maxUnbiasedByte) {
        result += alphabet[byte % alphabetLen];
      }
    }
  }

  return result;
}

/**
 * Computes an ISO expiration timestamp from a preset.
 */
export function computeExpirationDate(
  preset: ExpirationPreset,
  nowMs: number = Date.now()
): string | null {
  switch (preset) {
    case "15m":
      return new Date(nowMs + 15 * 60 * 1000).toISOString();
    case "1h":
      return new Date(nowMs + 60 * 60 * 1000).toISOString();
    case "24h":
      return new Date(nowMs + 24 * 60 * 60 * 1000).toISOString();
    case "7d":
      return new Date(nowMs + 7 * 24 * 60 * 60 * 1000).toISOString();
    case "never":
    default:
      return null;
  }
}
