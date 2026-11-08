/**
 * ONCE — End-to-End Zero-Knowledge Cryptography for Secrets
 *
 * Security Architecture:
 * 1. Every secret generates a fresh 256-bit (32-byte) random master key (`fragmentKey`)
 *    via CSPRNG (`crypto.getRandomValues`) and a fresh 96-bit (12-byte) random IV.
 * 2. `fragmentKey` is placed exclusively in the URL fragment (`#...`), which browsers
 *    never transmit in HTTP requests or `Referer` headers.
 * 3. Without a password:
 *    - `fragmentKey` is imported into HKDF-SHA-256 with domain separation
 *      (`"once-secret-v1:direct"`) to derive a 256-bit AES-GCM content encryption key.
 * 4. With an optional password:
 *    - The password is normalized (`NFKC`) and stretched with PBKDF2-HMAC-SHA-256
 *      using a fresh 128-bit (16-byte) random salt and 600,000 iterations to produce
 *      256 bits of password-derived key material (`pwdKeyBytes`).
 *    - `fragmentKey` (32 bytes) and `pwdKeyBytes` (32 bytes) are concatenated into a
 *      64-byte IKM and passed through HKDF-SHA-256 (`salt = kdfSalt`,
 *      `info = "once-secret-v1:hybrid-pbkdf2-hkdf"`) to derive the final 256-bit
 *      AES-GCM key.
 * 5. Metadata (`version`, `passwordProtected`, `kdfSalt`, `kdfIterations`) is bound as
 *    Additional Authenticated Data (AAD) in AES-256-GCM so any tampering with KDF
 *    parameters or flags causes authentication tag verification to fail.
 *
 * Security Limitations (Documented):
 * - Database-only compromise: Because the 256-bit `fragmentKey` is never sent to the
 *   server, an attacker who compromises only the database cannot mount an offline
 *   brute-force attack even if the user chose a weak password.
 * - Full-link + ciphertext compromise: If an attacker obtains BOTH the full URL
 *   (including `#fragmentKey`) AND consumes the ciphertext, a weak user password is
 *   subject to offline dictionary attacks at a cost of 600,000 PBKDF2-SHA-256
 *   iterations per guess.
 */

import type { EncryptedSecretBundle } from "@/types/secret";

export const SECRET_CRYPTO_VERSION = 1;
export const FRAGMENT_KEY_BYTE_LENGTH = 32; // 256 bits
export const AES_GCM_IV_BYTE_LENGTH = 12; // 96 bits
export const AES_GCM_TAG_BIT_LENGTH = 128; // 128-bit authentication tag
export const PBKDF2_SALT_BYTE_LENGTH = 16; // 128 bits
export const DEFAULT_PBKDF2_ITERATIONS = 600_000;
export const MIN_PBKDF2_ITERATIONS = 100_000;
export const MAX_PBKDF2_ITERATIONS = 1_000_000;
export const MAX_SECRET_PLAINTEXT_CHARS = 4000;
export const MIN_SECRET_PASSWORD_LENGTH = 8;

/**
 * Evaluates secret password strength without altering cryptographic derivation.
 */
export function evaluatePasswordStrength(
  pwd: string
): "too_short" | "medium" | "strong" {
  if (typeof pwd !== "string" || pwd.length < MIN_SECRET_PASSWORD_LENGTH) {
    return "too_short";
  }
  const hasMixedCase = /[a-z]/.test(pwd) && /[A-Z]/.test(pwd);
  const hasNumbers = /\d/.test(pwd);
  const hasSymbols = /[^a-zA-Z0-9]/.test(pwd);
  const varietyCount =
    (hasMixedCase ? 1 : 0) + (hasNumbers ? 1 : 0) + (hasSymbols ? 1 : 0);
  if (pwd.length >= 12 || varietyCount >= 2) return "strong";
  return "medium";
}

const HKDF_INFO_DIRECT = "once-secret-v1:direct";
const HKDF_INFO_HYBRID = "once-secret-v1:hybrid-pbkdf2-hkdf";
const BASE64URL_REGEX = /^[A-Za-z0-9_-]+$/;

export type SecretCryptoErrorCode =
  | "empty_plaintext"
  | "plaintext_too_long"
  | "invalid_fragment_key"
  | "password_required"
  | "invalid_kdf_params"
  | "decryption_failed";

export class SecretCryptoError extends Error {
  readonly code: SecretCryptoErrorCode;

  constructor(code: SecretCryptoErrorCode, message: string) {
    super(message);
    this.name = "SecretCryptoError";
    this.code = code;
  }
}

/**
 * Encodes a Uint8Array into a URL-safe Base64 string without padding.
 */
export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = globalThis.btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/**
 * Decodes a URL-safe Base64 string into a Uint8Array.
 */
export function base64UrlToBytes(input: string): Uint8Array {
  if (typeof input !== "string" || !input.trim() || !BASE64URL_REGEX.test(input)) {
    throw new Error("Invalid base64url string");
  }
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (base64.length % 4)) % 4;
  const padded = base64 + "=".repeat(padLen);
  const binary = globalThis.atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

/**
 * Validates that a base64url string decodes to the expected byte length range.
 */
export function isValidBase64UrlPayload(
  value: unknown,
  minBytes: number,
  maxBytes: number
): value is string {
  if (typeof value !== "string" || !BASE64URL_REGEX.test(value)) {
    return false;
  }
  try {
    const decoded = base64UrlToBytes(value);
    return decoded.byteLength >= minBytes && decoded.byteLength <= maxBytes;
  } catch {
    return false;
  }
}

/**
 * Validates whether a fragment key string is a syntactically valid 256-bit (32-byte) key.
 */
export function isValidFragmentKey(fragmentKey: string): boolean {
  return isValidBase64UrlPayload(
    fragmentKey,
    FRAGMENT_KEY_BYTE_LENGTH,
    FRAGMENT_KEY_BYTE_LENGTH
  );
}

/**
 * Extracts the raw base64url key from a URL hash fragment (e.g. "#abc..." or "abc...").
 */
export function parseFragmentKeyFromHash(hash: string): string | null {
  if (typeof hash !== "string") return null;
  const cleaned = hash.replace(/^#+/, "").trim();
  if (!cleaned) return null;
  return isValidFragmentKey(cleaned) ? cleaned : null;
}

/**
 * Builds Deterministic Additional Authenticated Data (AAD) binding the KDF parameters
 * to the AES-256-GCM authentication tag.
 */
function buildAdditionalAuthenticatedData(params: {
  passwordProtected: boolean;
  kdfSalt: string | null;
  kdfIterations: number | null;
}): Uint8Array<ArrayBuffer> {
  const canonical = JSON.stringify({
    v: SECRET_CRYPTO_VERSION,
    alg: "AES-256-GCM",
    pwd: params.passwordProtected,
    salt: params.passwordProtected ? params.kdfSalt : null,
    iter: params.passwordProtected ? params.kdfIterations : null,
  });
  return new TextEncoder().encode(canonical) as Uint8Array<ArrayBuffer>;
}

/**
 * Derives the 256-bit AES-GCM CryptoKey from the 256-bit fragment key and optional password.
 */
async function deriveAesGcmKey(params: {
  fragmentKeyBytes: Uint8Array;
  password?: string;
  passwordProtected: boolean;
  kdfSaltBytes: Uint8Array | null;
  kdfIterations: number | null;
  keyUsage: KeyUsage[];
}): Promise<CryptoKey> {
  const subtle = globalThis.crypto.subtle;
  const encoder = new TextEncoder();

  if (!params.passwordProtected) {
    const hkdfBaseKey = await subtle.importKey(
      "raw",
      params.fragmentKeyBytes as Uint8Array<ArrayBuffer>,
      "HKDF",
      false,
      ["deriveKey"]
    );

    return subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(32),
        info: encoder.encode(HKDF_INFO_DIRECT),
      },
      hkdfBaseKey,
      { name: "AES-GCM", length: 256 },
      false,
      params.keyUsage
    );
  }

  const normalizedPassword = (params.password ?? "").normalize("NFKC");
  if (!normalizedPassword) {
    throw new SecretCryptoError(
      "password_required",
      "A password is required to derive the decryption key."
    );
  }

  if (
    !params.kdfSaltBytes ||
    params.kdfSaltBytes.byteLength !== PBKDF2_SALT_BYTE_LENGTH ||
    typeof params.kdfIterations !== "number" ||
    !Number.isInteger(params.kdfIterations) ||
    params.kdfIterations < MIN_PBKDF2_ITERATIONS ||
    params.kdfIterations > MAX_PBKDF2_ITERATIONS
  ) {
    throw new SecretCryptoError(
      "invalid_kdf_params",
      "Invalid KDF salt or iteration count."
    );
  }

  // Step 1: PBKDF2-HMAC-SHA-256 on the password + random 128-bit salt
  const pbkdf2BaseKey = await subtle.importKey(
    "raw",
    encoder.encode(normalizedPassword),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const pwdDerivedBits = await subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: params.kdfSaltBytes as Uint8Array<ArrayBuffer>,
      iterations: params.kdfIterations,
    },
    pbkdf2BaseKey,
    256
  );

  const pwdKeyBytes = new Uint8Array(pwdDerivedBits);

  // Step 2: Combine 256-bit fragmentKey + 256-bit PBKDF2 output via HKDF-SHA-256
  const combinedIkm = new Uint8Array(
    params.fragmentKeyBytes.byteLength + pwdKeyBytes.byteLength
  );
  combinedIkm.set(params.fragmentKeyBytes, 0);
  combinedIkm.set(pwdKeyBytes, params.fragmentKeyBytes.byteLength);

  try {
    const hkdfBaseKey = await subtle.importKey(
      "raw",
      combinedIkm,
      "HKDF",
      false,
      ["deriveKey"]
    );

    return await subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: params.kdfSaltBytes as Uint8Array<ArrayBuffer>,
        info: encoder.encode(HKDF_INFO_HYBRID),
      },
      hkdfBaseKey,
      { name: "AES-GCM", length: 256 },
      false,
      params.keyUsage
    );
  } finally {
    // Zero out intermediate key material in memory
    pwdKeyBytes.fill(0);
    combinedIkm.fill(0);
  }
}

/**
 * Encrypts a plaintext message on the client using AES-256-GCM.
 */
export async function encryptSecretMessage(
  plaintext: string,
  options?: {
    password?: string;
    kdfIterations?: number;
  }
): Promise<EncryptedSecretBundle> {
  if (typeof plaintext !== "string" || plaintext.trim().length === 0) {
    throw new SecretCryptoError(
      "empty_plaintext",
      "Secret message cannot be empty."
    );
  }

  if (plaintext.length > MAX_SECRET_PLAINTEXT_CHARS) {
    throw new SecretCryptoError(
      "plaintext_too_long",
      `Secret message cannot exceed ${MAX_SECRET_PLAINTEXT_CHARS} characters.`
    );
  }

  const rawPassword = options?.password ?? "";
  const passwordProtected = rawPassword.length > 0;
  const iterations = passwordProtected
    ? (options?.kdfIterations ?? DEFAULT_PBKDF2_ITERATIONS)
    : null;

  const fragmentKeyBytes = new Uint8Array(FRAGMENT_KEY_BYTE_LENGTH);
  globalThis.crypto.getRandomValues(fragmentKeyBytes);

  const ivBytes = new Uint8Array(AES_GCM_IV_BYTE_LENGTH);
  globalThis.crypto.getRandomValues(ivBytes);

  const kdfSaltBytes = passwordProtected
    ? globalThis.crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_BYTE_LENGTH))
    : null;

  const fragmentKey = bytesToBase64Url(fragmentKeyBytes);
  const iv = bytesToBase64Url(ivBytes);
  const kdfSalt = kdfSaltBytes ? bytesToBase64Url(kdfSaltBytes) : null;

  try {
    const aesKey = await deriveAesGcmKey({
      fragmentKeyBytes,
      password: rawPassword,
      passwordProtected,
      kdfSaltBytes,
      kdfIterations: iterations,
      keyUsage: ["encrypt"],
    });

    const aad = buildAdditionalAuthenticatedData({
      passwordProtected,
      kdfSalt,
      kdfIterations: iterations,
    });

    const plaintextBytes = new TextEncoder().encode(
      plaintext
    ) as Uint8Array<ArrayBuffer>;

    const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: ivBytes,
        additionalData: aad,
        tagLength: AES_GCM_TAG_BIT_LENGTH,
      },
      aesKey,
      plaintextBytes
    );

    plaintextBytes.fill(0);

    return {
      ciphertext: bytesToBase64Url(new Uint8Array(encryptedBuffer)),
      iv,
      fragmentKey,
      passwordProtected,
      kdfSalt,
      kdfIterations: iterations,
    };
  } finally {
    fragmentKeyBytes.fill(0);
  }
}

/**
 * Decrypts an AES-256-GCM secret bundle on the client using the URL fragment key
 * and optional user password.
 */
export async function decryptSecretMessage(params: {
  ciphertext: string;
  iv: string;
  fragmentKey: string;
  passwordProtected: boolean;
  kdfSalt: string | null;
  kdfIterations: number | null;
  password?: string;
}): Promise<string> {
  if (!isValidFragmentKey(params.fragmentKey)) {
    throw new SecretCryptoError(
      "invalid_fragment_key",
      "Invalid or missing decryption key in URL fragment."
    );
  }

  if (
    !isValidBase64UrlPayload(
      params.iv,
      AES_GCM_IV_BYTE_LENGTH,
      AES_GCM_IV_BYTE_LENGTH
    ) ||
    !isValidBase64UrlPayload(params.ciphertext, 17, 16384)
  ) {
    throw new SecretCryptoError(
      "decryption_failed",
      "Malformed ciphertext or initialization vector."
    );
  }

  const fragmentKeyBytes = base64UrlToBytes(params.fragmentKey);
  const ivBytes = base64UrlToBytes(params.iv) as Uint8Array<ArrayBuffer>;
  const ciphertextBytes = base64UrlToBytes(
    params.ciphertext
  ) as Uint8Array<ArrayBuffer>;
  const kdfSaltBytes =
    params.passwordProtected && params.kdfSalt
      ? base64UrlToBytes(params.kdfSalt)
      : null;

  try {
    const aesKey = await deriveAesGcmKey({
      fragmentKeyBytes,
      password: params.password,
      passwordProtected: params.passwordProtected,
      kdfSaltBytes,
      kdfIterations: params.kdfIterations,
      keyUsage: ["decrypt"],
    });

    const aad = buildAdditionalAuthenticatedData({
      passwordProtected: params.passwordProtected,
      kdfSalt: params.kdfSalt,
      kdfIterations: params.kdfIterations,
    });

    const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: ivBytes,
        additionalData: aad,
        tagLength: AES_GCM_TAG_BIT_LENGTH,
      },
      aesKey,
      ciphertextBytes
    );

    return new TextDecoder("utf-8", { fatal: true }).decode(decryptedBuffer);
  } catch (err) {
    if (err instanceof SecretCryptoError) {
      throw err;
    }
    throw new SecretCryptoError(
      "decryption_failed",
      "Unable to decrypt secret: invalid password, wrong key, or tampered ciphertext."
    );
  } finally {
    fragmentKeyBytes.fill(0);
  }
}
