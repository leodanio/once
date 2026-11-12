/**
 * ONCE — Cryptographic Engine for FILES
 *
 * Specifications:
 * - Chunked Streaming AEAD (AES-256-GCM) with 5 MB chunks.
 * - Nonce derivation: 8 bytes random base IV + 4 bytes chunk index (Big-Endian).
 * - Chunk AAD: "ONCE-CHUNK-V1:" + tokenOrId + ":" + chunkIndex + ":" + isLast.
 * - Root SHA-256 plaintext integrity validation.
 * - Independent ECDSA P-256 key pair for Proof of Possession (PoP).
 * - Domain-separated PoP message: "ONCE-POP-V1:" + fileId + ":" + challengeId + ":" + challengeNonce.
 * - Password key wrapping via PBKDF2-HMAC-SHA-256 (600,000 iterations) + AES-256-GCM.
 * - Zero secrets stored on the server.
 * - ECDH P-256 key agreement for File Requests with SHA-256 fingerprint validation in URL fragment.
 */

import {
  bytesToBase64Url,
  base64UrlToBytes,
} from "@/lib/secrets/crypto";
import type { EncryptedFileMetadata } from "@/types/files";

export const FILE_CRYPTO_VERSION = 1;
export const CHUNK_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB
export const MAX_FILE_SIZE_BYTES = 45 * 1024 * 1024; // 45 MB hard limit
export const AES_GCM_TAG_LENGTH_BYTES = 16;
export const PBKDF2_FILE_ITERATIONS = 600_000;
export const PBKDF2_SALT_BYTES = 16;
export const WRAPPING_IV_BYTES = 12;

export class FileCryptoError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(`[${code}] ${message}`);
    this.name = "FileCryptoError";
    this.code = code;
  }
}

/**
 * Calculates SHA-256 of an ArrayBuffer or Uint8Array.
 */
export async function sha256Digest(data: BufferSource): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hash);
}

function rotr(n: number, b: number): number {
  return ((n >>> b) | (n << (32 - b))) >>> 0;
}

/**
 * Pure-JS Streaming SHA-256 hasher for true incremental file hashing
 * without holding large files in memory.
 */
export class StreamingSha256 {
  private H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  private buffer = new Uint8Array(64);
  private bufferLength = 0;
  private totalBytes = 0;
  private W = new Uint32Array(64);

  private static K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  update(chunk: Uint8Array | ArrayBuffer | ArrayBufferLike): this {
    const data = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
    let offset = 0;
    this.totalBytes += data.length;

    while (offset < data.length) {
      const toCopy = Math.min(64 - this.bufferLength, data.length - offset);
      this.buffer.set(data.subarray(offset, offset + toCopy), this.bufferLength);
      this.bufferLength += toCopy;
      offset += toCopy;

      if (this.bufferLength === 64) {
        this.processBlock(this.buffer);
        this.bufferLength = 0;
      }
    }
    return this;
  }

  digest(): Uint8Array {
    const totalBits = this.totalBytes * 8;
    this.buffer[this.bufferLength++] = 0x80;

    if (this.bufferLength > 56) {
      this.buffer.fill(0, this.bufferLength, 64);
      this.processBlock(this.buffer);
      this.bufferLength = 0;
    }

    this.buffer.fill(0, this.bufferLength, 56);
    const view = new DataView(this.buffer.buffer, this.buffer.byteOffset, 64);
    const highBits = Math.floor(totalBits / 0x100000000);
    const lowBits = totalBits >>> 0;
    view.setUint32(56, highBits, false);
    view.setUint32(60, lowBits, false);
    this.processBlock(this.buffer);

    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer, out.byteOffset, 32);
    for (let i = 0; i < 8; i++) {
      outView.setUint32(i * 4, this.H[i], false);
    }
    return out;
  }

  private processBlock(block: Uint8Array): void {
    const W = this.W;
    const blockView = new DataView(block.buffer, block.byteOffset, 64);

    for (let t = 0; t < 16; t++) {
      W[t] = blockView.getUint32(t * 4, false);
    }

    for (let t = 16; t < 64; t++) {
      const s0 = (rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3)) >>> 0;
      const s1 = (rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10)) >>> 0;
      W[t] = ((W[t - 16] + s0 + W[t - 7] + s1) | 0) >>> 0;
    }

    let a = this.H[0];
    let b = this.H[1];
    let c = this.H[2];
    let d = this.H[3];
    let e = this.H[4];
    let f = this.H[5];
    let g = this.H[6];
    let h = this.H[7];

    const K = StreamingSha256.K;
    for (let t = 0; t < 64; t++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = ((h + S1 + ch + K[t] + W[t]) | 0) >>> 0;
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = ((S0 + maj) | 0) >>> 0;

      h = g;
      g = f;
      f = e;
      e = ((d + temp1) | 0) >>> 0;
      d = c;
      c = b;
      b = a;
      a = ((temp1 + temp2) | 0) >>> 0;
    }

    this.H[0] = ((this.H[0] + a) | 0) >>> 0;
    this.H[1] = ((this.H[1] + b) | 0) >>> 0;
    this.H[2] = ((this.H[2] + c) | 0) >>> 0;
    this.H[3] = ((this.H[3] + d) | 0) >>> 0;
    this.H[4] = ((this.H[4] + e) | 0) >>> 0;
    this.H[5] = ((this.H[5] + f) | 0) >>> 0;
    this.H[6] = ((this.H[6] + g) | 0) >>> 0;
    this.H[7] = ((this.H[7] + h) | 0) >>> 0;
  }
}

/**
 * Generates a fresh 256-bit AES-GCM random key.
 */
export async function generateFileKey(): Promise<CryptoKey> {
  return await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

/**
 * Exports a CryptoKey to raw Uint8Array bytes.
 */
export async function exportRawKey(key: CryptoKey): Promise<Uint8Array> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return new Uint8Array(raw);
}

/**
 * Imports raw Uint8Array bytes into an AES-GCM CryptoKey.
 */
export async function importRawFileKey(bytes: Uint8Array): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "raw",
    bytes as BufferSource,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

/**
 * Derives a 12-byte IV for a specific chunk index:
 * First 8 bytes: random base_iv
 * Last 4 bytes: 32-bit big-endian chunk index
 */
export function deriveChunkIv(baseIv: Uint8Array, chunkIndex: number): Uint8Array {
  if (baseIv.length < 8) {
    throw new FileCryptoError("invalid_base_iv", "Base IV must be at least 8 bytes");
  }
  const iv = new Uint8Array(12);
  iv.set(baseIv.subarray(0, 8), 0);
  const view = new DataView(iv.buffer, iv.byteOffset, 12);
  view.setUint32(8, chunkIndex, false); // Big-Endian
  return iv;
}

/**
 * Builds AAD for a specific chunk.
 */
export function buildChunkAad(
  tokenOrId: string,
  chunkIndex: number,
  isLast: boolean
): Uint8Array {
  const str = `ONCE-CHUNK-V1:${tokenOrId}:${chunkIndex}:${isLast ? 1 : 0}`;
  return new TextEncoder().encode(str);
}

/**
 * Encrypts a single 5MB chunk using AES-256-GCM.
 */
export async function encryptChunk(
  chunkBuffer: ArrayBuffer | ArrayBufferLike,
  fileKey: CryptoKey,
  baseIv: Uint8Array,
  chunkIndex: number,
  isLast: boolean,
  tokenOrId: string
): Promise<Uint8Array> {
  const iv = deriveChunkIv(baseIv, chunkIndex);
  const aad = buildChunkAad(tokenOrId, chunkIndex, isLast);

  const ciphertextWithTag = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as BufferSource,
      additionalData: aad as BufferSource,
      tagLength: 128,
    },
    fileKey,
    chunkBuffer as BufferSource
  );

  return new Uint8Array(ciphertextWithTag);
}

/**
 * Decrypts a single 5MB chunk using AES-256-GCM.
 */
export async function decryptChunk(
  encryptedChunk: ArrayBuffer | ArrayBufferLike,
  fileKey: CryptoKey,
  baseIv: Uint8Array,
  chunkIndex: number,
  isLast: boolean,
  tokenOrId: string
): Promise<Uint8Array> {
  const iv = deriveChunkIv(baseIv, chunkIndex);
  const aad = buildChunkAad(tokenOrId, chunkIndex, isLast);

  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv as BufferSource,
        additionalData: aad as BufferSource,
        tagLength: 128,
      },
      fileKey,
      encryptedChunk as BufferSource
    );
    return new Uint8Array(plaintext);
  } catch {
    throw new FileCryptoError(
      "chunk_decryption_failed",
      `Decryption failed for chunk ${chunkIndex}. Data corrupted or tampered with.`
    );
  }
}

/**
 * Encrypts metadata JSON with the fileKey.
 */
export async function encryptMetadata(
  meta: EncryptedFileMetadata,
  fileKey: CryptoKey
): Promise<{ encryptedMetaB64: string; metaIvB64: string }> {
  const jsonStr = JSON.stringify(meta);
  const plaintext = new TextEncoder().encode(jsonStr);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode("ONCE-META-V1");

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as BufferSource,
      additionalData: aad as BufferSource,
      tagLength: 128,
    },
    fileKey,
    plaintext
  );

  return {
    encryptedMetaB64: bytesToBase64Url(new Uint8Array(ciphertext)),
    metaIvB64: bytesToBase64Url(iv),
  };
}

/**
 * Decrypts metadata JSON with the fileKey.
 */
export async function decryptMetadata(
  encryptedMetaB64: string,
  metaIvB64: string,
  fileKey: CryptoKey
): Promise<EncryptedFileMetadata> {
  const ciphertext = base64UrlToBytes(encryptedMetaB64);
  const iv = base64UrlToBytes(metaIvB64);
  const aad = new TextEncoder().encode("ONCE-META-V1");

  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv as BufferSource,
        additionalData: aad as BufferSource,
        tagLength: 128,
      },
      fileKey,
      ciphertext as BufferSource
    );
    const jsonStr = new TextDecoder().decode(plaintext);
    return JSON.parse(jsonStr) as EncryptedFileMetadata;
  } catch {
    throw new FileCryptoError("metadata_decryption_failed", "Failed to decrypt file metadata.");
  }
}

/* ========================================================================== */
/* Proof of Possession (ECDSA P-256)                                          */
/* ========================================================================== */

export async function generatePopKeyPair(): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["sign", "verify"]
  );
}

export async function exportPopPublicKeySpki(publicKey: CryptoKey): Promise<string> {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  return bytesToBase64Url(new Uint8Array(spki));
}

export async function exportPopPrivateKeyPkcs8(privateKey: CryptoKey): Promise<string> {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
  return bytesToBase64Url(new Uint8Array(pkcs8));
}

export async function importPopPublicKeySpki(spkiB64Url: string): Promise<CryptoKey> {
  const bytes = base64UrlToBytes(spkiB64Url);
  return await crypto.subtle.importKey(
    "spki",
    bytes as BufferSource,
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["verify"]
  );
}

export async function importPopPrivateKeyPkcs8(pkcs8B64Url: string): Promise<CryptoKey> {
  const bytes = base64UrlToBytes(pkcs8B64Url);
  return await crypto.subtle.importKey(
    "pkcs8",
    bytes as BufferSource,
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["sign"]
  );
}

export function buildPopPayload(
  fileId: string,
  challengeId: string,
  challengeNonce: string
): Uint8Array {
  const str = `ONCE-POP-V1:${fileId}:${challengeId}:${challengeNonce}`;
  return new TextEncoder().encode(str);
}

export async function signDownloadChallenge(
  privateKey: CryptoKey,
  fileId: string,
  challengeId: string,
  challengeNonce: string
): Promise<string> {
  const payload = buildPopPayload(fileId, challengeId, challengeNonce);
  const signature = await crypto.subtle.sign(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    },
    privateKey,
    payload as BufferSource
  );
  return bytesToBase64Url(new Uint8Array(signature));
}

export async function verifyDownloadChallenge(
  publicKey: CryptoKey,
  fileId: string,
  challengeId: string,
  challengeNonce: string,
  signatureB64Url: string
): Promise<boolean> {
  const payload = buildPopPayload(fileId, challengeId, challengeNonce);
  const signature = base64UrlToBytes(signatureB64Url);
  try {
    return await crypto.subtle.verify(
      {
        name: "ECDSA",
        hash: { name: "SHA-256" },
      },
      publicKey,
      signature as BufferSource,
      payload as BufferSource
    );
  } catch {
    return false;
  }
}

/* ========================================================================== */
/* Password Key Wrapping (PBKDF2-HMAC-SHA256 + AES-GCM)                      */
/* ========================================================================== */

export async function deriveKeyEncryptionKey(
  password: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const normalizedPassword = password.normalize("NFKC");
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(normalizedPassword),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as BufferSource,
      iterations: PBKDF2_FILE_ITERATIONS,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function wrapKeysWithPassword(
  fileKeyBytes: Uint8Array,
  popPrivateKeyPkcs8B64: string,
  password: string
): Promise<{ saltB64: string; ivB64: string; wrappedBundleB64: string }> {
  const salt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(WRAPPING_IV_BYTES));
  const kek = await deriveKeyEncryptionKey(password, salt);

  const payloadObj = {
    k: bytesToBase64Url(fileKeyBytes),
    s: popPrivateKeyPkcs8B64,
  };
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payloadObj));
  const aad = new TextEncoder().encode("ONCE-KW-V1");

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as BufferSource,
      additionalData: aad as BufferSource,
      tagLength: 128,
    },
    kek,
    payloadBytes
  );

  return {
    saltB64: bytesToBase64Url(salt),
    ivB64: bytesToBase64Url(iv),
    wrappedBundleB64: bytesToBase64Url(new Uint8Array(ciphertext)),
  };
}

export async function unwrapKeysWithPassword(
  saltB64: string,
  ivB64: string,
  wrappedBundleB64: string,
  password: string
): Promise<{ fileKeyBytes: Uint8Array; popPrivateKeyPkcs8: string; popPrivateKeyPkcs8B64: string }> {
  const salt = base64UrlToBytes(saltB64);
  const iv = base64UrlToBytes(ivB64);
  const wrappedBytes = base64UrlToBytes(wrappedBundleB64);

  const kek = await deriveKeyEncryptionKey(password, salt);
  const aad = new TextEncoder().encode("ONCE-KW-V1");

  try {
    const decryptedBytes = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv as BufferSource,
        additionalData: aad as BufferSource,
        tagLength: 128,
      },
      kek,
      wrappedBytes as BufferSource
    );

    const payloadObj = JSON.parse(new TextDecoder().decode(decryptedBytes));
    if (!payloadObj.k || !payloadObj.s) {
      throw new Error("Invalid bundle payload");
    }

    return {
      fileKeyBytes: base64UrlToBytes(payloadObj.k),
      popPrivateKeyPkcs8: payloadObj.s,
      popPrivateKeyPkcs8B64: payloadObj.s,
    };
  } catch {
    throw new FileCryptoError("wrong_password", "Incorrect password or corrupted key bundle.");
  }
}

/* ========================================================================== */
/* Fragment Serializer and Parser                                             */
/* ========================================================================== */

export type FragmentParsedData =
  | { mode: "raw"; fileKeyBytes: Uint8Array; popPrivateKeyPkcs8: string; baseIv: Uint8Array }
  | { mode: "pwd"; saltB64: string; ivB64: string; wrappedBundleB64: string; baseIv: Uint8Array };

export function formatTransferFragmentRaw(
  fileKeyBytes: Uint8Array,
  popPrivateKeyPkcs8: string,
  baseIv: Uint8Array
): string {
  return `#v1.raw.${bytesToBase64Url(fileKeyBytes)}.${popPrivateKeyPkcs8}.${bytesToBase64Url(baseIv)}`;
}

export function formatTransferFragmentPwd(
  saltB64: string,
  ivB64: string,
  wrappedBundleB64: string,
  baseIv: Uint8Array
): string {
  return `#v1.pwd.${saltB64}.${ivB64}.${wrappedBundleB64}.${bytesToBase64Url(baseIv)}`;
}

export function parseTransferFragment(hash: string): FragmentParsedData {
  const cleanHash = hash.startsWith("#") ? hash.slice(1) : hash;
  const parts = cleanHash.split(".");

  if (parts.length < 2 || parts[0] !== "v1") {
    throw new FileCryptoError("invalid_fragment", "Unsupported or invalid URL fragment format.");
  }

  const mode = parts[1];
  if (mode === "raw") {
    if (parts.length !== 5) {
      throw new FileCryptoError("invalid_fragment_raw", "Malformed raw key fragment.");
    }
    return {
      mode: "raw",
      fileKeyBytes: base64UrlToBytes(parts[2]),
      popPrivateKeyPkcs8: parts[3],
      baseIv: base64UrlToBytes(parts[4]),
    };
  } else if (mode === "pwd") {
    if (parts.length !== 6) {
      throw new FileCryptoError("invalid_fragment_pwd", "Malformed password-protected fragment.");
    }
    return {
      mode: "pwd",
      saltB64: parts[2],
      ivB64: parts[3],
      wrappedBundleB64: parts[4],
      baseIv: base64UrlToBytes(parts[5]),
    };
  } else {
    throw new FileCryptoError("unknown_fragment_mode", `Unknown fragment mode: ${mode}`);
  }
}

/* ========================================================================== */
/* FILE REQUEST Cryptography (ECDH P-256 + HKDF + Fingerprint)                */
/* ========================================================================== */

export async function generateEcdhKeyPair(): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    ["deriveKey", "deriveBits"]
  );
}

export async function exportEcdhPublicKeySpki(publicKey: CryptoKey): Promise<string> {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  return bytesToBase64Url(new Uint8Array(spki));
}

export async function exportEcdhPrivateKeyPkcs8(privateKey: CryptoKey): Promise<string> {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
  return bytesToBase64Url(new Uint8Array(pkcs8));
}

export async function importEcdhPublicKeySpki(spkiB64Url: string): Promise<CryptoKey> {
  const bytes = base64UrlToBytes(spkiB64Url);
  return await crypto.subtle.importKey(
    "spki",
    bytes as BufferSource,
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    []
  );
}

export async function importEcdhPrivateKeyPkcs8(pkcs8B64Url: string): Promise<CryptoKey> {
  const bytes = base64UrlToBytes(pkcs8B64Url);
  return await crypto.subtle.importKey(
    "pkcs8",
    bytes as BufferSource,
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    ["deriveKey", "deriveBits"]
  );
}

/**
 * Computes the SHA-256 fingerprint of an ECDH public key (in Base64URL).
 * Embedded in the public request link fragment: #v1.req.<fingerprint>
 */
export async function computePublicKeyFingerprint(spkiB64Url: string): Promise<string> {
  const spkiBytes = base64UrlToBytes(spkiB64Url);
  const hash = await sha256Digest(spkiBytes as BufferSource);
  return bytesToBase64Url(hash);
}

/**
 * Derives an AES-GCM shared key from an ECDH exchange using HKDF-SHA-256.
 */
export async function deriveEcdhSharedKey(
  privateKey: CryptoKey,
  peerPublicKey: CryptoKey
): Promise<CryptoKey> {
  // 1. Derive shared secret bits
  const sharedBits = await crypto.subtle.deriveBits(
    {
      name: "ECDH",
      public: peerPublicKey,
    },
    privateKey,
    256
  );

  // 2. Import shared bits into HKDF
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedBits,
    "HKDF",
    false,
    ["deriveKey"]
  );

  // 3. Derive 256-bit AES-GCM key
  const salt = new Uint8Array(32); // All zeros standard salt
  const info = new TextEncoder().encode("ONCE-REQUEST-V1:shared-secret");

  return await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: info as BufferSource,
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Guest wraps the ephemeral fileKey using the derived ECDH shared key.
 */
export async function wrapFileKeyWithEcdh(
  fileKeyBytes: Uint8Array,
  sharedKey: CryptoKey
): Promise<{ ivB64: string; wrappedKeyB64: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode("ONCE-REQ-WRAP-V1");

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as BufferSource,
      additionalData: aad as BufferSource,
      tagLength: 128,
    },
    sharedKey,
    fileKeyBytes as BufferSource
  );

  return {
    ivB64: bytesToBase64Url(iv),
    wrappedKeyB64: bytesToBase64Url(new Uint8Array(ciphertext)),
  };
}

/**
 * Request Creator unwraps the fileKey using their private ECDH key and guest's public key.
 */
export async function unwrapFileKeyWithEcdh(
  wrappedKeyB64: string,
  ivB64: string,
  creatorPrivateKey: CryptoKey,
  guestPublicKey: CryptoKey
): Promise<Uint8Array> {
  const sharedKey = await deriveEcdhSharedKey(creatorPrivateKey, guestPublicKey);
  const iv = base64UrlToBytes(ivB64);
  const ciphertext = base64UrlToBytes(wrappedKeyB64);
  const aad = new TextEncoder().encode("ONCE-REQ-WRAP-V1");

  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv as BufferSource,
        additionalData: aad as BufferSource,
        tagLength: 128,
      },
      sharedKey,
      ciphertext as BufferSource
    );
    return new Uint8Array(plaintext);
  } catch {
    throw new FileCryptoError("ecdh_unwrap_failed", "Failed to unwrap file key with ECDH shared secret.");
  }
}
