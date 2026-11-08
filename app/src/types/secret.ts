import type { ExpirationPreset } from "./link";

export interface EncryptedSecretBundle {
  /** Base64url-encoded AES-256-GCM ciphertext (includes 128-bit auth tag) */
  ciphertext: string;
  /** Base64url-encoded 96-bit (12-byte) random initialization vector */
  iv: string;
  /** Base64url-encoded 256-bit (32-byte) random key stored ONLY in URL #fragment */
  fragmentKey: string;
  /** Whether a user password participated in key derivation */
  passwordProtected: boolean;
  /** Base64url-encoded 128-bit (16-byte) random PBKDF2 salt when passwordProtected is true */
  kdfSalt: string | null;
  /** PBKDF2 iteration count when passwordProtected is true */
  kdfIterations: number | null;
}

export interface CreateSecretRequest {
  ciphertext: string;
  iv: string;
  passwordProtected: boolean;
  kdfSalt?: string | null;
  kdfIterations?: number | null;
  expiration?: ExpirationPreset;
}

export interface CreatedSecretMetadata {
  id: string;
  token: string;
  expiration: ExpirationPreset;
  expiresAt: string | null;
  passwordProtected: boolean;
  createdAt: string;
}

export interface GeneratedSecretShare {
  id: string;
  token: string;
  /** Full client-constructed URL including #fragmentKey (never seen by server) */
  shareUrl: string;
  expiration: ExpirationPreset;
  expiresAt: string | null;
  passwordProtected: boolean;
  createdAt: string;
}

export type SecretMetadataStatus =
  | "available"
  | "expired"
  | "consumed"
  | "not_found";

export interface SecretMetadataResult {
  status: SecretMetadataStatus;
  passwordProtected: boolean;
  expiresAt: string | null;
}

export type ConsumeSecretStatus =
  | "valid"
  | "expired"
  | "consumed"
  | "not_found";

export interface ConsumeSecretResult {
  status: ConsumeSecretStatus;
  ciphertext: string | null;
  iv: string | null;
  passwordProtected: boolean;
  kdfSalt: string | null;
  kdfIterations: number | null;
  expiresAt: string | null;
  consumedAt: string | null;
}
