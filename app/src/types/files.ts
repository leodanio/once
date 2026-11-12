export type FileExpirationPreset = "10m" | "1h" | "24h" | "7d";

export interface EncryptedFileMetadata {
  originalName: string;
  originalSize: number;
  mimeType: string;
  chunkCount: number;
  chunkSize: number;
  totalEncryptedSize: number;
  sha256Hash: string; // Plaintext root hash for integrity check post-decryption
}

export interface FileTransferRecord {
  id: string;
  transferToken: string;
  storagePath: string;
  encryptedMeta: string; // JSON string or base64 of encrypted metadata
  popPublicKeySpki: string; // Base64URL SPKI
  maxDownloads: number;
  downloadCount: number;
  status: "pending_upload" | "ready" | "completed" | "expired" | "deleted";
  expiresAt: string;
  createdAt: string;
}

export interface DownloadChallengeRecord {
  id: string;
  fileId: string;
  challengeNonce: string; // Hex or base64
  status: "pending" | "consumed" | "expired";
  expiresAt: string;
  createdAt: string;
  consumedAt: string | null;
}

export interface FileRequestRecord {
  id: string;
  requestToken: string;
  ownerTokenHash: string;
  title: string;
  maxFiles: number;
  maxBytesPerFile: number;
  filesCount: number;
  creatorPublicKeySpki: string;
  status: "active" | "closed" | "expired";
  expiresAt: string;
  createdAt: string;
  closedAt: string | null;
}

export interface FileRequestItemRecord {
  id: string;
  requestId: string;
  storagePath: string;
  sizeBytes: number;
  guestPublicKeySpki: string;
  wrappedKeyBundle: string; // JSON with IV, ciphertext, tag of the fileKey wrapped with shared secret
  encryptedMeta: string;
  status: "pending_upload" | "ready" | "deleted" | "expired";
  createdAt: string;
}

export interface CreateTransferRequest {
  popPublicKeySpki: string;
  encryptedMeta: string;
  sizeBytes: number;
  maxDownloads: number;
  expiration: FileExpirationPreset;
}

export interface CreateTransferResponse {
  transferToken: string;
  signedUploadUrl: string;
  storagePath: string;
  expiresAt: string;
}

export interface CreateFileRequestParams {
  title: string;
  creatorPublicKeySpki: string;
  maxFiles: number;
  maxBytesPerFile: number;
  expiration: FileExpirationPreset;
}

export interface CreateFileRequestResponse {
  requestToken: string;
  ownerToken: string;
  expiresAt: string;
}
