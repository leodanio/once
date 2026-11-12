import type { SupabaseClient } from "@supabase/supabase-js";
import {
  getServerSupabaseClient,
  isSupabaseConfigured,
  type CheckRateLimitRpcRow,
} from "@/lib/supabase/server";
import type {
  DownloadChallengeRecord,
  FileExpirationPreset,
  FileRequestItemRecord,
  FileRequestRecord,
  FileTransferRecord,
} from "@/types/files";
import { generateRandomSlug } from "@/lib/utils/url";

export const FILE_UPLOAD_MAX_BYTES = 45 * 1024 * 1024; // 45 MB
export const BUCKET_NAME = "files";

export function computeFileExpirationDate(
  preset: FileExpirationPreset,
  nowMs: number = Date.now()
): string {
  switch (preset) {
    case "10m":
      return new Date(nowMs + 10 * 60 * 1000).toISOString();
    case "1h":
      return new Date(nowMs + 60 * 60 * 1000).toISOString();
    case "24h":
      return new Date(nowMs + 24 * 60 * 60 * 1000).toISOString();
    case "7d":
    default:
      return new Date(nowMs + 7 * 24 * 60 * 60 * 1000).toISOString();
  }
}

export interface InsertTransferParams {
  transferToken: string;
  storagePath: string;
  encryptedMeta: Record<string, unknown>;
  popPublicKeySpki: string;
  maxDownloads: number;
  expiresAt: string;
}

export type InsertTransferResult =
  | { ok: true; record: FileTransferRecord }
  | { ok: false; reason: "token_conflict" | "db_error"; message?: string };

export type GenerateChallengeResult =
  | {
      ok: true;
      challengeId: string;
      challengeNonce: string;
      fileId: string;
      popPublicKeySpki: string;
    }
  | { ok: false; reason: string };

export type ConsumeDownloadResult =
  | { ok: true; storagePath: string }
  | { ok: false; reason: string };

export interface InsertFileRequestParams {
  requestToken: string;
  ownerTokenHash: string;
  title: string;
  creatorPublicKeySpki: string;
  maxFiles: number;
  maxBytesPerFile: number;
  expiresAt: string;
}

export type InsertFileRequestResult =
  | { ok: true; record: FileRequestRecord }
  | { ok: false; reason: "token_conflict" | "db_error"; message?: string };

export type ReserveItemResult =
  | { ok: true; itemId: string; requestId: string }
  | { ok: false; reason: string };

export type ConfirmItemResult =
  | { ok: true }
  | { ok: false; reason: string };

export type ConfirmTransferResult =
  | { ok: true }
  | { ok: false; reason: string };

export interface ClaimDeletionQueueResult {
  id: string;
  storagePath: string;
  attempts: number;
}

export type DeleteItemResult =
  | { ok: true }
  | { ok: false; reason: string };

export type CloseRequestResult =
  | { ok: true }
  | { ok: false; reason: string };

export interface CleanupResult {
  expiredTransfers: number;
  expiredRequests: number;
  expiredPendingItems: number;
  queuedForDeletion: number;
}

export interface FileRepository {
  createTransfer(params: InsertTransferParams): Promise<InsertTransferResult>;
  confirmTransfer(transferToken: string): Promise<ConfirmTransferResult>;
  getTransferByToken(token: string): Promise<FileTransferRecord | null>;
  generateDownloadChallenge(transferToken: string, clientIp: string): Promise<GenerateChallengeResult>;
  getChallengeById(challengeId: string): Promise<DownloadChallengeRecord | null>;
  consumeDownload(fileId: string, challengeId: string, gracePeriodMinutes?: number): Promise<ConsumeDownloadResult>;
  createFileRequest(params: InsertFileRequestParams): Promise<InsertFileRequestResult>;
  getFileRequestByToken(requestToken: string): Promise<FileRequestRecord | null>;
  getFileRequestByOwnerHash(ownerTokenHash: string): Promise<FileRequestRecord | null>;
  reserveRequestItem(requestToken: string, storagePath: string, sizeBytes: number): Promise<ReserveItemResult>;
  confirmRequestItem(
    itemId: string,
    guestPublicKeySpki: string,
    wrappedKeyBundle: Record<string, unknown>,
    encryptedMeta: Record<string, unknown>
  ): Promise<ConfirmItemResult>;
  getRequestItems(requestId: string): Promise<FileRequestItemRecord[]>;
  getRequestItemById(itemId: string): Promise<FileRequestItemRecord | null>;
  deleteRequestItem(ownerTokenHash: string, itemId: string): Promise<DeleteItemResult>;
  closeFileRequest(ownerTokenHash: string): Promise<CloseRequestResult>;
  checkRateLimit(key: string, maxRequests: number, windowSeconds: number): Promise<CheckRateLimitRpcRow>;
  cleanupExpiredFiles(): Promise<CleanupResult>;
  claimDeletionQueueBatch(batchSize: number, leaseMinutes?: number): Promise<ClaimDeletionQueueResult[]>;
  finalizeDeletionQueueSuccess(ids: string[]): Promise<void>;
  recordDeletionQueueFailure(id: string, error: string): Promise<void>;
  createSignedUploadUrl(storagePath: string): Promise<string>;
  createSignedDownloadUrl(storagePath: string, expiresInSeconds: number): Promise<string>;
  deleteStorageObjects(storagePaths: string[]): Promise<void>;
}

/* ========================================================================== */
/* In-Memory File Repository (For Isolated Deterministic Tests)               */
/* ========================================================================== */

export class AtomicMemoryFileRepository implements FileRepository {
  transfers = new Map<string, FileTransferRecord>();
  challenges = new Map<string, DownloadChallengeRecord>();
  requests = new Map<string, FileRequestRecord>();
  requestItems = new Map<string, FileRequestItemRecord>();
  deletionQueue = new Map<string, {
    id: string;
    storagePath: string;
    deleteAfter: string;
    attempts: number;
    lastError: string | null;
    claimExpiresAt: string | null;
  }>();
  rateLimits = new Map<string, { count: number; windowStart: number }>();

  async createTransfer(params: InsertTransferParams): Promise<InsertTransferResult> {
    for (const t of this.transfers.values()) {
      if (t.transferToken === params.transferToken) {
        return { ok: false, reason: "token_conflict" };
      }
    }

    const id = crypto.randomUUID();
    const record: FileTransferRecord = {
      id,
      transferToken: params.transferToken,
      storagePath: params.storagePath,
      encryptedMeta: JSON.stringify(params.encryptedMeta),
      popPublicKeySpki: params.popPublicKeySpki,
      maxDownloads: params.maxDownloads,
      downloadCount: 0,
      status: "pending_upload",
      expiresAt: params.expiresAt,
      createdAt: new Date().toISOString(),
    };

    this.transfers.set(id, record);
    return { ok: true, record };
  }

  async confirmTransfer(transferToken: string): Promise<ConfirmTransferResult> {
    const file = await this.getTransferByToken(transferToken);
    if (!file) return { ok: false, reason: "file_not_found" };
    if (file.status === "ready") return { ok: true };
    if (file.status !== "pending_upload") return { ok: false, reason: "invalid_file_status" };
    if (new Date(file.expiresAt).getTime() <= Date.now()) return { ok: false, reason: "file_expired" };
    file.status = "ready";
    return { ok: true };
  }

  async getTransferByToken(token: string): Promise<FileTransferRecord | null> {
    for (const t of this.transfers.values()) {
      if (t.transferToken === token) {
        return t;
      }
    }
    return null;
  }

  async generateDownloadChallenge(
    transferToken: string,
    clientIp: string
  ): Promise<GenerateChallengeResult> {
    const file = await this.getTransferByToken(transferToken);
    if (!file) return { ok: false, reason: "file_not_found" };
    if (file.downloadCount >= file.maxDownloads || file.status === "completed") return { ok: false, reason: "max_downloads_reached" };
    if (new Date(file.expiresAt).getTime() <= Date.now()) return { ok: false, reason: "file_expired" };
    if (file.status !== "ready") return { ok: false, reason: "file_not_ready" };

    let ipPending = 0;
    let totalPending = 0;
    const now = Date.now();

    for (const c of this.challenges.values()) {
      if (c.fileId === file.id && c.status === "pending" && new Date(c.expiresAt).getTime() > now) {
        totalPending++;
        if ((c as unknown as { clientIp: string }).clientIp === clientIp) {
          ipPending++;
        }
      }
    }

    if (ipPending >= 2) return { ok: false, reason: "too_many_pending_ip_challenges" };
    if (totalPending >= 10) return { ok: false, reason: "too_many_concurrent_challenges" };

    const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
    let nonceHex = "";
    for (let i = 0; i < nonceBytes.length; i++) {
      nonceHex += nonceBytes[i].toString(16).padStart(2, "0");
    }

    const challengeId = crypto.randomUUID();
    const chalRecord: DownloadChallengeRecord & { clientIp: string } = {
      id: challengeId,
      fileId: file.id,
      clientIp,
      challengeNonce: nonceHex,
      status: "pending",
      expiresAt: new Date(now + 60000).toISOString(),
      createdAt: new Date(now).toISOString(),
      consumedAt: null,
    };

    this.challenges.set(challengeId, chalRecord);

    return {
      ok: true,
      challengeId,
      challengeNonce: nonceHex,
      fileId: file.id,
      popPublicKeySpki: file.popPublicKeySpki,
    };
  }

  async getChallengeById(challengeId: string): Promise<DownloadChallengeRecord | null> {
    return this.challenges.get(challengeId) ?? null;
  }

  async consumeDownload(
    fileId: string,
    challengeId: string,
    gracePeriodMinutes: number = 10
  ): Promise<ConsumeDownloadResult> {
    const file = this.transfers.get(fileId);
    if (!file) return { ok: false, reason: "file_not_found" };
    if (file.status !== "ready") return { ok: false, reason: "invalid_file_status" };
    if (new Date(file.expiresAt).getTime() <= Date.now()) return { ok: false, reason: "file_expired" };
    if (file.downloadCount >= file.maxDownloads) return { ok: false, reason: "max_downloads_reached" };

    const chal = this.challenges.get(challengeId);
    if (!chal || chal.fileId !== fileId) return { ok: false, reason: "challenge_not_found" };
    if (chal.status !== "pending") return { ok: false, reason: "challenge_already_used_or_invalid" };
    if (new Date(chal.expiresAt).getTime() <= Date.now()) {
      chal.status = "expired";
      return { ok: false, reason: "challenge_expired" };
    }

    chal.status = "consumed";
    chal.consumedAt = new Date().toISOString();

    file.downloadCount++;
    if (file.downloadCount >= file.maxDownloads) {
      file.status = "completed";
      const deleteAfter = new Date(Date.now() + gracePeriodMinutes * 60 * 1000).toISOString();
      this.enqueueDeletion(file.storagePath, deleteAfter);
    }

    return { ok: true, storagePath: file.storagePath };
  }

  async createFileRequest(params: InsertFileRequestParams): Promise<InsertFileRequestResult> {
    for (const r of this.requests.values()) {
      if (r.requestToken === params.requestToken || r.ownerTokenHash === params.ownerTokenHash) {
        return { ok: false, reason: "token_conflict" };
      }
    }

    const id = crypto.randomUUID();
    const record: FileRequestRecord = {
      id,
      requestToken: params.requestToken,
      ownerTokenHash: params.ownerTokenHash,
      title: params.title,
      creatorPublicKeySpki: params.creatorPublicKeySpki,
      maxFiles: params.maxFiles,
      maxBytesPerFile: params.maxBytesPerFile,
      filesCount: 0,
      status: "active",
      expiresAt: params.expiresAt,
      createdAt: new Date().toISOString(),
      closedAt: null,
    };

    this.requests.set(id, record);
    return { ok: true, record };
  }

  async getFileRequestByToken(requestToken: string): Promise<FileRequestRecord | null> {
    for (const r of this.requests.values()) {
      if (r.requestToken === requestToken) return r;
    }
    return null;
  }

  async getFileRequestByOwnerHash(ownerTokenHash: string): Promise<FileRequestRecord | null> {
    for (const r of this.requests.values()) {
      if (r.ownerTokenHash === ownerTokenHash) return r;
    }
    return null;
  }

  async reserveRequestItem(
    requestToken: string,
    storagePath: string,
    sizeBytes: number
  ): Promise<ReserveItemResult> {
    const req = await this.getFileRequestByToken(requestToken);
    if (!req) return { ok: false, reason: "request_not_found" };
    if (req.status !== "active") return { ok: false, reason: "request_not_active" };
    if (new Date(req.expiresAt).getTime() <= Date.now()) return { ok: false, reason: "request_expired" };
    if (req.filesCount >= req.maxFiles) return { ok: false, reason: "request_max_files_reached" };
    if (sizeBytes > req.maxBytesPerFile) return { ok: false, reason: "file_too_large" };

    const itemId = crypto.randomUUID();
    const item: FileRequestItemRecord = {
      id: itemId,
      requestId: req.id,
      storagePath,
      sizeBytes,
      guestPublicKeySpki: "",
      wrappedKeyBundle: "{}",
      encryptedMeta: "{}",
      status: "pending_upload",
      createdAt: new Date().toISOString(),
    };

    this.requestItems.set(itemId, item);
    return { ok: true, itemId, requestId: req.id };
  }

  async confirmRequestItem(
    itemId: string,
    guestPublicKeySpki: string,
    wrappedKeyBundle: Record<string, unknown>,
    encryptedMeta: Record<string, unknown>
  ): Promise<ConfirmItemResult> {
    const item = this.requestItems.get(itemId);
    if (!item) return { ok: false, reason: "item_not_found" };
    if (item.status !== "pending_upload") return { ok: false, reason: "invalid_item_status" };

    const req = this.requests.get(item.requestId);
    if (!req) return { ok: false, reason: "request_not_found" };

    item.status = "ready";
    item.guestPublicKeySpki = guestPublicKeySpki;
    item.wrappedKeyBundle = JSON.stringify(wrappedKeyBundle);
    item.encryptedMeta = JSON.stringify(encryptedMeta);

    req.filesCount++;
    return { ok: true };
  }

  async getRequestItems(requestId: string): Promise<FileRequestItemRecord[]> {
    const items: FileRequestItemRecord[] = [];
    for (const item of this.requestItems.values()) {
      if (item.requestId === requestId && item.status === "ready") {
        items.push(item);
      }
    }
    return items;
  }

  async getRequestItemById(itemId: string): Promise<FileRequestItemRecord | null> {
    return this.requestItems.get(itemId) ?? null;
  }

  private enqueueDeletion(storagePath: string, deleteAfter: string): void {
    const existing = this.deletionQueue.get(storagePath);
    if (existing) {
      existing.deleteAfter = deleteAfter;
    } else {
      this.deletionQueue.set(storagePath, {
        id: crypto.randomUUID(),
        storagePath,
        deleteAfter,
        attempts: 0,
        lastError: null,
        claimExpiresAt: null,
      });
    }
  }

  async deleteRequestItem(ownerTokenHash: string, itemId: string): Promise<DeleteItemResult> {
    const req = await this.getFileRequestByOwnerHash(ownerTokenHash);
    if (!req) return { ok: false, reason: "request_not_found" };

    const item = this.requestItems.get(itemId);
    if (!item || item.requestId !== req.id) return { ok: false, reason: "item_not_found" };

    item.status = "deleted";
    this.enqueueDeletion(item.storagePath, new Date(Date.now() + 10 * 60 * 1000).toISOString());
    return { ok: true };
  }

  async closeFileRequest(ownerTokenHash: string): Promise<CloseRequestResult> {
    const req = await this.getFileRequestByOwnerHash(ownerTokenHash);
    if (!req) return { ok: false, reason: "request_not_found" };

    req.status = "closed";
    req.closedAt = new Date().toISOString();

    for (const item of this.requestItems.values()) {
      if (item.requestId === req.id && item.status !== "deleted") {
        item.status = "deleted";
        this.enqueueDeletion(item.storagePath, new Date(Date.now() + 10 * 60 * 1000).toISOString());
      }
    }

    return { ok: true };
  }

  async checkRateLimit(
    key: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<CheckRateLimitRpcRow> {
    const now = Date.now();
    const entry = this.rateLimits.get(key);

    if (!entry || now - entry.windowStart >= windowSeconds * 1000) {
      this.rateLimits.set(key, { count: 1, windowStart: now });
      return {
        allowed: true,
        current_count: 1,
        reset_at: new Date(now + windowSeconds * 1000).toISOString(),
      };
    }

    entry.count++;
    return {
      allowed: entry.count <= maxRequests,
      current_count: entry.count,
      reset_at: new Date(entry.windowStart + windowSeconds * 1000).toISOString(),
    };
  }

  async cleanupExpiredFiles(): Promise<CleanupResult> {
    let expiredTransfers = 0;
    let expiredRequests = 0;
    let expiredPendingItems = 0;
    const now = Date.now();

    for (const t of this.transfers.values()) {
      if (t.status === "ready" && new Date(t.expiresAt).getTime() <= now) {
        t.status = "expired";
        this.enqueueDeletion(t.storagePath, new Date(now).toISOString());
        expiredTransfers++;
      }
    }

    for (const r of this.requests.values()) {
      if (r.status === "active" && new Date(r.expiresAt).getTime() <= now) {
        r.status = "expired";
        expiredRequests++;
        for (const item of this.requestItems.values()) {
          if (item.requestId === r.id && item.status !== "deleted") {
            item.status = "deleted";
            this.enqueueDeletion(item.storagePath, new Date(now).toISOString());
          }
        }
      }
    }

    const twoHoursAgo = now - 2 * 60 * 60 * 1000;
    for (const item of this.requestItems.values()) {
      if (item.status === "pending_upload" && new Date(item.createdAt).getTime() <= twoHoursAgo) {
        item.status = "expired";
        this.enqueueDeletion(item.storagePath, new Date(now).toISOString());
        expiredPendingItems++;
      }
    }

    return {
      expiredTransfers,
      expiredRequests,
      expiredPendingItems,
      queuedForDeletion: this.deletionQueue.size,
    };
  }

  async claimDeletionQueueBatch(batchSize: number, leaseMinutes: number = 5): Promise<ClaimDeletionQueueResult[]> {
    const now = Date.now();
    const candidates: Array<{ id: string; storagePath: string; attempts: number; deleteAfter: string }> = [];

    for (const item of this.deletionQueue.values()) {
      const deleteAfterMs = new Date(item.deleteAfter).getTime();
      const claimExpired = !item.claimExpiresAt || new Date(item.claimExpiresAt).getTime() <= now;
      if (deleteAfterMs <= now && claimExpired && item.attempts < 5) {
        candidates.push({
          id: item.id,
          storagePath: item.storagePath,
          attempts: item.attempts,
          deleteAfter: item.deleteAfter,
        });
      }
    }

    candidates.sort((a, b) => new Date(a.deleteAfter).getTime() - new Date(b.deleteAfter).getTime());
    const selected = candidates.slice(0, batchSize);

    const results: ClaimDeletionQueueResult[] = [];
    const leaseExpires = new Date(now + leaseMinutes * 60 * 1000).toISOString();
    for (const sel of selected) {
      const entry = this.deletionQueue.get(sel.storagePath);
      if (entry) {
        entry.attempts += 1;
        entry.claimExpiresAt = leaseExpires;
        results.push({
          id: entry.id,
          storagePath: entry.storagePath,
          attempts: entry.attempts,
        });
      }
    }
    return results;
  }

  async finalizeDeletionQueueSuccess(ids: string[]): Promise<void> {
    const idSet = new Set(ids);
    for (const [path, entry] of this.deletionQueue.entries()) {
      if (idSet.has(entry.id)) {
        this.deletionQueue.delete(path);
      }
    }
  }

  async recordDeletionQueueFailure(id: string, error: string): Promise<void> {
    for (const entry of this.deletionQueue.values()) {
      if (entry.id === id) {
        entry.lastError = error;
        entry.claimExpiresAt = null;
        const backoffMinutes = Math.min(60, 5 * Math.pow(2, Math.max(0, entry.attempts - 1)));
        entry.deleteAfter = new Date(Date.now() + backoffMinutes * 60 * 1000).toISOString();
        break;
      }
    }
  }

  async createSignedUploadUrl(storagePath: string): Promise<string> {
    return `https://mock-storage.once.internal/upload?path=${encodeURIComponent(storagePath)}&token=mock-upload-token`;
  }

  async createSignedDownloadUrl(storagePath: string): Promise<string> {
    return `https://mock-storage.once.internal/download?path=${encodeURIComponent(storagePath)}&token=mock-download-token`;
  }

  async deleteStorageObjects(storagePaths: string[]): Promise<void> {
    for (const path of storagePaths) {
      this.deletionQueue.delete(path);
    }
  }
}

/* ========================================================================== */
/* Supabase PostgreSQL File Repository (Production)                           */
/* ========================================================================== */

export class SupabaseFileRepository implements FileRepository {
  private client: SupabaseClient;

  constructor(client?: SupabaseClient) {
    this.client = client ?? getServerSupabaseClient();
  }

  async createTransfer(params: InsertTransferParams): Promise<InsertTransferResult> {
    const { data, error } = await this.client
      .from("file_transfers")
      .insert({
        transfer_token: params.transferToken,
        storage_path: params.storagePath,
        encrypted_meta: params.encryptedMeta,
        pop_public_key_spki: params.popPublicKeySpki,
        max_downloads: params.maxDownloads,
        expires_at: params.expiresAt,
        status: "pending_upload",
      })
      .select()
      .single();

    if (error) {
      if (error.code === "23505") {
        return { ok: false, reason: "token_conflict" };
      }
      return { ok: false, reason: "db_error", message: error.message };
    }

    return {
      ok: true,
      record: {
        id: data.id,
        transferToken: data.transfer_token,
        storagePath: data.storage_path,
        encryptedMeta: JSON.stringify(data.encrypted_meta),
        popPublicKeySpki: data.pop_public_key_spki,
        maxDownloads: data.max_downloads,
        downloadCount: data.download_count,
        status: data.status,
        expiresAt: data.expires_at,
        createdAt: data.created_at,
      },
    };
  }

  async confirmTransfer(transferToken: string): Promise<ConfirmTransferResult> {
    const { data, error } = await this.client.rpc("confirm_transfer_upload", {
      p_transfer_token: transferToken,
    });

    if (error || !data || data.length === 0) {
      return { ok: false, reason: error?.message ?? "confirm_transfer_rpc_failed" };
    }

    const row = data[0];
    if (!row.res_success) return { ok: false, reason: row.res_reason };

    return { ok: true };
  }

  async getTransferByToken(token: string): Promise<FileTransferRecord | null> {
    const { data, error } = await this.client
      .from("file_transfers")
      .select("*")
      .eq("transfer_token", token)
      .maybeSingle();

    if (error || !data) return null;

    return {
      id: data.id,
      transferToken: data.transfer_token,
      storagePath: data.storage_path,
      encryptedMeta: typeof data.encrypted_meta === "string" ? data.encrypted_meta : JSON.stringify(data.encrypted_meta),
      popPublicKeySpki: data.pop_public_key_spki,
      maxDownloads: data.max_downloads,
      downloadCount: data.download_count,
      status: data.status,
      expiresAt: data.expires_at,
      createdAt: data.created_at,
    };
  }

  async generateDownloadChallenge(
    transferToken: string,
    clientIp: string
  ): Promise<GenerateChallengeResult> {
    const { data, error } = await this.client.rpc("generate_download_challenge", {
      p_transfer_token: transferToken,
      p_client_ip: clientIp,
    });

    if (error || !data || data.length === 0) {
      return { ok: false, reason: error?.message ?? "challenge_rpc_failed" };
    }

    const row = data[0];
    if (!row.res_success) {
      return { ok: false, reason: row.res_reason };
    }

    return {
      ok: true,
      challengeId: row.res_challenge_id,
      challengeNonce: row.res_challenge_nonce,
      fileId: row.res_file_id,
      popPublicKeySpki: row.res_pop_public_key_spki,
    };
  }

  async getChallengeById(challengeId: string): Promise<DownloadChallengeRecord | null> {
    const { data, error } = await this.client
      .from("download_challenges")
      .select("*")
      .eq("id", challengeId)
      .maybeSingle();

    if (error || !data) return null;

    return {
      id: data.id,
      fileId: data.file_id,
      challengeNonce: data.challenge_nonce,
      status: data.status,
      expiresAt: data.expires_at,
      createdAt: data.created_at,
      consumedAt: data.consumed_at,
    };
  }

  async consumeDownload(
    fileId: string,
    challengeId: string,
    gracePeriodMinutes: number = 10
  ): Promise<ConsumeDownloadResult> {
    const { data, error } = await this.client.rpc("consume_file_download", {
      p_file_id: fileId,
      p_challenge_id: challengeId,
      p_grace_period_minutes: gracePeriodMinutes,
    });

    if (error || !data || data.length === 0) {
      return { ok: false, reason: error?.message ?? "consume_rpc_failed" };
    }

    const row = data[0];
    if (!row.res_success) {
      return { ok: false, reason: row.res_reason };
    }

    return { ok: true, storagePath: row.res_storage_path };
  }

  async createFileRequest(params: InsertFileRequestParams): Promise<InsertFileRequestResult> {
    const { data, error } = await this.client
      .from("file_requests")
      .insert({
        request_token: params.requestToken,
        owner_token_hash: params.ownerTokenHash,
        title: params.title,
        creator_public_key_spki: params.creatorPublicKeySpki,
        max_files: params.maxFiles,
        max_bytes_per_file: params.maxBytesPerFile,
        expires_at: params.expiresAt,
        status: "active",
      })
      .select()
      .single();

    if (error) {
      if (error.code === "23505") return { ok: false, reason: "token_conflict" };
      return { ok: false, reason: "db_error", message: error.message };
    }

    return {
      ok: true,
      record: {
        id: data.id,
        requestToken: data.request_token,
        ownerTokenHash: data.owner_token_hash,
        title: data.title,
        creatorPublicKeySpki: data.creator_public_key_spki,
        maxFiles: data.max_files,
        maxBytesPerFile: data.max_bytes_per_file,
        filesCount: data.files_count,
        status: data.status,
        expiresAt: data.expires_at,
        createdAt: data.created_at,
        closedAt: data.closed_at,
      },
    };
  }

  async getFileRequestByToken(requestToken: string): Promise<FileRequestRecord | null> {
    const { data, error } = await this.client
      .from("file_requests")
      .select("*")
      .eq("request_token", requestToken)
      .maybeSingle();

    if (error || !data) return null;

    return {
      id: data.id,
      requestToken: data.request_token,
      ownerTokenHash: data.owner_token_hash,
      title: data.title,
      creatorPublicKeySpki: data.creator_public_key_spki,
      maxFiles: data.max_files,
      maxBytesPerFile: data.max_bytes_per_file,
      filesCount: data.files_count,
      status: data.status,
      expiresAt: data.expires_at,
      createdAt: data.created_at,
      closedAt: data.closed_at,
    };
  }

  async getFileRequestByOwnerHash(ownerTokenHash: string): Promise<FileRequestRecord | null> {
    const { data, error } = await this.client
      .from("file_requests")
      .select("*")
      .eq("owner_token_hash", ownerTokenHash)
      .maybeSingle();

    if (error || !data) return null;

    return {
      id: data.id,
      requestToken: data.request_token,
      ownerTokenHash: data.owner_token_hash,
      title: data.title,
      creatorPublicKeySpki: data.creator_public_key_spki,
      maxFiles: data.max_files,
      maxBytesPerFile: data.max_bytes_per_file,
      filesCount: data.files_count,
      status: data.status,
      expiresAt: data.expires_at,
      createdAt: data.created_at,
      closedAt: data.closed_at,
    };
  }

  async reserveRequestItem(
    requestToken: string,
    storagePath: string,
    sizeBytes: number
  ): Promise<ReserveItemResult> {
    const { data, error } = await this.client.rpc("reserve_request_item", {
      p_request_token: requestToken,
      p_storage_path: storagePath,
      p_size_bytes: sizeBytes,
    });

    if (error || !data || data.length === 0) {
      return { ok: false, reason: error?.message ?? "reserve_rpc_failed" };
    }

    const row = data[0];
    if (!row.res_success) return { ok: false, reason: row.res_reason };

    return { ok: true, itemId: row.res_item_id, requestId: row.res_request_id };
  }

  async confirmRequestItem(
    itemId: string,
    guestPublicKeySpki: string,
    wrappedKeyBundle: Record<string, unknown>,
    encryptedMeta: Record<string, unknown>
  ): Promise<ConfirmItemResult> {
    const { data, error } = await this.client.rpc("confirm_request_item", {
      p_item_id: itemId,
      p_guest_public_key_spki: guestPublicKeySpki,
      p_wrapped_key_bundle: wrappedKeyBundle,
      p_encrypted_meta: encryptedMeta,
    });

    if (error || !data || data.length === 0) {
      return { ok: false, reason: error?.message ?? "confirm_rpc_failed" };
    }

    const row = data[0];
    if (!row.res_success) return { ok: false, reason: row.res_reason };

    return { ok: true };
  }

  async getRequestItems(requestId: string): Promise<FileRequestItemRecord[]> {
    const { data, error } = await this.client
      .from("file_request_items")
      .select("*")
      .eq("request_id", requestId)
      .eq("status", "ready")
      .order("created_at", { ascending: false });

    if (error || !data) return [];

    return data.map((d) => ({
      id: d.id,
      requestId: d.request_id,
      storagePath: d.storage_path,
      sizeBytes: d.size_bytes,
      guestPublicKeySpki: d.guest_public_key_spki,
      wrappedKeyBundle: typeof d.wrapped_key_bundle === "string" ? d.wrapped_key_bundle : JSON.stringify(d.wrapped_key_bundle),
      encryptedMeta: typeof d.encrypted_meta === "string" ? d.encrypted_meta : JSON.stringify(d.encrypted_meta),
      status: d.status,
      createdAt: d.created_at,
    }));
  }

  async getRequestItemById(itemId: string): Promise<FileRequestItemRecord | null> {
    const { data, error } = await this.client
      .from("file_request_items")
      .select("*")
      .eq("id", itemId)
      .maybeSingle();

    if (error || !data) return null;

    return {
      id: data.id,
      requestId: data.request_id,
      storagePath: data.storage_path,
      sizeBytes: data.size_bytes,
      guestPublicKeySpki: data.guest_public_key_spki,
      wrappedKeyBundle: typeof data.wrapped_key_bundle === "string" ? data.wrapped_key_bundle : JSON.stringify(data.wrapped_key_bundle),
      encryptedMeta: typeof data.encrypted_meta === "string" ? data.encrypted_meta : JSON.stringify(data.encrypted_meta),
      status: data.status,
      createdAt: data.created_at,
    };
  }

  async deleteRequestItem(ownerTokenHash: string, itemId: string): Promise<DeleteItemResult> {
    const { data, error } = await this.client.rpc("delete_request_item", {
      p_owner_token_hash: ownerTokenHash,
      p_item_id: itemId,
    });

    if (error || !data || data.length === 0) {
      return { ok: false, reason: error?.message ?? "delete_item_rpc_failed" };
    }

    const row = data[0];
    if (!row.res_success) return { ok: false, reason: row.res_reason };

    return { ok: true };
  }

  async closeFileRequest(ownerTokenHash: string): Promise<CloseRequestResult> {
    const { data, error } = await this.client.rpc("close_file_request", {
      p_owner_token_hash: ownerTokenHash,
    });

    if (error || !data || data.length === 0) {
      return { ok: false, reason: error?.message ?? "close_request_rpc_failed" };
    }

    const row = data[0];
    if (!row.res_success) return { ok: false, reason: row.res_reason };

    return { ok: true };
  }

  async checkRateLimit(
    key: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<CheckRateLimitRpcRow> {
    const { data, error } = await this.client.rpc("check_rate_limit", {
      p_key: key,
      p_max_requests: maxRequests,
      p_window_seconds: windowSeconds,
    });

    if (error || !data || data.length === 0) {
      // In case of error, defensively allow or disallow according to policy
      return {
        allowed: false,
        current_count: maxRequests + 1,
        reset_at: new Date(Date.now() + windowSeconds * 1000).toISOString(),
      };
    }

    return data[0] as CheckRateLimitRpcRow;
  }

  async cleanupExpiredFiles(): Promise<CleanupResult> {
    const { data, error } = await this.client.rpc("cleanup_expired_files_cron");
    if (error || !data || data.length === 0) {
      return { expiredTransfers: 0, expiredRequests: 0, expiredPendingItems: 0, queuedForDeletion: 0 };
    }

    const row = data[0];
    return {
      expiredTransfers: row.expired_transfers_count ?? 0,
      expiredRequests: row.expired_requests_count ?? 0,
      expiredPendingItems: row.expired_pending_items_count ?? 0,
      queuedForDeletion: row.queued_for_deletion_count ?? 0,
    };
  }

  async claimDeletionQueueBatch(batchSize: number, leaseMinutes: number = 5): Promise<ClaimDeletionQueueResult[]> {
    const { data, error } = await this.client.rpc("claim_deletion_queue_batch", {
      p_batch_size: batchSize,
      p_lease_seconds: leaseMinutes * 60,
    });

    if (error || !data) {
      return [];
    }

    return data.map((d: { res_id?: string; queue_id?: string; res_storage_path?: string; storage_path?: string; res_attempts?: number; attempts?: number }) => ({
      id: d.res_id ?? d.queue_id ?? "",
      storagePath: d.res_storage_path ?? d.storage_path ?? "",
      attempts: d.res_attempts ?? d.attempts ?? 0,
    }));
  }

  async finalizeDeletionQueueSuccess(ids: string[]): Promise<void> {
    if (ids.length === 0) return;
    await this.client.rpc("finalize_deletion_queue_success", {
      p_ids: ids,
    });
  }

  async recordDeletionQueueFailure(id: string, error: string): Promise<void> {
    await this.client.rpc("record_deletion_queue_failure", {
      p_id: id,
      p_error: error,
    });
  }

  async createSignedUploadUrl(storagePath: string): Promise<string> {
    const { data, error } = await this.client.storage
      .from(BUCKET_NAME)
      .createSignedUploadUrl(storagePath);

    if (error || !data) {
      throw new Error(`Failed to create signed upload URL: ${error?.message}`);
    }

    return data.signedUrl;
  }

  async createSignedDownloadUrl(storagePath: string, expiresInSeconds: number = 60): Promise<string> {
    const { data, error } = await this.client.storage
      .from(BUCKET_NAME)
      .createSignedUrl(storagePath, expiresInSeconds);

    if (error || !data) {
      throw new Error(`Failed to create signed download URL: ${error?.message}`);
    }

    return data.signedUrl;
  }

  async deleteStorageObjects(storagePaths: string[]): Promise<void> {
    if (storagePaths.length === 0) return;
    await this.client.storage.from(BUCKET_NAME).remove(storagePaths);
  }
}

/* ========================================================================== */
/* Active Repository Resolver                                                 */
/* ========================================================================== */

let activeFileRepository: FileRepository | null = null;

export function getActiveFileRepository(): FileRepository {
  if (activeFileRepository) {
    return activeFileRepository;
  }

  if (isSupabaseConfigured()) {
    activeFileRepository = new SupabaseFileRepository();
    return activeFileRepository;
  }

  if (process.env.NODE_ENV === "test") {
    activeFileRepository = new AtomicMemoryFileRepository();
    return activeFileRepository;
  }

  throw new Error("Supabase is not configured and in-memory repository is disabled in non-test environment.");
}

export function setFileRepositoryForTests(repo: FileRepository | null): void {
  activeFileRepository = repo;
}
