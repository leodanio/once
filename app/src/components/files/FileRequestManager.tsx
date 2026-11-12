"use client";

import { useEffect, useState } from "react";
import {
  Folder,
  Download,
  Trash2,
  Lock,
  Check,
  AlertCircle,
  Loader2,
  FileText,
  XCircle,
} from "lucide-react";
import { useApp } from "@/components/providers/AppProviders";
import { cn } from "@/lib/utils/cn";
import {
  CHUNK_SIZE_BYTES,
  AES_GCM_TAG_LENGTH_BYTES,
  importEcdhPrivateKeyPkcs8,
  importEcdhPublicKeySpki,
  unwrapFileKeyWithEcdh,
  importRawFileKey,
  decryptMetadata,
  decryptChunk,
  StreamingSha256,
} from "@/lib/files/crypto";
import { base64UrlToBytes, bytesToBase64Url } from "@/lib/secrets/crypto";
import type { EncryptedFileMetadata } from "@/types/files";

interface FileRequestManagerProps {
  token?: string; // Optional legacy prop
}

interface RequestItemView {
  id: string;
  sizeBytes: number;
  guestPublicKeySpki: string;
  wrappedKeyBundle: { iv: string; key: string; baseIv: string };
  encryptedMeta: { data: string; iv: string };
  createdAt: string;
  decryptedMeta?: EncryptedFileMetadata;
  isDownloading?: boolean;
}

export function FileRequestManager({ token: legacyToken }: FileRequestManagerProps = {}) {
  const { t } = useApp();
  const [requestInfo, setRequestInfo] = useState<{
    id: string;
    title: string;
    requestToken: string;
    maxFiles: number;
    filesCount: number;
    maxBytesPerFile: number;
    status: string;
    expiresAt: string;
    createdAt: string;
  } | null>(null);

  const [items, setItems] = useState<RequestItemView[]>([]);
  const [ownerToken, setOwnerToken] = useState<string | null>(null);
  const [creatorPrivateKeyPkcs8, setCreatorPrivateKeyPkcs8] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isClosing, setIsClosing] = useState(false);

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  useEffect(() => {
    async function loadData() {
      try {
        setIsLoading(true);

        const hash = window.location.hash.replace(/^#/, "");
        let extractedOwnerToken = legacyToken || "";
        let extractedPrivateKey = "";

        if (hash.startsWith("v1.own.")) {
          const parts = hash.split(".");
          if (parts.length >= 4) {
            extractedOwnerToken = parts[2];
            extractedPrivateKey = parts.slice(3).join(".");
          }
        } else if (hash.includes(".")) {
          const parts = hash.split(".");
          extractedOwnerToken = parts[0];
          extractedPrivateKey = parts.slice(1).join(".");
        } else if (hash && legacyToken) {
          extractedOwnerToken = legacyToken;
          extractedPrivateKey = hash;
        }

        if (!extractedOwnerToken || !extractedPrivateKey) {
          throw new Error("Credenziali di gestione o chiave privata mancanti nel link (#). Impossibile decifrare i file.");
        }

        setOwnerToken(extractedOwnerToken);
        setCreatorPrivateKeyPkcs8(extractedPrivateKey);

        const res = await fetch("/api/files/manage", {
          headers: {
            "X-Owner-Token": extractedOwnerToken,
          },
        });

        if (!res.ok) {
          throw new Error("Richiesta file non trovata o token di gestione non valido.");
        }

        const data = await res.json();
        setRequestInfo(data.request);

        // Client-side decryption of each item's metadata
        const creatorPrivateKey = await importEcdhPrivateKeyPkcs8(extractedPrivateKey);
        const resolvedItems: RequestItemView[] = [];

        for (const item of data.items) {
          try {
            const guestPublicKey = await importEcdhPublicKeySpki(item.guestPublicKeySpki);
            const fileKeyBytes = await unwrapFileKeyWithEcdh(
              item.wrappedKeyBundle.key,
              item.wrappedKeyBundle.iv,
              creatorPrivateKey,
              guestPublicKey
            );
            const fileKey = await importRawFileKey(fileKeyBytes);
            const decMeta = await decryptMetadata(
              item.encryptedMeta.data,
              item.encryptedMeta.iv,
              fileKey
            );
            resolvedItems.push({ ...item, decryptedMeta: decMeta });
          } catch {
            resolvedItems.push(item);
          }
        }

        setItems(resolvedItems);
      } catch (err) {
        setErrorMessage(err instanceof Error ? err.message : "Errore nel caricamento del pannello.");
      } finally {
        setIsLoading(false);
      }
    }
    loadData();
  }, [legacyToken]);

  const handleDownloadItem = async (item: RequestItemView) => {
    if (!creatorPrivateKeyPkcs8 || !ownerToken) return;

    try {
      setItems((prev) =>
        prev.map((i) => (i.id === item.id ? { ...i, isDownloading: true } : i))
      );

      // 1. Get signed download URL
      const res = await fetch(`/api/files/manage/download/${item.id}`, {
        method: "POST",
        headers: {
          "X-Owner-Token": ownerToken,
        },
      });
      if (!res.ok) throw new Error("Errore nella richiesta di download.");

      const { downloadUrl } = await res.json();

      // 2. Fetch ciphertext from storage
      const storageRes = await fetch(downloadUrl);
      if (!storageRes.ok) throw new Error("Errore nel download dei dati cifrati dallo storage.");
      const ciphertextBuffer = await storageRes.arrayBuffer();

      // 3. Derive keys
      const creatorPrivateKey = await importEcdhPrivateKeyPkcs8(creatorPrivateKeyPkcs8);
      const guestPublicKey = await importEcdhPublicKeySpki(item.guestPublicKeySpki);
      const fileKeyBytes = await unwrapFileKeyWithEcdh(
        item.wrappedKeyBundle.key,
        item.wrappedKeyBundle.iv,
        creatorPrivateKey,
        guestPublicKey
      );
      const fileKey = await importRawFileKey(fileKeyBytes);
      const baseIv = base64UrlToBytes(item.wrappedKeyBundle.baseIv);

      // 4. Decrypt metadata
      const meta = await decryptMetadata(item.encryptedMeta.data, item.encryptedMeta.iv, fileKey);

      // 5. Decrypt chunks & verify integrity incrementally
      const decryptedParts: Uint8Array[] = [];
      const encryptedChunkSize = CHUNK_SIZE_BYTES + AES_GCM_TAG_LENGTH_BYTES;
      const count = meta.chunkCount;
      let offset = 0;
      const verifier = new StreamingSha256();

      for (let i = 0; i < count; i++) {
        const isLast = i === count - 1;
        const currentEncChunkSize = isLast ? ciphertextBuffer.byteLength - offset : encryptedChunkSize;
        const chunkCipher = ciphertextBuffer.slice(offset, offset + currentEncChunkSize);
        offset += currentEncChunkSize;

        const decChunk = await decryptChunk(
          chunkCipher,
          fileKey,
          baseIv,
          i,
          isLast,
          requestInfo?.requestToken ?? ""
        );
        verifier.update(decChunk);
        decryptedParts.push(decChunk);
      }

      // 6. Verify SHA-256 integrity
      const calculatedHashB64 = bytesToBase64Url(verifier.digest());
      if (calculatedHashB64 !== meta.sha256Hash) {
        throw new Error("Verifica integrità fallita: il file è corrotto.");
      }

      // 7. Trigger browser file save directly from chunk array
      const blob = new Blob(decryptedParts as BlobPart[], { type: meta.mimeType });
      const blobUrl = URL.createObjectURL(blob);
      const downloadAnchor = document.createElement("a");
      downloadAnchor.href = blobUrl;
      downloadAnchor.download = meta.originalName;
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      document.body.removeChild(downloadAnchor);
      URL.revokeObjectURL(blobUrl);

      setItems((prev) =>
        prev.map((i) => (i.id === item.id ? { ...i, isDownloading: false } : i))
      );
    } catch (err) {
      setItems((prev) =>
        prev.map((i) => (i.id === item.id ? { ...i, isDownloading: false } : i))
      );
      alert(err instanceof Error ? err.message : "Errore durante il download.");
    }
  };

  const handleDeleteItem = async (itemId: string) => {
    if (!ownerToken) return;
    if (!confirm("Sei sicuro di voler eliminare questo file? L'azione è irreversibile.")) return;

    try {
      const res = await fetch(`/api/files/manage/items/${itemId}`, {
        method: "DELETE",
        headers: {
          "X-Owner-Token": ownerToken,
        },
      });
      if (!res.ok) throw new Error("Errore durante l'eliminazione del file.");
      setItems((prev) => prev.filter((i) => i.id !== itemId));
    } catch (err) {
      alert(err instanceof Error ? err.message : "Errore durante l'eliminazione.");
    }
  };

  const handleCloseRequest = async () => {
    if (!ownerToken) return;
    if (!confirm("Sei sicuro di voler chiudere la richiesta? Tutti i file ricevuti verranno pianificati per l'eliminazione e non sarà più possibile caricare nuovi documenti.")) return;

    try {
      setIsClosing(true);
      const res = await fetch("/api/files/manage/close", {
        method: "POST",
        headers: {
          "X-Owner-Token": ownerToken,
        },
      });
      if (!res.ok) throw new Error("Errore durante la chiusura della richiesta.");

      setRequestInfo((prev) => (prev ? { ...prev, status: "closed" } : null));
      setItems([]);
      setIsClosing(false);
    } catch (err) {
      setIsClosing(false);
      alert(err instanceof Error ? err.message : "Errore durante la chiusura.");
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-12 text-foreground-muted">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );
  }

  if (errorMessage) {
    return (
      <div className="w-full max-w-md mx-auto p-6 rounded-xl border border-rose-500/30 bg-rose-500/10 text-center space-y-3">
        <AlertCircle className="h-8 w-8 text-rose-400 mx-auto" />
        <h2 className="text-base font-medium text-rose-400">Pannello Non Accessibile</h2>
        <p className="text-xs text-foreground-muted">{errorMessage}</p>
      </div>
    );
  }

  return (
    <div className="w-full max-w-2xl mx-auto space-y-6">
      {/* Header card */}
      <div className="rounded-xl border border-border bg-card p-6 space-y-4">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <h1 className="text-xl font-medium text-foreground">{requestInfo?.title}</h1>
            <p className="text-xs text-foreground-muted">
              Stato: <span className={cn("font-medium", requestInfo?.status === "active" ? "text-emerald-400" : "text-foreground-muted")}>{requestInfo?.status === "active" ? "Attiva" : "Chiusa"}</span> • File ricevuti: {items.length} / {requestInfo?.maxFiles}
            </p>
          </div>
          {requestInfo?.status === "active" && (
            <button
              type="button"
              onClick={handleCloseRequest}
              disabled={isClosing}
              className="px-3 py-1.5 rounded-md border border-rose-500/30 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 text-xs font-medium transition-colors"
            >
              {isClosing ? t.files.manage.closing : t.files.manage.closeRequest}
            </button>
          )}
        </div>
      </div>

      {/* Files List */}
      <div className="space-y-3">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-foreground-muted">
          {t.files.manage.receivedFiles}
        </h2>

        {items.length === 0 ? (
          <div className="rounded-xl border border-border/50 bg-card/30 p-8 text-center space-y-2">
            <Folder className="h-8 w-8 text-foreground-muted mx-auto opacity-50" />
            <p className="text-xs text-foreground-muted">{t.files.manage.noFiles}</p>
          </div>
        ) : (
          <div className="space-y-2">
            {items.map((item) => (
              <div
                key={item.id}
                className="flex items-center justify-between p-4 rounded-xl border border-border bg-card hover:bg-card-hover transition-colors"
              >
                <div className="flex items-center space-x-3 min-w-0">
                  <div className="p-2 rounded-lg bg-surface border border-border text-primary shrink-0">
                    <FileText className="h-5 w-5" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">
                      {item.decryptedMeta ? item.decryptedMeta.originalName : `File (${formatFileSize(item.sizeBytes)})`}
                    </p>
                    <p className="text-[11px] text-foreground-muted">
                      {item.decryptedMeta ? formatFileSize(item.decryptedMeta.originalSize) : formatFileSize(item.sizeBytes)} • Caricato il {new Date(item.createdAt).toLocaleDateString()}
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-2 shrink-0">
                  <button
                    type="button"
                    onClick={() => handleDownloadItem(item)}
                    disabled={item.isDownloading}
                    className="p-2 rounded-lg border border-border bg-surface hover:bg-surface-hover text-foreground hover:text-primary transition-colors disabled:opacity-50"
                    title={t.files.manage.downloadFile}
                  >
                    {item.isDownloading ? (
                      <Loader2 className="h-4 w-4 animate-spin text-primary" />
                    ) : (
                      <Download className="h-4 w-4" />
                    )}
                  </button>

                  <button
                    type="button"
                    onClick={() => handleDeleteItem(item.id)}
                    className="p-2 rounded-lg border border-border bg-surface hover:bg-rose-500/10 text-foreground-muted hover:text-rose-400 transition-colors"
                    title={t.files.manage.deleteFile}
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
