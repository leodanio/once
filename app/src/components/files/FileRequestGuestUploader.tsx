"use client";

import { useEffect, useState, useRef, type FormEvent, type DragEvent } from "react";
import {
  Upload,
  Check,
  ShieldCheck,
  ShieldAlert,
  AlertCircle,
  FileText,
  Loader2,
  X,
} from "lucide-react";
import { useApp } from "@/components/providers/AppProviders";
import { cn } from "@/lib/utils/cn";
import {
  CHUNK_SIZE_BYTES,
  generateFileKey,
  exportRawKey,
  generateEcdhKeyPair,
  exportEcdhPublicKeySpki,
  importEcdhPublicKeySpki,
  computePublicKeyFingerprint,
  deriveEcdhSharedKey,
  wrapFileKeyWithEcdh,
  encryptMetadata,
  encryptChunk,
  StreamingSha256,
} from "@/lib/files/crypto";
import { bytesToBase64Url } from "@/lib/secrets/crypto";
import type { EncryptedFileMetadata } from "@/types/files";

interface FileRequestGuestUploaderProps {
  token: string;
}

export function FileRequestGuestUploader({ token }: FileRequestGuestUploaderProps) {
  const { t } = useApp();
  const [requestInfo, setRequestInfo] = useState<{
    title: string;
    creatorPublicKeySpki: string;
    maxFiles: number;
    filesCount: number;
    maxBytesPerFile: number;
    status: string;
    expiresAt: string;
  } | null>(null);

  const [isLoadingRequest, setIsLoadingRequest] = useState(true);
  const [fingerprintVerified, setFingerprintVerified] = useState(false);
  const [fingerprintMismatch, setFingerprintMismatch] = useState(false);

  const [file, setFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [statusMessage, setStatusMessage] = useState("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [uploadSuccess, setUploadSuccess] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  useEffect(() => {
    async function loadRequest() {
      try {
        setIsLoadingRequest(true);
        const res = await fetch(`/api/files/request/${token}`);
        if (!res.ok) {
          throw new Error("Richiesta file non trovata o non valida.");
        }
        const data = await res.json();
        setRequestInfo(data);

        // Verify fingerprint from fragment
        const hash = window.location.hash.replace(/^#/, "");
        if (hash) {
          const calculatedFp = await computePublicKeyFingerprint(data.creatorPublicKeySpki);
          if (calculatedFp === hash) {
            setFingerprintVerified(true);
          } else {
            setFingerprintMismatch(true);
          }
        }
      } catch (err) {
        setErrorMessage(err instanceof Error ? err.message : "Errore nel caricamento della richiesta.");
      } finally {
        setIsLoadingRequest(false);
      }
    }
    loadRequest();
  }, [token]);

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelected = (selectedFile: File) => {
    setErrorMessage(null);
    if (!requestInfo) return;
    if (selectedFile.size > requestInfo.maxBytesPerFile) {
      setErrorMessage(`Il file supera il limite massimo consentito di ${formatFileSize(requestInfo.maxBytesPerFile)}.`);
      return;
    }
    setFile(selectedFile);
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!file || !requestInfo || fingerprintMismatch) return;

    try {
      setIsUploading(true);
      setUploadProgress(5);
      setStatusMessage("Generazione chiavi crittografiche effimere...");
      setErrorMessage(null);

      // 1. Generate ephemeral file key and guest ECDH key pair
      const fileKey = await generateFileKey();
      const fileKeyBytes = await exportRawKey(fileKey);
      const guestEcdhPair = await generateEcdhKeyPair();
      const guestPublicKeySpki = await exportEcdhPublicKeySpki(guestEcdhPair.publicKey);

      // 2. Import creator ECDH public key & derive shared secret
      const creatorPublicKey = await importEcdhPublicKeySpki(requestInfo.creatorPublicKeySpki);
      const sharedKey = await deriveEcdhSharedKey(guestEcdhPair.privateKey, creatorPublicKey);

      // 3. Wrap file key with shared secret
      const wrappedBundle = await wrapFileKeyWithEcdh(fileKeyBytes, sharedKey);

      setUploadProgress(20);
      setStatusMessage("Cifratura del file in blocchi da 5 MB (AES-256-GCM)...");

      // 4. Encrypt file incrementally in 5MB chunks & calculate plaintext root SHA-256
      const chunkCount = Math.ceil(file.size / CHUNK_SIZE_BYTES) || 1;
      const baseIv = crypto.getRandomValues(new Uint8Array(8));
      const encryptedChunks: Uint8Array[] = [];
      const streamingHasher = new StreamingSha256();

      let totalEncryptedBytes = 0;
      for (let i = 0; i < chunkCount; i++) {
        const start = i * CHUNK_SIZE_BYTES;
        const end = Math.min(start + CHUNK_SIZE_BYTES, file.size);
        const chunkSlice = await file.slice(start, end).arrayBuffer();
        streamingHasher.update(chunkSlice);

        const isLast = i === chunkCount - 1;
        const encChunk = await encryptChunk(
          chunkSlice,
          fileKey,
          baseIv,
          i,
          isLast,
          token
        );
        encryptedChunks.push(encChunk);
        totalEncryptedBytes += encChunk.byteLength;

        const pct = 20 + Math.round(((i + 1) / chunkCount) * 45);
        setUploadProgress(pct);
      }

      const sha256Hash = bytesToBase64Url(streamingHasher.digest());

      setUploadProgress(70);
      setStatusMessage("Cifratura dei metadati...");

      const meta: EncryptedFileMetadata = {
        originalName: file.name,
        originalSize: file.size,
        mimeType: file.type || "application/octet-stream",
        chunkCount,
        chunkSize: CHUNK_SIZE_BYTES,
        totalEncryptedSize: totalEncryptedBytes,
        sha256Hash,
      };

      const { encryptedMetaB64, metaIvB64 } = await encryptMetadata(meta, fileKey);

      // 5. Reserve upload slot
      setStatusMessage("Prenotazione slot di upload...");
      const reserveRes = await fetch(`/api/files/request/${token}/reserve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sizeBytes: totalEncryptedBytes }),
      });

      if (!reserveRes.ok) {
        const err = await reserveRes.json().catch(() => ({}));
        throw new Error(err.message || "Impossibile prenotare lo slot di upload.");
      }

      const { slotId, signedUploadUrl } = await reserveRes.json();

      setUploadProgress(80);
      setStatusMessage("Upload del file cifrato...");

      // 6. Build Blob & upload to storage via Signed Upload URL (single PUT)
      const encryptedBlob = new Blob(encryptedChunks as BlobPart[], {
        type: "application/octet-stream",
      });

      const uploadRes = await fetch(signedUploadUrl, {
        method: "PUT",
        headers: { "Content-Type": "application/octet-stream" },
        body: encryptedBlob,
      });

      if (!uploadRes.ok) {
        throw new Error("Errore durante l'upload dei dati cifrati verso lo storage.");
      }

      setUploadProgress(95);
      setStatusMessage("Conferma finale dell'invio...");

      // 7. Confirm item
      const confirmRes = await fetch(`/api/files/request/${token}/confirm`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          slotId,
          guestPublicKeySpki,
          wrappedKeyBundle: {
            iv: wrappedBundle.ivB64,
            key: wrappedBundle.wrappedKeyB64,
            baseIv: bytesToBase64Url(baseIv),
          },
          encryptedMeta: { data: encryptedMetaB64, iv: metaIvB64 },
        }),
      });

      if (!confirmRes.ok) {
        const err = await confirmRes.json().catch(() => ({}));
        throw new Error(err.message || "Errore nella conferma dell'upload.");
      }

      setUploadProgress(100);
      setUploadSuccess(true);
      setIsUploading(false);
    } catch (err) {
      setIsUploading(false);
      setUploadProgress(0);
      setErrorMessage(err instanceof Error ? err.message : "Si è verificato un errore.");
    }
  };

  if (isLoadingRequest) {
    return (
      <div className="flex items-center justify-center p-12 text-foreground-muted">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );
  }

  if (fingerprintMismatch) {
    return (
      <div className="w-full max-w-md mx-auto p-6 rounded-xl border border-rose-500/40 bg-rose-500/10 text-center space-y-4">
        <ShieldAlert className="h-10 w-10 text-rose-400 mx-auto" />
        <h2 className="text-base font-semibold text-rose-400">Avviso Critico di Sicurezza</h2>
        <p className="text-xs text-foreground-muted leading-relaxed">
          {t.files.guest.fingerprintMismatch}
        </p>
      </div>
    );
  }

  if (requestInfo?.status !== "active") {
    return (
      <div className="w-full max-w-md mx-auto p-8 rounded-xl border border-border bg-card text-center space-y-3">
        <AlertCircle className="h-8 w-8 text-foreground-muted mx-auto" />
        <h2 className="text-lg font-medium text-foreground">Richiesta Non Attiva</h2>
        <p className="text-xs text-foreground-muted">{t.files.guest.closedOrExpired}</p>
      </div>
    );
  }

  if (uploadSuccess) {
    return (
      <div className="w-full max-w-md mx-auto p-8 rounded-xl border border-emerald-500/20 bg-card text-center space-y-4">
        <div className="h-12 w-12 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 mx-auto">
          <Check className="h-6 w-6" />
        </div>
        <div>
          <h2 className="text-lg font-medium text-foreground">File Inviato con Successo</h2>
          <p className="text-xs text-foreground-muted mt-1">{file?.name}</p>
        </div>
        <p className="text-xs text-foreground-muted">
          Il file è stato cifrato end-to-end ed è ora a disposizione del creatore della richiesta.
        </p>
      </div>
    );
  }

  return (
    <div className="w-full max-w-xl mx-auto space-y-6">
      <div className="text-center space-y-2">
        <h1 className="text-2xl font-medium tracking-tight text-foreground">{requestInfo?.title}</h1>
        <p className="text-xs text-foreground-muted">{t.files.guest.subtitle}</p>

        {fingerprintVerified && (
          <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 text-[11px] font-medium border border-emerald-500/20">
            <ShieldCheck className="h-3.5 w-3.5" />
            <span>{t.files.guest.fingerprintVerified}</span>
          </div>
        )}
      </div>

      <form onSubmit={handleSubmit} className="space-y-5">
        {!file ? (
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={cn(
              "group relative flex flex-col items-center justify-center p-8 sm:p-12 rounded-xl border border-dashed transition-all cursor-pointer text-center",
              isDragging
                ? "border-foreground bg-secondary/60 scale-[0.99]"
                : "border-border hover:border-foreground-muted/50 bg-card/50 hover:bg-card"
            )}
          >
            <input
              ref={fileInputRef}
              type="file"
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  handleFileSelected(e.target.files[0]);
                }
              }}
              className="hidden"
            />
            <div className="h-12 w-12 rounded-full bg-secondary flex items-center justify-center mb-4 text-foreground-muted group-hover:text-foreground transition-colors">
              <Upload className="h-5 w-5" />
            </div>
            <p className="text-sm font-medium text-foreground mb-1">
              Trascina qui il file da inviare
            </p>
            <p className="text-xs text-foreground-muted">
              Massimo {formatFileSize(requestInfo?.maxBytesPerFile ?? 45 * 1024 * 1024)} • Cifratura client-side
            </p>
          </div>
        ) : (
          <div className="flex items-center justify-between p-4 rounded-xl border border-border bg-card">
            <div className="flex items-center gap-3 min-w-0">
              <div className="h-10 w-10 rounded-lg bg-secondary flex items-center justify-center text-foreground shrink-0">
                <FileText className="h-5 w-5" />
              </div>
              <div className="min-w-0">
                <p className="text-sm font-medium text-foreground truncate">{file.name}</p>
                <p className="text-xs text-foreground-muted">{formatFileSize(file.size)}</p>
              </div>
            </div>
            {!isUploading && (
              <button
                type="button"
                onClick={() => setFile(null)}
                aria-label="Rimuovi file selezionato"
                className="p-1.5 rounded-md hover:bg-secondary text-foreground-muted hover:text-foreground transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            )}
          </div>
        )}

        {isUploading && (
          <div className="rounded-xl border border-border bg-card p-6 space-y-4 animate-in fade-in">
            <div className="flex items-center justify-between text-sm">
              <span className="font-medium text-foreground">{statusMessage}</span>
              <span className="font-mono text-foreground-muted">{uploadProgress}%</span>
            </div>
            <div className="w-full h-1.5 rounded-full bg-secondary overflow-hidden">
              <div
                className="h-full bg-foreground transition-all duration-200"
                style={{ width: `${uploadProgress}%` }}
              />
            </div>
          </div>
        )}

        {errorMessage && (
          <div className="flex items-center gap-2 p-3 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-400 text-xs">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        {file && !isUploading && (
          <button
            type="submit"
            className="w-full py-3 rounded-lg bg-foreground text-background font-medium text-sm hover:opacity-90 transition-opacity flex items-center justify-center gap-2"
          >
            <span>{t.files.guest.uploadButton}</span>
          </button>
        )}
      </form>
    </div>
  );
}
