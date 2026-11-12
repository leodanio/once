"use client";

import { useState, useRef, useMemo, type FormEvent, type DragEvent } from "react";
import {
  Upload,
  Check,
  Copy,
  Lock,
  Eye,
  EyeOff,
  Loader2,
  AlertCircle,
  FileText,
  X,
  ArrowRight,
} from "lucide-react";
import { useApp } from "@/components/providers/AppProviders";
import { cn } from "@/lib/utils/cn";
import {
  CHUNK_SIZE_BYTES,
  MAX_FILE_SIZE_BYTES,
  generateFileKey,
  exportRawKey,
  generatePopKeyPair,
  exportPopPublicKeySpki,
  exportPopPrivateKeyPkcs8,
  encryptMetadata,
  encryptChunk,
  StreamingSha256,
  wrapKeysWithPassword,
  formatTransferFragmentRaw,
  formatTransferFragmentPwd,
} from "@/lib/files/crypto";
import { evaluatePasswordStrength, MIN_SECRET_PASSWORD_LENGTH, bytesToBase64Url } from "@/lib/secrets/crypto";
import type { FileExpirationPreset, EncryptedFileMetadata } from "@/types/files";

const EXPIRATION_OPTIONS: { label: string; value: FileExpirationPreset }[] = [
  { label: "10 min", value: "10m" },
  { label: "1 hour", value: "1h" },
  { label: "24 hours", value: "24h" },
  { label: "7 days", value: "7d" },
];

const DOWNLOAD_OPTIONS = [1, 2, 5, 10];

export function FileTransferCreator() {
  const { t } = useApp();
  const [file, setFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [expiration, setExpiration] = useState<FileExpirationPreset>("24h");
  const [maxDownloads, setMaxDownloads] = useState<number>(1);
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [statusMessage, setStatusMessage] = useState("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [generatedLink, setGeneratedLink] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

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
    if (selectedFile.size > MAX_FILE_SIZE_BYTES) {
      setErrorMessage(`Il file supera il limite massimo consentito di 45 MB.`);
      return;
    }
    setFile(selectedFile);
  };

  const pwdStrength = useMemo(() => {
    if (!password) return null;
    return evaluatePasswordStrength(password);
  }, [password]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!file) return;

    if (password && password.length < MIN_SECRET_PASSWORD_LENGTH) {
      setErrorMessage(`La password deve contenere almeno ${MIN_SECRET_PASSWORD_LENGTH} caratteri.`);
      return;
    }

    try {
      setIsUploading(true);
      setUploadProgress(5);
      setStatusMessage("Generazione chiavi crittografiche...");
      setErrorMessage(null);

      // 1. Generate keys
      const fileKey = await generateFileKey();
      const fileKeyBytes = await exportRawKey(fileKey);
      const popKeyPair = await generatePopKeyPair();
      const popPublicKeySpki = await exportPopPublicKeySpki(popKeyPair.publicKey);
      const popPrivateKeyPkcs8 = await exportPopPrivateKeyPkcs8(popKeyPair.privateKey);

      setUploadProgress(15);
      setStatusMessage("Elaborazione e cifratura chunk (AES-256-GCM)...");

      // 2. Process file incrementally in 5MB chunks & calculate plaintext root hash
      const chunkCount = Math.ceil(file.size / CHUNK_SIZE_BYTES) || 1;
      const baseIv = crypto.getRandomValues(new Uint8Array(8));
      const encryptedChunks: Uint8Array[] = [];
      const streamingHasher = new StreamingSha256();

      // Encrypt each 5MB chunk without loading entire file into memory
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
          "once-transfer"
        );
        encryptedChunks.push(encChunk);
        totalEncryptedBytes += encChunk.byteLength;

        const pct = 15 + Math.round(((i + 1) / chunkCount) * 45);
        setUploadProgress(pct);
      }

      const sha256Hash = bytesToBase64Url(streamingHasher.digest());

      setUploadProgress(65);
      setStatusMessage("Cifratura metadati...");

      // 3. Encrypt metadata
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

      // 4. Reserve transfer slot on server
      setStatusMessage("Prenotazione slot di trasferimento...");
      const createRes = await fetch("/api/files/transfer/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          popPublicKeySpki,
          encryptedMeta: { data: encryptedMetaB64, iv: metaIvB64 },
          sizeBytes: totalEncryptedBytes,
          maxDownloads,
          expiration,
        }),
      });

      if (!createRes.ok) {
        const err = await createRes.json().catch(() => ({}));
        throw new Error(err.message || "Impossibile creare lo slot di trasferimento sul server.");
      }

      const { transferToken, signedUploadUrl } = await createRes.json();

      setUploadProgress(75);
      setStatusMessage("Caricamento del file cifrato...");

      // 5. Build encrypted payload as a Blob without monolithic ArrayBuffer allocation
      const encryptedBlob = new Blob(encryptedChunks as BlobPart[], {
        type: "application/octet-stream",
      });

      // 6. Upload directly via Signed Upload URL (single PUT)
      const uploadRes = await fetch(signedUploadUrl, {
        method: "PUT",
        headers: {
          "Content-Type": "application/octet-stream",
        },
        body: encryptedBlob,
      });

      if (!uploadRes.ok) {
        throw new Error("Errore durante l'upload dei dati cifrati verso lo storage.");
      }

      // Confirm upload completion to transition status from pending_upload to ready
      setStatusMessage("Conferma disponibilità trasferimento...");
      const confirmRes = await fetch("/api/files/transfer/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ transferToken }),
      });

      if (!confirmRes.ok) {
        throw new Error("Errore durante la conferma del trasferimento sul server.");
      }

      setUploadProgress(95);
      setStatusMessage("Generazione link sicuro...");

      // 7. Format URL fragment with keys
      let fragment = "";
      if (password) {
        const wrapped = await wrapKeysWithPassword(fileKeyBytes, popPrivateKeyPkcs8, password);
        fragment = formatTransferFragmentPwd(
          wrapped.saltB64,
          wrapped.ivB64,
          wrapped.wrappedBundleB64,
          baseIv
        );
      } else {
        fragment = formatTransferFragmentRaw(fileKeyBytes, popPrivateKeyPkcs8, baseIv);
      }

      const origin = window.location.origin;
      const fullUrl = `${origin}/files/download/${transferToken}${fragment}`;

      setUploadProgress(100);
      setGeneratedLink(fullUrl);
      setIsUploading(false);
    } catch (err) {
      setIsUploading(false);
      setUploadProgress(0);
      setErrorMessage(err instanceof Error ? err.message : "Si è verificato un errore imprevisto.");
    }
  };

  const handleCopyLink = async () => {
    if (!generatedLink) return;
    try {
      await navigator.clipboard.writeText(generatedLink);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
      setCopied(true);
    }
  };

  const handleReset = () => {
    setFile(null);
    setGeneratedLink(null);
    setPassword("");
    setErrorMessage(null);
    setUploadProgress(0);
  };

  // If link generated, show success view
  if (generatedLink) {
    return (
      <div className="w-full max-w-xl mx-auto space-y-6 animate-in fade-in duration-300">
        <div className="rounded-xl border border-border bg-card p-6 sm:p-8 space-y-6">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <Check className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-medium text-foreground">{t.files.send.linkCreated}</h2>
              <p className="text-xs text-foreground-muted">{file?.name} ({formatFileSize(file?.size ?? 0)})</p>
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center gap-2 p-3 rounded-lg border border-border bg-background">
              <input
                type="text"
                readOnly
                value={generatedLink}
                aria-label="Link per scaricare il file"
                className="w-full bg-transparent text-xs sm:text-sm font-mono text-foreground focus:outline-none select-all truncate"
              />
              <button
                type="button"
                onClick={handleCopyLink}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-foreground text-background text-xs font-medium hover:opacity-90 transition-opacity shrink-0"
              >
                {copied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
                <span>{copied ? t.files.send.copied : t.files.send.copyLink}</span>
              </button>
            </div>
            <p className="text-xs text-foreground-muted">
              {t.files.send.linkWarning}
            </p>
          </div>

          <button
            type="button"
            onClick={handleReset}
            className="w-full py-2.5 rounded-lg border border-border bg-secondary hover:bg-secondary-hover text-sm font-medium text-foreground transition-colors"
          >
            Invia un altro file
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-xl mx-auto space-y-6">
      <form onSubmit={handleSubmit} className="space-y-5">
        {/* Dropzone */}
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
              {t.files.send.dragDropNotice}
            </p>
            <p className="text-xs text-foreground-muted">
              {t.files.send.maxSizeNotice}
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

        {/* Options */}
        {file && !isUploading && (
          <div className="space-y-4 rounded-xl border border-border bg-card p-5">
            {/* Expiration */}
            <div className="space-y-2">
              <label className="text-xs font-medium uppercase tracking-wider text-foreground-muted">
                {t.files.send.expiration}
              </label>
              <div className="grid grid-cols-4 gap-2">
                {EXPIRATION_OPTIONS.map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => setExpiration(opt.value)}
                    className={cn(
                      "py-2 text-xs font-medium rounded-md border transition-all text-center",
                      expiration === opt.value
                        ? "border-foreground bg-foreground text-background"
                        : "border-border bg-secondary hover:bg-secondary-hover text-foreground"
                    )}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Max downloads */}
            <div className="space-y-2">
              <label className="text-xs font-medium uppercase tracking-wider text-foreground-muted">
                {t.files.send.maxDownloads}
              </label>
              <div className="grid grid-cols-4 gap-2">
                {DOWNLOAD_OPTIONS.map((val) => (
                  <button
                    key={val}
                    type="button"
                    onClick={() => setMaxDownloads(val)}
                    className={cn(
                      "py-2 text-xs font-medium rounded-md border transition-all text-center",
                      maxDownloads === val
                        ? "border-foreground bg-foreground text-background"
                        : "border-border bg-secondary hover:bg-secondary-hover text-foreground"
                    )}
                  >
                    {val === 1 ? "1 download" : `${val} download`}
                  </button>
                ))}
              </div>
            </div>

            {/* Password */}
            <div className="space-y-2 pt-2 border-t border-border">
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium uppercase tracking-wider text-foreground-muted">
                  {t.files.send.passwordLabel}
                </label>
                <span className="text-[10px] text-foreground-muted font-mono">Opzionale</span>
              </div>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={t.files.send.passwordPlaceholder}
                  className="w-full px-3 py-2 pr-10 rounded-md border border-border bg-background text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-border-focus"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? "Nascondi password" : "Mostra password"}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-foreground-muted hover:text-foreground"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {pwdStrength && (
                <div className="flex items-center gap-1.5 text-xs">
                  <span className="text-foreground-muted">Sicurezza:</span>
                  <span
                    className={cn(
                      "font-medium",
                      pwdStrength === "strong"
                        ? "text-emerald-400"
                        : pwdStrength === "medium"
                        ? "text-amber-400"
                        : "text-rose-400"
                    )}
                  >
                    {pwdStrength === "strong" ? "Forte" : pwdStrength === "medium" ? "Media" : "Troppo corta (min. 8 car.)"}
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Upload Progress */}
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
            <p className="text-xs text-foreground-muted flex items-center gap-1.5">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              Non chiudere questa scheda fino al termine del trasferimento.
            </p>
          </div>
        )}

        {/* Error message */}
        {errorMessage && (
          <div className="flex items-center gap-2 p-3 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-400 text-xs">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Submit button */}
        {file && !isUploading && (
          <button
            type="submit"
            className="w-full py-3 rounded-lg bg-foreground text-background font-medium text-sm hover:opacity-90 transition-opacity flex items-center justify-center gap-2"
          >
            <span>{t.files.send.generateButton}</span>
            <ArrowRight className="h-4 w-4" />
          </button>
        )}
      </form>
    </div>
  );
}
