"use client";

import { useEffect, useState, useTransition } from "react";
import {
  Download,
  Lock,
  Check,
  AlertCircle,
  FileText,
  Loader2,
  ShieldAlert,
} from "lucide-react";
import { useApp } from "@/components/providers/AppProviders";
import { cn } from "@/lib/utils/cn";
import {
  CHUNK_SIZE_BYTES,
  AES_GCM_TAG_LENGTH_BYTES,
  parseTransferFragment,
  unwrapKeysWithPassword,
  importRawFileKey,
  importPopPrivateKeyPkcs8,
  signDownloadChallenge,
  decryptChunk,
  decryptMetadata,
  sha256Digest,
  type FragmentParsedData,
} from "@/lib/files/crypto";
import { bytesToBase64Url } from "@/lib/secrets/crypto";
import type { EncryptedFileMetadata } from "@/types/files";

interface FileDownloaderProps {
  token: string;
}

export function FileDownloader({ token }: FileDownloaderProps) {
  const { t } = useApp();
  const [fragmentData, setFragmentData] = useState<FragmentParsedData | null>(null);
  const [fragmentError, setFragmentError] = useState<string | null>(null);

  const [password, setPassword] = useState("");
  const [passwordError, setPasswordError] = useState<string | null>(null);

  const [isProcessing, setIsProcessing] = useState(false);
  const [progressText, setProgressText] = useState("");
  const [progressPct, setProgressPct] = useState(0);
  const [downloadSuccess, setDownloadSuccess] = useState(false);
  const [downloadedFileName, setDownloadedFileName] = useState("");

  const [errorStatus, setErrorStatus] = useState<string | null>(null);

  // Parse fragment on client mount
  useEffect(() => {
    try {
      const hash = window.location.hash;
      if (!hash || hash.length <= 1) {
        setFragmentError("Il link è privo della chiave crittografica nel frammento (#). Impossibile decifrare il file.");
        return;
      }
      const parsed = parseTransferFragment(hash);
      setFragmentData(parsed);
    } catch (e) {
      setFragmentError(e instanceof Error ? e.message : "Formato frammento non valido.");
    }
  }, []);

  const handleDownload = async () => {
    if (!fragmentData) return;

    try {
      setIsProcessing(true);
      setErrorStatus(null);
      setPasswordError(null);
      setProgressPct(10);
      setProgressText("Richiesta challenge crittografica al server...");

      // 1. If password protected, unwrap keys in memory
      let fileKeyBytes: Uint8Array;
      let popPrivateKeyPkcs8: string;
      const baseIv = fragmentData.baseIv;

      if (fragmentData.mode === "pwd") {
        if (!password) {
          setPasswordError("Inserisci la password per decifrare il file.");
          setIsProcessing(false);
          return;
        }
        try {
          const unwrapped = await unwrapKeysWithPassword(
            fragmentData.saltB64,
            fragmentData.ivB64,
            fragmentData.wrappedBundleB64,
            password
          );
          fileKeyBytes = unwrapped.fileKeyBytes;
          popPrivateKeyPkcs8 = unwrapped.popPrivateKeyPkcs8B64;
        } catch {
          setPasswordError("Password errata. La verifica crittografica locale è fallita.");
          setIsProcessing(false);
          return;
        }
      } else {
        fileKeyBytes = fragmentData.fileKeyBytes;
        popPrivateKeyPkcs8 = fragmentData.popPrivateKeyPkcs8;
      }

      const fileKey = await importRawFileKey(fileKeyBytes);
      const popPrivateKey = await importPopPrivateKeyPkcs8(popPrivateKeyPkcs8);

      // 2. Request challenge from server
      const chalRes = await fetch("/api/files/download/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ transferToken: token }),
      });

      if (!chalRes.ok) {
        const err = await chalRes.json().catch(() => ({}));
        if (chalRes.status === 410) {
          setErrorStatus("expired");
        } else {
          setErrorStatus(err.message || "Errore nella richiesta di download.");
        }
        setIsProcessing(false);
        return;
      }

      const { challengeId, challengeNonce, fileId, encryptedMeta } = await chalRes.json();

      setProgressPct(30);
      setProgressText("Firma Proof of Possession (ECDSA P-256)...");

      // 3. Compute Proof of Possession signature
      const signatureB64Url = await signDownloadChallenge(
        popPrivateKey,
        fileId,
        challengeId,
        challengeNonce
      );

      setProgressPct(45);
      setProgressText("Autorizzazione download e ricezione Signed URL...");

      // 4. Consume download and get signed URL
      const consumeRes = await fetch("/api/files/download/consume", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          transferToken: token,
          challengeId,
          signatureB64Url,
        }),
      });

      if (!consumeRes.ok) {
        const err = await consumeRes.json().catch(() => ({}));
        setErrorStatus(err.message || "Autorizzazione download non riuscita.");
        setIsProcessing(false);
        return;
      }

      const { downloadUrl } = await consumeRes.json();

      setProgressPct(60);
      setProgressText("Scaricamento del file cifrato dallo storage...");

      // 5. Download ciphertext directly from Supabase Storage
      const storageRes = await fetch(downloadUrl);
      if (!storageRes.ok) {
        throw new Error("Impossibile scaricare i dati dal server di storage.");
      }
      const ciphertextBuffer = await storageRes.arrayBuffer();

      setProgressPct(80);
      setProgressText("Decifratura dei chunk in memoria (AES-256-GCM)...");

      // 6. Decrypt metadata
      let meta: EncryptedFileMetadata;
      try {
        meta = await decryptMetadata(encryptedMeta.data, encryptedMeta.iv, fileKey);
      } catch {
        throw new Error("Decifratura dei metadati fallita.");
      }

      // 7. Decrypt chunks
      const decryptedParts: Uint8Array[] = [];
      const encryptedChunkSize = CHUNK_SIZE_BYTES + AES_GCM_TAG_LENGTH_BYTES;
      const count = meta.chunkCount;
      let offset = 0;

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
          "once-transfer"
        );
        decryptedParts.push(decChunk);
      }

      setProgressPct(95);
      setProgressText("Verifica integrità SHA-256 e composizione file...");

      // 8. Assemble full plaintext buffer & verify root SHA-256 integrity hash
      const fullPlaintext = new Uint8Array(meta.originalSize);
      let pOffset = 0;
      for (const part of decryptedParts) {
        fullPlaintext.set(part, pOffset);
        pOffset += part.byteLength;
      }

      const calculatedHash = await sha256Digest(fullPlaintext);
      const calculatedHashB64 = bytesToBase64Url(calculatedHash);

      if (calculatedHashB64 !== meta.sha256Hash) {
        throw new Error("Verifica integrità fallita! Il file decifrato non corrisponde all'originale.");
      }

      // 9. Trigger browser download
      const blob = new Blob([fullPlaintext], { type: meta.mimeType });
      const blobUrl = URL.createObjectURL(blob);
      const downloadAnchor = document.createElement("a");
      downloadAnchor.href = blobUrl;
      downloadAnchor.download = meta.originalName;
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      document.body.removeChild(downloadAnchor);
      URL.revokeObjectURL(blobUrl);

      setProgressPct(100);
      setDownloadedFileName(meta.originalName);
      setDownloadSuccess(true);
      setIsProcessing(false);
    } catch (err) {
      setIsProcessing(false);
      setErrorStatus(err instanceof Error ? err.message : "Errore durante il download.");
    }
  };

  if (fragmentError) {
    return (
      <div className="w-full max-w-md mx-auto p-6 rounded-xl border border-rose-500/30 bg-rose-500/10 text-center space-y-3">
        <ShieldAlert className="h-8 w-8 text-rose-400 mx-auto" />
        <h2 className="text-base font-medium text-rose-400">Link Incompleto o Non Valido</h2>
        <p className="text-xs text-foreground-muted">{fragmentError}</p>
      </div>
    );
  }

  if (errorStatus === "expired") {
    return (
      <div className="w-full max-w-md mx-auto p-8 rounded-xl border border-border bg-card text-center space-y-3">
        <AlertCircle className="h-8 w-8 text-foreground-muted mx-auto" />
        <h2 className="text-lg font-medium text-foreground">{t.files.download.expiredTitle}</h2>
        <p className="text-xs text-foreground-muted">{t.files.download.expiredDescription}</p>
      </div>
    );
  }

  if (downloadSuccess) {
    return (
      <div className="w-full max-w-md mx-auto p-8 rounded-xl border border-emerald-500/20 bg-card text-center space-y-4">
        <div className="h-12 w-12 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 mx-auto">
          <Check className="h-6 w-6" />
        </div>
        <div>
          <h2 className="text-lg font-medium text-foreground">Download completato</h2>
          <p className="text-xs text-foreground-muted mt-1">{downloadedFileName}</p>
        </div>
        <p className="text-xs text-foreground-muted">
          Il file è stato decifrato e salvato sul tuo dispositivo.
        </p>
      </div>
    );
  }

  return (
    <div className="w-full max-w-md mx-auto space-y-6">
      <div className="rounded-xl border border-border bg-card p-6 sm:p-8 space-y-6 text-center">
        <div className="h-12 w-12 rounded-full bg-secondary flex items-center justify-center text-foreground mx-auto">
          <FileText className="h-6 w-6" />
        </div>

        <div>
          <h2 className="text-lg font-medium text-foreground">{t.files.download.title}</h2>
          <p className="text-xs text-foreground-muted mt-1">{t.files.download.subtitle}</p>
        </div>

        {/* Password input if password-protected */}
        {fragmentData?.mode === "pwd" && (
          <div className="space-y-2 text-left pt-2 border-t border-border">
            <label className="text-xs font-medium uppercase tracking-wider text-foreground-muted flex items-center gap-1.5">
              <Lock className="h-3.5 w-3.5 text-foreground-muted" />
              <span>Password richiesta</span>
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Inserisci la password di decifratura..."
              className="w-full px-3 py-2 rounded-md border border-border bg-background text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-border-focus"
            />
            {passwordError && (
              <p className="text-xs text-rose-400">{passwordError}</p>
            )}
          </div>
        )}

        {/* Progress bar */}
        {isProcessing && (
          <div className="space-y-3 pt-2 text-left">
            <div className="flex justify-between text-xs text-foreground-muted">
              <span>{progressText}</span>
              <span className="font-mono">{progressPct}%</span>
            </div>
            <div className="w-full h-1.5 rounded-full bg-secondary overflow-hidden">
              <div
                className="h-full bg-foreground transition-all duration-200"
                style={{ width: `${progressPct}%` }}
              />
            </div>
          </div>
        )}

        {/* Error message */}
        {errorStatus && errorStatus !== "expired" && (
          <div className="flex items-center gap-2 p-3 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-400 text-xs text-left">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{errorStatus}</span>
          </div>
        )}

        {/* Download action button */}
        {!isProcessing && (
          <button
            type="button"
            onClick={handleDownload}
            className="w-full py-3 rounded-lg bg-foreground text-background font-medium text-sm hover:opacity-90 transition-opacity flex items-center justify-center gap-2"
          >
            <Download className="h-4 w-4" />
            <span>{t.files.download.downloadButton}</span>
          </button>
        )}
      </div>
    </div>
  );
}
