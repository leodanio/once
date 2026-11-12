"use client";

import { useState, type FormEvent } from "react";
import {
  Check,
  Copy,
  ArrowRight,
  AlertCircle,
  FolderPlus,
  Key,
  Share2,
} from "lucide-react";
import { useApp } from "@/components/providers/AppProviders";
import { cn } from "@/lib/utils/cn";
import {
  generateEcdhKeyPair,
  exportEcdhPublicKeySpki,
  exportEcdhPrivateKeyPkcs8,
  computePublicKeyFingerprint,
} from "@/lib/files/crypto";
import type { FileExpirationPreset } from "@/types/files";

const EXPIRATION_OPTIONS: { label: string; value: FileExpirationPreset }[] = [
  { label: "1 hour", value: "1h" },
  { label: "24 hours", value: "24h" },
  { label: "7 days", value: "7d" },
];

const MAX_FILES_OPTIONS = [1, 3, 5, 10];
const MAX_SIZE_OPTIONS = [
  { label: "10 MB", value: 10 * 1024 * 1024 },
  { label: "25 MB", value: 25 * 1024 * 1024 },
  { label: "45 MB", value: 45 * 1024 * 1024 },
];

export function FileRequestCreator() {
  const { t } = useApp();
  const [title, setTitle] = useState("");
  const [maxFiles, setMaxFiles] = useState(5);
  const [maxBytesPerFile, setMaxBytesPerFile] = useState(45 * 1024 * 1024);
  const [expiration, setExpiration] = useState<FileExpirationPreset>("7d");
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [createdResult, setCreatedResult] = useState<{
    publicUrl: string;
    manageUrl: string;
  } | null>(null);
  const [copiedPublic, setCopiedPublic] = useState(false);
  const [copiedManage, setCopiedManage] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!title.trim()) {
      setErrorMessage("Inserisci un titolo o una descrizione per la richiesta.");
      return;
    }

    try {
      setIsLoading(true);
      setErrorMessage(null);

      // 1. Generate Creator ECDH P-256 Key Pair
      const ecdhPair = await generateEcdhKeyPair();
      const creatorPublicKeySpki = await exportEcdhPublicKeySpki(ecdhPair.publicKey);
      const creatorPrivateKeyPkcs8 = await exportEcdhPrivateKeyPkcs8(ecdhPair.privateKey);

      // 2. Compute SHA-256 fingerprint of the public key
      const fingerprint = await computePublicKeyFingerprint(creatorPublicKeySpki);

      // 3. Call creation API
      const res = await fetch("/api/files/request/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: title.trim(),
          creatorPublicKeySpki,
          maxFiles,
          maxBytesPerFile,
          expiration,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.message || "Errore durante la creazione della richiesta.");
      }

      const { requestToken, ownerToken } = await res.json();
      const origin = window.location.origin;

      // Public upload link has public key fingerprint in fragment
      const publicUrl = `${origin}/files/request/${requestToken}#${fingerprint}`;
      // Private management link contains owner token and private key in fragment only
      const manageUrl = `${origin}/files/manage#v1.own.${ownerToken}.${creatorPrivateKeyPkcs8}`;

      setCreatedResult({ publicUrl, manageUrl });
      setIsLoading(false);
    } catch (err) {
      setIsLoading(false);
      setErrorMessage(err instanceof Error ? err.message : "Si è verificato un errore.");
    }
  };

  const copyToClipboard = async (text: string, type: "public" | "manage") => {
    try {
      await navigator.clipboard.writeText(text);
      if (type === "public") {
        setCopiedPublic(true);
        setTimeout(() => setCopiedPublic(false), 2000);
      } else {
        setCopiedManage(true);
        setTimeout(() => setCopiedManage(false), 2000);
      }
    } catch {
      // Fallback
    }
  };

  const handleReset = () => {
    setTitle("");
    setCreatedResult(null);
    setErrorMessage(null);
  };

  if (createdResult) {
    return (
      <div className="w-full max-w-xl mx-auto space-y-6 animate-in fade-in duration-300">
        <div className="rounded-xl border border-border bg-card p-6 sm:p-8 space-y-6">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <Check className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-medium text-foreground">{t.files.request.requestCreated}</h2>
              <p className="text-xs text-foreground-muted">{title}</p>
            </div>
          </div>

          {/* Public Link */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs font-medium text-foreground uppercase tracking-wider">
              <Share2 className="h-3.5 w-3.5 text-foreground-muted" />
              <span>{t.files.request.publicLinkLabel}</span>
            </div>
            <div className="flex items-center gap-2 p-3 rounded-lg border border-border bg-background">
              <input
                type="text"
                readOnly
                value={createdResult.publicUrl}
                aria-label="Link pubblico per caricare file"
                className="w-full bg-transparent text-xs font-mono text-foreground focus:outline-none select-all truncate"
              />
              <button
                type="button"
                onClick={() => copyToClipboard(createdResult.publicUrl, "public")}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-foreground text-background text-xs font-medium hover:opacity-90 transition-opacity shrink-0"
              >
                {copiedPublic ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
                <span>{copiedPublic ? t.files.request.copied : t.files.request.copyLink}</span>
              </button>
            </div>
          </div>

          {/* Private Owner Link */}
          <div className="space-y-2 pt-2 border-t border-border">
            <div className="flex items-center gap-2 text-xs font-medium text-amber-400 uppercase tracking-wider">
              <Key className="h-3.5 w-3.5" />
              <span>{t.files.request.ownerLinkLabel}</span>
            </div>
            <div className="flex items-center gap-2 p-3 rounded-lg border border-amber-500/30 bg-amber-500/5">
              <input
                type="text"
                readOnly
                value={createdResult.manageUrl}
                aria-label="Link privato di gestione richiesta"
                className="w-full bg-transparent text-xs font-mono text-foreground focus:outline-none select-all truncate"
              />
              <button
                type="button"
                onClick={() => copyToClipboard(createdResult.manageUrl, "manage")}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-foreground text-background text-xs font-medium hover:opacity-90 transition-opacity shrink-0"
              >
                {copiedManage ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
                <span>{copiedManage ? t.files.request.copied : t.files.request.copyLink}</span>
              </button>
            </div>
            <p className="text-xs text-foreground-muted">
              {t.files.request.ownerWarning}
            </p>
          </div>

          <div className="flex gap-3">
            <a
              href={createdResult.manageUrl}
              className="flex-1 py-2.5 rounded-lg bg-foreground text-background text-center text-xs sm:text-sm font-medium hover:opacity-90 transition-opacity"
            >
              Apri pannello di gestione
            </a>
            <button
              type="button"
              onClick={handleReset}
              className="px-4 py-2.5 rounded-lg border border-border bg-secondary hover:bg-secondary-hover text-xs sm:text-sm font-medium text-foreground transition-colors"
            >
              Nuova richiesta
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-xl mx-auto space-y-6">
      <form onSubmit={handleSubmit} className="space-y-5 rounded-xl border border-border bg-card p-6">
        <div className="space-y-2">
          <label className="text-xs font-medium uppercase tracking-wider text-foreground-muted">
            {t.files.request.titleLabel}
          </label>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder={t.files.request.titlePlaceholder}
            className="w-full px-3 py-2.5 rounded-md border border-border bg-background text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-border-focus"
          />
        </div>

        {/* Max Files */}
        <div className="space-y-2">
          <label className="text-xs font-medium uppercase tracking-wider text-foreground-muted">
            {t.files.request.maxFilesLabel}
          </label>
          <div className="grid grid-cols-4 gap-2">
            {MAX_FILES_OPTIONS.map((num) => (
              <button
                key={num}
                type="button"
                onClick={() => setMaxFiles(num)}
                className={cn(
                  "py-2 text-xs font-medium rounded-md border transition-all text-center",
                  maxFiles === num
                    ? "border-foreground bg-foreground text-background"
                    : "border-border bg-secondary hover:bg-secondary-hover text-foreground"
                )}
              >
                {num === 1 ? "1 file" : `${num} file`}
              </button>
            ))}
          </div>
        </div>

        {/* Max Size */}
        <div className="space-y-2">
          <label className="text-xs font-medium uppercase tracking-wider text-foreground-muted">
            {t.files.request.maxFileSizeLabel}
          </label>
          <div className="grid grid-cols-3 gap-2">
            {MAX_SIZE_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                type="button"
                onClick={() => setMaxBytesPerFile(opt.value)}
                className={cn(
                  "py-2 text-xs font-medium rounded-md border transition-all text-center",
                  maxBytesPerFile === opt.value
                    ? "border-foreground bg-foreground text-background"
                    : "border-border bg-secondary hover:bg-secondary-hover text-foreground"
                )}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        {/* Expiration */}
        <div className="space-y-2">
          <label className="text-xs font-medium uppercase tracking-wider text-foreground-muted">
            {t.files.request.expirationLabel}
          </label>
          <div className="grid grid-cols-3 gap-2">
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

        {errorMessage && (
          <div className="flex items-center gap-2 p-3 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-400 text-xs">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        <button
          type="submit"
          disabled={isLoading}
          className="w-full py-3 rounded-lg bg-foreground text-background font-medium text-sm hover:opacity-90 transition-opacity flex items-center justify-center gap-2 disabled:opacity-50"
        >
          {isLoading ? (
            <span>{t.files.request.creatingButton}</span>
          ) : (
            <>
              <FolderPlus className="h-4 w-4" />
              <span>{t.files.request.generateButton}</span>
            </>
          )}
        </button>
      </form>
    </div>
  );
}
