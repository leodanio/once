"use client";

import { useState, useEffect, useRef, type FormEvent } from "react";
import Link from "next/link";
import {
  AlertCircle,
  ArrowRight,
  Check,
  Copy,
  Eye,
  EyeOff,
  Loader2,
  Lock,
  ShieldAlert,
} from "lucide-react";
import type {
  ConsumeSecretResult,
  SecretMetadataResult,
} from "@/types/secret";
import {
  decryptSecretMessage,
  parseFragmentKeyFromHash,
} from "@/lib/secrets/crypto";
import { Header } from "@/components/layout/Header";
import { Footer } from "@/components/layout/Footer";
import { useApp } from "@/components/providers/AppProviders";
import { cn } from "@/lib/utils/cn";

interface SecretReaderProps {
  token: string;
  initialMetadata: SecretMetadataResult;
}

type ReaderState =
  | "checking_fragment"
  | "missing_key"
  | "ready"
  | "revealing"
  | "revealed"
  | "consumed_wrong_password"
  | "consumed"
  | "expired"
  | "network_error";

export function SecretReader({ token, initialMetadata }: SecretReaderProps) {
  const { t } = useApp();
  const fragmentKeyRef = useRef<string | null>(null);
  const consumedPayloadRef = useRef<ConsumeSecretResult | null>(null);

  const [readerState, setReaderState] = useState<ReaderState>(() => {
    if (
      initialMetadata.status === "consumed" ||
      initialMetadata.status === "not_found"
    ) {
      return "consumed";
    }
    if (initialMetadata.status === "expired") {
      return "expired";
    }
    return "checking_fragment";
  });

  const [passwordProtected, setPasswordProtected] = useState(
    initialMetadata.passwordProtected
  );
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [decryptedMessage, setDecryptedMessage] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const passwordInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (typeof window === "undefined") return;

    const parsedKey = parseFragmentKeyFromHash(window.location.hash);
    if (parsedKey) {
      fragmentKeyRef.current = parsedKey;
      // Immediately scrub the #fragment key from browser URL bar & history
      // while retaining it in component memory until decryption completes.
      try {
        window.history.replaceState(
          null,
          "",
          window.location.pathname + window.location.search
        );
      } catch {
        // Ignore history API restrictions
      }
    }

    setReaderState((prev) => {
      if (prev !== "checking_fragment") return prev;
      return parsedKey ? "ready" : "missing_key";
    });
  }, []);

  const handleRevealSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (readerState === "revealing") return;

    const fragmentKey = fragmentKeyRef.current;
    if (!fragmentKey) {
      setReaderState("missing_key");
      return;
    }

    if (passwordProtected && password.length === 0) {
      setErrorMessage(t.secrets.read.passwordRequiredError);
      passwordInputRef.current?.focus();
      return;
    }

    setErrorMessage(null);
    setReaderState("revealing");

    let payload = consumedPayloadRef.current;

    // 1. Atomically consume secret from server if not already fetched in this tab session
    if (!payload) {
      try {
        const response = await fetch(
          `/api/secrets/${encodeURIComponent(token)}/consume`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-Once-Consume-Intent": "1",
            },
          }
        );

        const data = (await response.json()) as {
          result?: ConsumeSecretResult;
        };

        if (!data.result) {
          setReaderState("network_error");
          return;
        }

        if (
          data.result.status === "consumed" ||
          data.result.status === "not_found"
        ) {
          setReaderState("consumed");
          return;
        }

        if (data.result.status === "expired") {
          setReaderState("expired");
          return;
        }

        payload = data.result;
        consumedPayloadRef.current = payload;
        setPasswordProtected(payload.passwordProtected);
      } catch {
        // Network failure during atomic consumption: cannot guarantee whether the request
        // reached the server, so we must NOT pretend the secret is recoverable.
        setReaderState("network_error");
        return;
      }
    }

    // 2. Decrypt ciphertext client-side using Web Crypto API
    try {
      if (!payload.ciphertext || !payload.iv) {
        setReaderState("consumed");
        return;
      }

      const plaintext = await decryptSecretMessage({
        ciphertext: payload.ciphertext,
        iv: payload.iv,
        fragmentKey,
        passwordProtected: payload.passwordProtected,
        kdfSalt: payload.kdfSalt,
        kdfIterations: payload.kdfIterations,
        password: payload.passwordProtected ? password : undefined,
      });

      // Scrub sensitive key material and ciphertext from memory after successful decryption
      fragmentKeyRef.current = null;
      consumedPayloadRef.current = null;
      setPassword("");
      setDecryptedMessage(plaintext);
      setReaderState("revealed");
    } catch {
      setErrorMessage(t.secrets.read.wrongPasswordError);
      setReaderState("consumed_wrong_password");
      setTimeout(() => passwordInputRef.current?.focus(), 30);
    }
  };

  const handleCopyMessage = async () => {
    if (!decryptedMessage) return;
    try {
      await navigator.clipboard.writeText(decryptedMessage);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <>
      <Header />
      <main className="flex-1 flex flex-col items-center justify-center w-full max-w-xl mx-auto px-6 py-12">
        {/* State 1: Destroyed / Already Consumed / Not Found */}
        {readerState === "consumed" && (
          <div className="w-full rounded-xl bg-surface border border-border p-6 sm:p-8 text-center space-y-5 animate-fade-in">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-input border border-border">
              <span
                className="h-1.5 w-1.5 rounded-full bg-red-500"
                aria-hidden="true"
              />
              <span className="text-[11px] font-mono uppercase tracking-wider text-foreground-muted">
                {t.secrets.read.consumedBadge}
              </span>
            </div>

            <div className="space-y-2">
              <h1 className="text-xl sm:text-2xl font-medium tracking-tight text-foreground">
                {t.secrets.read.consumedTitle}
              </h1>
              <p className="text-sm text-foreground-muted max-w-md mx-auto leading-relaxed">
                {t.secrets.read.consumedDescription}
              </p>
            </div>

            <div className="pt-2">
              <Link
                href="/"
                className="inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-xs sm:text-sm font-medium bg-foreground text-background hover:opacity-90 transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-foreground/40"
              >
                <span>{t.secrets.read.createNewSecretButton}</span>
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </Link>
            </div>
          </div>
        )}

        {/* State 2: Expired */}
        {readerState === "expired" && (
          <div className="w-full rounded-xl bg-surface border border-border p-6 sm:p-8 text-center space-y-5 animate-fade-in">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-input border border-border">
              <span
                className="h-1.5 w-1.5 rounded-full bg-red-500"
                aria-hidden="true"
              />
              <span className="text-[11px] font-mono uppercase tracking-wider text-foreground-muted">
                {t.secrets.read.expiredBadge}
              </span>
            </div>

            <div className="space-y-2">
              <h1 className="text-xl sm:text-2xl font-medium tracking-tight text-foreground">
                {t.secrets.read.expiredTitle}
              </h1>
              <p className="text-sm text-foreground-muted max-w-md mx-auto leading-relaxed">
                {t.secrets.read.expiredDescription}
              </p>
            </div>

            <div className="pt-2">
              <Link
                href="/"
                className="inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-xs sm:text-sm font-medium bg-foreground text-background hover:opacity-90 transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-foreground/40"
              >
                <span>{t.secrets.read.createNewSecretButton}</span>
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </Link>
            </div>
          </div>
        )}

        {/* State 3: Missing or Invalid #fragment Key (Secret NOT consumed) */}
        {readerState === "missing_key" && (
          <div className="w-full rounded-xl bg-surface border border-border p-6 sm:p-8 text-center space-y-5 animate-fade-in">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-input border border-border">
              <span
                className="h-1.5 w-1.5 rounded-full bg-amber-500"
                aria-hidden="true"
              />
              <span className="text-[11px] font-mono uppercase tracking-wider text-foreground-muted">
                {t.secrets.read.missingKeyBadge}
              </span>
            </div>

            <div className="space-y-2">
              <h1 className="text-xl sm:text-2xl font-medium tracking-tight text-foreground">
                {t.secrets.read.missingKeyTitle}
              </h1>
              <p className="text-sm text-foreground-muted max-w-md mx-auto leading-relaxed">
                {t.secrets.read.missingKeyDescription}
              </p>
            </div>

            <div className="pt-2">
              <Link
                href="/"
                className="inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-xs sm:text-sm font-medium bg-foreground text-background hover:opacity-90 transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-foreground/40"
              >
                <span>{t.secrets.read.createNewSecretButton}</span>
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </Link>
            </div>
          </div>
        )}

        {/* State 4: Network Error During Consumption (Irreversible Warning) */}
        {readerState === "network_error" && (
          <div className="w-full rounded-xl bg-surface border border-border p-6 sm:p-8 text-center space-y-5 animate-fade-in">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-input border border-border">
              <span
                className="h-1.5 w-1.5 rounded-full bg-red-500"
                aria-hidden="true"
              />
              <span className="text-[11px] font-mono uppercase tracking-wider text-foreground-muted">
                {t.secrets.read.consumedBadge}
              </span>
            </div>

            <div className="space-y-2">
              <h1 className="text-xl sm:text-2xl font-medium tracking-tight text-foreground">
                {t.secrets.read.networkConsumeErrorTitle}
              </h1>
              <p className="text-sm text-foreground-muted max-w-md mx-auto leading-relaxed">
                {t.secrets.read.networkConsumeErrorDescription}
              </p>
            </div>

            <div className="pt-2">
              <Link
                href="/"
                className="inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-xs sm:text-sm font-medium bg-foreground text-background hover:opacity-90 transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-foreground/40"
              >
                <span>{t.secrets.read.createNewSecretButton}</span>
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </Link>
            </div>
          </div>
        )}

        {/* State 5: Preparation Screen / Password Entry / Retry after Wrong Password */}
        {(readerState === "ready" ||
          readerState === "revealing" ||
          readerState === "consumed_wrong_password") && (
          <div className="w-full rounded-xl bg-surface border border-border p-6 sm:p-8 space-y-6 animate-fade-in">
            <div className="text-center space-y-3">
              <h1 className="text-xl sm:text-2xl font-medium tracking-tight text-foreground">
                {t.secrets.read.prepTitle}
              </h1>
              <p className="text-sm text-foreground-muted max-w-md mx-auto leading-relaxed">
                {passwordProtected
                  ? t.secrets.read.passwordRequiredDescription
                  : t.secrets.read.prepDescription}
              </p>
            </div>

            <form
              onSubmit={handleRevealSubmit}
              method="POST"
              noValidate
              className="space-y-4"
            >
              {passwordProtected && (
                <div className="space-y-1.5">
                  <label
                    htmlFor="decrypt-password"
                    className="block text-xs font-medium text-foreground-muted"
                  >
                    {t.secrets.read.passwordInputLabel}
                  </label>
                  <div
                    className={cn(
                      "flex items-center rounded-lg bg-input border transition-colors duration-150",
                      errorMessage
                        ? "border-red-500/60 focus-within:border-red-500"
                        : "border-border focus-within:border-border-focus"
                    )}
                  >
                    <Lock
                      className="ml-3 h-3.5 w-3.5 text-foreground-subtle shrink-0"
                      aria-hidden="true"
                    />
                    <input
                      ref={passwordInputRef}
                      id="decrypt-password"
                      name="password"
                      type={showPassword ? "text" : "password"}
                      value={password}
                      disabled={readerState === "revealing"}
                      onChange={(e) => {
                        setPassword(e.target.value);
                        if (errorMessage) setErrorMessage(null);
                      }}
                      placeholder={t.secrets.read.passwordInputPlaceholder}
                      autoComplete="current-password"
                      autoCapitalize="off"
                      autoCorrect="off"
                      spellCheck={false}
                      aria-invalid={Boolean(errorMessage)}
                      className="w-full bg-transparent px-2.5 py-2.5 text-xs sm:text-sm text-foreground placeholder:text-foreground-subtle focus:outline-none disabled:opacity-50"
                    />
                    <button
                      type="button"
                      disabled={readerState === "revealing"}
                      onClick={() => setShowPassword((prev) => !prev)}
                      aria-pressed={showPassword}
                      aria-label={
                        showPassword
                          ? t.secrets.hidePasswordAriaLabel
                          : t.secrets.showPasswordAriaLabel
                      }
                      className="mr-1.5 p-1.5 rounded-md text-foreground-subtle hover:text-foreground transition-colors duration-150 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border-focus"
                    >
                      {showPassword ? (
                        <EyeOff className="h-3.5 w-3.5" aria-hidden="true" />
                      ) : (
                        <Eye className="h-3.5 w-3.5" aria-hidden="true" />
                      )}
                    </button>
                  </div>
                </div>
              )}

              {errorMessage && (
                <p
                  role="alert"
                  className="flex items-center gap-1.5 text-xs text-red-500"
                >
                  <AlertCircle
                    className="h-3.5 w-3.5 shrink-0"
                    aria-hidden="true"
                  />
                  <span>{errorMessage}</span>
                </p>
              )}

              {readerState === "consumed_wrong_password" && (
                <div className="flex items-start gap-2 rounded-lg bg-input border border-border px-3 py-2.5 text-xs text-foreground-muted">
                  <ShieldAlert
                    className="h-3.5 w-3.5 text-amber-500 shrink-0 mt-0.5"
                    aria-hidden="true"
                  />
                  <span>{t.secrets.read.wrongPasswordConsumedNotice}</span>
                </div>
              )}

              <button
                type="submit"
                disabled={readerState === "revealing"}
                className={cn(
                  "w-full inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-xs sm:text-sm font-medium bg-foreground text-background hover:opacity-90 active:scale-[0.99] transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-foreground/40",
                  readerState === "revealing" && "opacity-80 cursor-wait"
                )}
              >
                {readerState === "revealing" ? (
                  <>
                    <Loader2
                      className="h-4 w-4 animate-spin text-background"
                      aria-hidden="true"
                    />
                    <span>{t.secrets.read.revealingButton}</span>
                  </>
                ) : (
                  <>
                    <span>{t.secrets.read.revealButton}</span>
                    <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                  </>
                )}
              </button>
            </form>
          </div>
        )}

        {/* State 6: Decrypted Secret Message View */}
        {readerState === "revealed" && decryptedMessage !== null && (
          <div className="w-full rounded-xl bg-surface border border-border p-5 sm:p-6 space-y-4 animate-fade-in">
            <div className="rounded-lg bg-input border border-border p-4 max-h-[22rem] overflow-y-auto">
              <pre className="font-mono text-sm text-foreground whitespace-pre-wrap break-words leading-relaxed select-all">
                {decryptedMessage}
              </pre>
            </div>

            {/* Direct destruction notice without container box */}
            <p className="text-xs text-foreground-muted leading-relaxed sm:whitespace-nowrap sm:truncate">
              {t.secrets.read.revealedWarning}
            </p>

            <div className="pt-2 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
              <button
                type="button"
                onClick={handleCopyMessage}
                className={cn(
                  "flex-1 inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-xs sm:text-sm font-medium border transition-all duration-150 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border-focus",
                  copied
                    ? "bg-foreground text-background border-foreground"
                    : "bg-input text-foreground border-border hover:bg-surface-hover hover:border-border-focus"
                )}
              >
                {copied ? (
                  <>
                    <Check className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>{t.secrets.read.copiedMessageButton}</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>{t.secrets.read.copyMessageButton}</span>
                  </>
                )}
              </button>

              <Link
                href="/"
                className="flex-1 inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-xs sm:text-sm font-medium bg-foreground text-background hover:opacity-90 active:scale-[0.99] transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-foreground/40 text-center"
              >
                <span>{t.secrets.read.createNewSecretButton}</span>
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </Link>
            </div>
          </div>
        )}
      </main>
      <Footer />
    </>
  );
}
