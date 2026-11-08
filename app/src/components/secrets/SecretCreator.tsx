"use client";

import { useState, useRef, useMemo, type FormEvent } from "react";
import {
  ArrowRight,
  AlertCircle,
  Check,
  Copy,
  Eye,
  EyeOff,
  Loader2,
  Lock,
  X,
} from "lucide-react";
import type { ExpirationPreset } from "@/types/link";
import type {
  CreatedSecretMetadata,
  GeneratedSecretShare,
} from "@/types/secret";
import type { CreateSecretErrorCode } from "@/lib/secrets/service";
import {
  encryptSecretMessage,
  MAX_SECRET_PLAINTEXT_CHARS,
  MIN_SECRET_PASSWORD_LENGTH,
  evaluatePasswordStrength,
} from "@/lib/secrets/crypto";
import { useApp } from "@/components/providers/AppProviders";
import { cn } from "@/lib/utils/cn";

export const MAX_SECRET_LENGTH = MAX_SECRET_PLAINTEXT_CHARS;
export { MIN_SECRET_PASSWORD_LENGTH, evaluatePasswordStrength };

const EXPIRATION_OPTIONS: ExpirationPreset[] = [
  "never",
  "15m",
  "1h",
  "24h",
  "7d",
];

export type SecretFormErrorCode =
  | "empty"
  | "too_long"
  | "password_too_short"
  | "rate_limited"
  | "encryption_error"
  | "server_error";

export function SecretCreator() {
  const { t } = useApp();
  const [message, setMessage] = useState("");
  const [expiration, setExpiration] = useState<ExpirationPreset>("never");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorCode, setErrorCode] = useState<SecretFormErrorCode | null>(null);
  const [generatedSecret, setGeneratedSecret] =
    useState<GeneratedSecretShare | null>(null);
  const [copied, setCopied] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const passwordInputRef = useRef<HTMLInputElement>(null);

  const validateMessage = (value: string): SecretFormErrorCode | null => {
    const trimmed = value.trim();
    if (!trimmed) {
      return "empty";
    }
    if (value.length > MAX_SECRET_LENGTH) {
      return "too_long";
    }
    return null;
  };

  const handleMessageChange = (value: string) => {
    setMessage(value);
    if (errorCode) {
      setErrorCode(null);
    }
  };

  const handleMessageBlur = () => {
    if (message.length > 0) {
      const err = validateMessage(message);
      if (err) {
        setErrorCode(err);
      }
    }
  };

  const handleClearMessage = () => {
    setMessage("");
    setErrorCode(null);
    setTimeout(() => textareaRef.current?.focus(), 30);
  };

  const handleResetForm = () => {
    setGeneratedSecret(null);
    setMessage("");
    setPassword("");
    setShowPassword(false);
    setErrorCode(null);
    setCopied(false);
    setTimeout(() => textareaRef.current?.focus(), 30);
  };

  const handleCopy = async () => {
    if (!generatedSecret) return;
    try {
      await navigator.clipboard.writeText(generatedSecret.shareUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handlePasswordChange = (value: string) => {
    setPassword(value);
    if (errorCode === "password_too_short") {
      setErrorCode(null);
    }
  };

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (isLoading) return;

    const validationError = validateMessage(message);
    if (validationError) {
      setErrorCode(validationError);
      textareaRef.current?.focus();
      return;
    }

    if (password.length > 0 && password.length < MIN_SECRET_PASSWORD_LENGTH) {
      setErrorCode("password_too_short");
      passwordInputRef.current?.focus();
      return;
    }

    setErrorCode(null);
    setIsLoading(true);

    try {
      // 1. Client-side E2E encryption (AES-256-GCM + optional PBKDF2/HKDF)
      let encryptedBundle;
      try {
        encryptedBundle = await encryptSecretMessage(message, {
          password: password.length > 0 ? password : undefined,
        });
      } catch {
        setErrorCode("encryption_error");
        setIsLoading(false);
        return;
      }

      // 2. Transmit ONLY ciphertext and KDF/AEAD metadata to backend
      const response = await fetch("/api/secrets", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ciphertext: encryptedBundle.ciphertext,
          iv: encryptedBundle.iv,
          passwordProtected: encryptedBundle.passwordProtected,
          kdfSalt: encryptedBundle.kdfSalt,
          kdfIterations: encryptedBundle.kdfIterations,
          expiration,
        }),
      });

      const data = (await response.json()) as {
        secret?: CreatedSecretMetadata;
        errorCode?: CreateSecretErrorCode;
      };

      if (!response.ok || !data.secret) {
        if (response.status === 429 || data.errorCode === "rate_limited") {
          setErrorCode("rate_limited");
        } else {
          setErrorCode("server_error");
        }
        setIsLoading(false);
        return;
      }

      // 3. Construct shareable link locally with decryption key in #fragment
      const origin =
        typeof window !== "undefined"
          ? window.location.origin
          : "https://once.sh";
      const shareUrl = `${origin}/secrets/${data.secret.token}#${encryptedBundle.fragmentKey}`;

      setGeneratedSecret({
        ...data.secret,
        shareUrl,
      });
      setMessage("");
      setPassword("");
      setShowPassword(false);
      setCopied(false);
    } catch {
      setErrorCode("server_error");
    } finally {
      setIsLoading(false);
    }
  };

  const activeErrorMessage =
    errorCode === "empty"
      ? t.secrets.emptyMessageError
      : errorCode === "too_long"
        ? t.secrets.messageTooLongError
        : errorCode === "password_too_short"
          ? t.secrets.passwordTooShortError
          : errorCode === "rate_limited"
            ? t.secrets.rateLimitedError
            : errorCode === "encryption_error"
              ? t.secrets.encryptionError
              : errorCode === "server_error"
                ? t.secrets.serverError
                : null;

  const hasPassword = password.length > 0;
  const passwordStrength = useMemo(
    () => (hasPassword ? evaluatePasswordStrength(password) : null),
    [password, hasPassword]
  );

  return (
    <div className="w-full max-w-xl mx-auto">
      <form
        onSubmit={handleSubmit}
        method="POST"
        noValidate
        className="space-y-3"
      >
        {/* Secret Message Input Card */}
        <div
          className={cn(
            "relative rounded-xl bg-surface p-2 border transition-colors duration-200",
            activeErrorMessage
              ? "border-red-500/60 focus-within:border-red-500"
              : "border-border hover:border-border-hover focus-within:border-border-focus"
          )}
        >
          <label htmlFor="secret-message" className="sr-only">
            {t.secrets.messageLabel}
          </label>

          <div className="relative rounded-lg dark:bg-input">
            <textarea
              ref={textareaRef}
              id="secret-message"
              name="message"
              value={message}
              disabled={isLoading}
              maxLength={MAX_SECRET_LENGTH}
              onChange={(e) => handleMessageChange(e.target.value)}
              onBlur={handleMessageBlur}
              placeholder={t.secrets.messagePlaceholder}
              aria-invalid={Boolean(activeErrorMessage)}
              aria-describedby={
                activeErrorMessage
                  ? "secret-char-counter secret-error-message"
                  : "secret-char-counter"
              }
              className="block [field-sizing:content] w-full h-auto min-h-[7.5rem] max-h-[18rem] resize-y rounded-lg bg-transparent dark:bg-input px-3.5 pt-3 pb-2 pr-9 text-sm sm:text-base text-foreground placeholder:text-foreground-subtle focus:outline-none leading-relaxed disabled:opacity-50"
            />
            {message.length > 0 && !isLoading && (
              <button
                type="button"
                onClick={handleClearMessage}
                aria-label={t.secrets.clearMessageAriaLabel}
                className="absolute top-2.5 right-2.5 p-1 rounded-md text-foreground-subtle hover:text-foreground transition-colors duration-150 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border-focus"
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            )}
          </div>

          {/* Character Counter Bar */}
          <div className="flex items-center justify-end px-2 pb-1 pt-2">
            <span
              id="secret-char-counter"
              className={cn(
                "text-[11px] font-mono transition-colors duration-150",
                message.length >= MAX_SECRET_LENGTH
                  ? "text-foreground font-medium"
                  : "text-foreground-subtle"
              )}
            >
              {message.length}/{MAX_SECRET_LENGTH}
            </span>
          </div>
        </div>

        {/* Inline Validation Error */}
        <div
          className={cn(
            "grid transition-all duration-200 ease-out-expo",
            activeErrorMessage
              ? "grid-rows-[1fr] opacity-100"
              : "grid-rows-[0fr] opacity-0"
          )}
        >
          <div className="overflow-hidden">
            {activeErrorMessage && (
              <p
                id="secret-error-message"
                role="alert"
                className="flex items-center gap-1.5 px-1 text-xs text-red-500"
              >
                <AlertCircle
                  className="h-3.5 w-3.5 shrink-0"
                  aria-hidden="true"
                />
                <span>{activeErrorMessage}</span>
              </p>
            )}
          </div>
        </div>

        {/* Options & Action Card */}
        <div className="rounded-xl bg-surface border border-border p-4 sm:p-5 space-y-4">
          {/* Configurable Expiration */}
          <div className="space-y-1.5">
            <span className="block text-xs font-medium text-foreground-muted">
              {t.secrets.expirationLabel}
            </span>
            <div
              role="radiogroup"
              aria-label={t.secrets.expirationLabel}
              className="grid grid-cols-5 gap-1.5"
            >
              {EXPIRATION_OPTIONS.map((preset) => {
                const isSelected = expiration === preset;
                return (
                  <button
                    key={preset}
                    type="button"
                    role="radio"
                    aria-checked={isSelected}
                    disabled={isLoading}
                    onClick={() => setExpiration(preset)}
                    className={cn(
                      "px-2 py-2 rounded-lg text-xs font-medium border transition-all duration-150 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border-focus truncate",
                      isSelected
                        ? "bg-foreground text-background border-foreground"
                        : "bg-input text-foreground-muted border-border hover:border-border-focus hover:text-foreground"
                    )}
                  >
                    {t.form.expirationPresets[preset]}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Password Protection Option */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label
                htmlFor="secret-password"
                className="block text-xs font-medium text-foreground-muted"
              >
                {t.secrets.passwordLabel}
              </label>
              <span
                className={cn(
                  "inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono border transition-colors duration-150",
                  hasPassword
                    ? "bg-input border-border-focus text-foreground"
                    : "bg-input border-border text-foreground-subtle"
                )}
              >
                {hasPassword
                  ? t.secrets.passwordActiveBadge
                  : t.secrets.passwordOptionalBadge}
              </span>
            </div>

            <div className="flex items-center rounded-lg bg-input border border-border focus-within:border-border-focus transition-colors duration-150">
              <Lock
                className="ml-3 h-3.5 w-3.5 text-foreground-subtle shrink-0"
                aria-hidden="true"
              />
              <input
                ref={passwordInputRef}
                id="secret-password"
                name="password"
                type={showPassword ? "text" : "password"}
                value={password}
                disabled={isLoading}
                onChange={(e) => handlePasswordChange(e.target.value)}
                placeholder={t.secrets.passwordPlaceholder}
                autoComplete="new-password"
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
                aria-describedby="secret-password-hint"
                className="w-full bg-transparent px-2.5 py-2 text-xs text-foreground placeholder:text-foreground-subtle focus:outline-none disabled:opacity-50"
              />
              <button
                type="button"
                disabled={isLoading}
                onClick={() => setShowPassword((prev) => !prev)}
                aria-pressed={showPassword}
                aria-label={
                  showPassword
                    ? t.secrets.hidePasswordAriaLabel
                    : t.secrets.showPasswordAriaLabel
                }
                title={
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

            {/* Password Robustness / Strength Indicator */}
            {hasPassword && passwordStrength && (
              <div className="space-y-1.5 px-0.5 pt-0.5">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="font-mono text-foreground-subtle">
                    {passwordStrength === "too_short"
                      ? `${t.secrets.passwordStrengthWeak} (${password.length}/${MIN_SECRET_PASSWORD_LENGTH})`
                      : passwordStrength === "medium"
                        ? t.secrets.passwordStrengthMedium
                        : t.secrets.passwordStrengthStrong}
                  </span>
                  <span
                    className={cn(
                      "text-[10px] uppercase font-mono tracking-wider",
                      passwordStrength === "too_short"
                        ? "text-amber-500"
                        : passwordStrength === "medium"
                          ? "text-foreground-muted"
                          : "text-emerald-500"
                    )}
                  >
                    {passwordStrength === "too_short"
                      ? "< 8"
                      : passwordStrength === "medium"
                        ? "OK"
                        : "MAX"}
                  </span>
                </div>
                <div className="grid grid-cols-3 gap-1 h-1 w-full bg-input rounded-full overflow-hidden">
                  <div
                    className={cn(
                      "h-full rounded-full transition-colors duration-200",
                      passwordStrength === "too_short"
                        ? "bg-amber-500/70"
                        : passwordStrength === "medium"
                          ? "bg-foreground/60"
                          : "bg-emerald-500"
                    )}
                  />
                  <div
                    className={cn(
                      "h-full rounded-full transition-colors duration-200",
                      passwordStrength === "too_short"
                        ? "bg-border"
                        : passwordStrength === "medium"
                          ? "bg-foreground/60"
                          : "bg-emerald-500"
                    )}
                  />
                  <div
                    className={cn(
                      "h-full rounded-full transition-colors duration-200",
                      passwordStrength === "strong"
                        ? "bg-emerald-500"
                        : "bg-border"
                    )}
                  />
                </div>
              </div>
            )}

            {hasPassword && (
              <p
                id="secret-password-hint"
                className="text-[11px] text-foreground-subtle leading-relaxed px-0.5"
              >
                {t.secrets.passwordSecurityHint}
              </p>
            )}
          </div>

          {/* Create Secret Submit Button */}
          <div className="pt-1">
            <button
              type="submit"
              disabled={isLoading}
              className={cn(
                "w-full inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-xs sm:text-sm font-medium bg-foreground text-background hover:opacity-90 active:scale-[0.99] transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-foreground/40",
                isLoading && "opacity-80 cursor-wait"
              )}
            >
              {isLoading ? (
                <>
                  <Loader2
                    className="h-4 w-4 animate-spin text-background"
                    aria-hidden="true"
                  />
                  <span>{t.secrets.creatingButton}</span>
                </>
              ) : (
                <>
                  <span>{t.secrets.createButton}</span>
                  <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                </>
              )}
            </button>
          </div>
        </div>
      </form>

      {/* Generated Secret Link Card */}
      {generatedSecret && (
        <div
          aria-live="polite"
          className="mt-5 rounded-xl bg-surface border border-border p-4 sm:p-5 space-y-3.5 animate-fade-in"
        >
          {/* Primary Focus: Shareable E2E Link + Actions */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2.5 min-w-0">
              <span
                className="h-1.5 w-1.5 rounded-full shrink-0 bg-emerald-500"
                aria-hidden="true"
              />
              <span className="font-mono text-sm sm:text-base font-medium tracking-tight select-all truncate text-foreground">
                {generatedSecret.shareUrl}
              </span>
            </div>

            <div className="flex items-center gap-1.5 shrink-0">
              <button
                type="button"
                onClick={handleCopy}
                className={cn(
                  "inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium border transition-all duration-150 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border-focus",
                  copied
                    ? "bg-foreground text-background border-foreground"
                    : "bg-input text-foreground border-border hover:bg-surface-hover hover:border-border-focus"
                )}
              >
                {copied ? (
                  <>
                    <Check className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>{t.result.copiedButton}</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>{t.result.copyButton}</span>
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={handleResetForm}
                aria-label={t.secrets.newSecretAriaLabel}
                title={t.secrets.newSecretAriaLabel}
                className="inline-flex items-center justify-center p-1.5 rounded-lg text-foreground-subtle hover:text-foreground hover:bg-input transition-colors duration-150 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border-focus"
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            </div>
          </div>

          {/* Direct One-Time Read Notice without container box */}
          <p className="text-xs text-foreground-muted leading-relaxed sm:whitespace-nowrap sm:truncate">
            {t.secrets.oneTimeWarning}
          </p>

          {/* Subtle Integrated Metadata Row */}
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-foreground-subtle font-mono">
            <span>{t.result.singleRemainingView}</span>
            <span aria-hidden="true">·</span>
            <span>{t.form.expirationPresets[generatedSecret.expiration]}</span>
            <span aria-hidden="true">·</span>
            <span className="text-foreground-muted">{t.secrets.e2eBadge}</span>
            {generatedSecret.passwordProtected && (
              <>
                <span aria-hidden="true">·</span>
                <span className="text-foreground-muted">
                  {t.secrets.passwordActiveBadge}
                </span>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
