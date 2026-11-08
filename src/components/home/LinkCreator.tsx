"use client";

import { useState, useRef, type FormEvent } from "react";
import {
  ArrowRight,
  Check,
  Copy,
  Loader2,
  AlertCircle,
  X,
} from "lucide-react";
import type { AdvancedLinkOptions, GeneratedLink } from "@/types/link";
import {
  validateDestinationUrl,
  validateCustomSlug,
  getDestinationHostname,
  type UrlValidationErrorCode,
  type SlugValidationErrorCode,
} from "@/lib/utils/url";
import type { CreateLinkErrorCode } from "@/lib/links/service";
import { useApp } from "@/components/providers/AppProviders";
import { cn } from "@/lib/utils/cn";
import { AdvancedOptions } from "./AdvancedOptions";

const DEFAULT_ADVANCED_OPTIONS: AdvancedLinkOptions = {
  customSlug: "",
  expiration: "never",
  maxViews: 1,
  expiredMessage: "",
};

const SLUG_ERROR_CODES = new Set<string>([
  "slug_short",
  "slug_long",
  "slug_invalid",
  "slug_reserved",
  "slug_taken",
]);

export function LinkCreator() {
  const { t } = useApp();
  const [urlInput, setUrlInput] = useState("");
  const [urlErrorCode, setUrlErrorCode] =
    useState<UrlValidationErrorCode | null>(null);
  const [slugErrorCode, setSlugErrorCode] =
    useState<SlugValidationErrorCode | null>(null);
  const [apiErrorCode, setApiErrorCode] =
    useState<CreateLinkErrorCode | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [options, setOptions] = useState<AdvancedLinkOptions>(
    DEFAULT_ADVANCED_OPTIONS
  );
  const [generatedLink, setGeneratedLink] = useState<GeneratedLink | null>(
    null
  );
  const [copied, setCopied] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleUrlChange = (value: string) => {
    setUrlInput(value);
    if (urlErrorCode) setUrlErrorCode(null);
    if (apiErrorCode) setApiErrorCode(null);
  };

  const handleOptionsChange = (updated: AdvancedLinkOptions) => {
    setOptions(updated);
    if (slugErrorCode) setSlugErrorCode(null);
    if (apiErrorCode) setApiErrorCode(null);
  };

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (isLoading) return;

    const urlValidation = validateDestinationUrl(urlInput);
    if (!urlValidation.isValid || !urlValidation.normalizedUrl) {
      setUrlErrorCode(urlValidation.errorCode ?? "invalid_url");
      setApiErrorCode(null);
      inputRef.current?.focus();
      return;
    }

    const slugValidation = validateCustomSlug(options.customSlug);
    if (!slugValidation.isValid) {
      setSlugErrorCode(slugValidation.errorCode ?? "slug_invalid");
      setApiErrorCode(null);
      return;
    }

    setUrlErrorCode(null);
    setSlugErrorCode(null);
    setApiErrorCode(null);
    setIsLoading(true);

    try {
      const response = await fetch("/api/links", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          destinationUrl: urlValidation.normalizedUrl,
          customSlug: options.customSlug.trim() || undefined,
          expiration: options.expiration,
          maxViews: options.maxViews,
          expiredMessage: options.expiredMessage.trim() || undefined,
        }),
      });

      const data = (await response.json()) as {
        link?: GeneratedLink;
        errorCode?: CreateLinkErrorCode;
      };

      if (!response.ok || !data.link) {
        const errCode = data.errorCode ?? "server_error";
        if (SLUG_ERROR_CODES.has(errCode)) {
          setSlugErrorCode(errCode as SlugValidationErrorCode);
        } else {
          setApiErrorCode(errCode);
        }
        setIsLoading(false);
        return;
      }

      setGeneratedLink(data.link);
      setCopied(false);
    } catch {
      setApiErrorCode("server_error");
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = async () => {
    if (!generatedLink) return;
    try {
      await navigator.clipboard.writeText(generatedLink.shortUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleResetForm = () => {
    setGeneratedLink(null);
    setUrlInput("");
    setUrlErrorCode(null);
    setSlugErrorCode(null);
    setApiErrorCode(null);
    setCopied(false);
    setTimeout(() => inputRef.current?.focus(), 30);
  };

  const activeErrorMessage = urlErrorCode
    ? t.form.urlErrors[urlErrorCode]
    : apiErrorCode
      ? t.form.apiErrors[apiErrorCode]
      : null;

  return (
    <div className="w-full max-w-xl mx-auto">
      <form onSubmit={handleSubmit} noValidate className="space-y-3">
        {/* Main Input Card */}
        <div
          className={cn(
            "relative flex flex-col sm:flex-row items-stretch sm:items-center gap-2 rounded-xl bg-surface p-2 border transition-colors duration-200",
            activeErrorMessage
              ? "border-red-500/60 focus-within:border-red-500"
              : "border-border hover:border-border-hover focus-within:border-border-focus"
          )}
        >
          <label htmlFor="destination-url" className="sr-only">
            {t.form.destinationLabel}
          </label>
          <div className="relative flex-1 flex items-center rounded-lg dark:bg-input">
            <input
              ref={inputRef}
              id="destination-url"
              type="url"
              inputMode="url"
              value={urlInput}
              disabled={isLoading}
              onChange={(e) => handleUrlChange(e.target.value)}
              placeholder={t.form.destinationPlaceholder}
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              aria-invalid={Boolean(activeErrorMessage)}
              aria-describedby={
                activeErrorMessage ? "url-error-message" : undefined
              }
              className="w-full rounded-lg bg-transparent dark:bg-input pl-3.5 pr-8 py-2.5 text-sm sm:text-base text-foreground placeholder:text-foreground-subtle focus:outline-none disabled:opacity-50"
            />
            {urlInput.length > 0 && !isLoading && (
              <button
                type="button"
                onClick={handleResetForm}
                aria-label={t.form.clearInputAriaLabel}
                className="absolute right-2 p-1 rounded-md text-foreground-subtle hover:text-foreground transition-colors duration-150 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border-focus"
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            )}
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className={cn(
              "inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-xs sm:text-sm font-medium transition-all duration-150 shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-foreground/40",
              "bg-foreground text-background hover:opacity-90 active:scale-[0.99]",
              isLoading && "opacity-80 cursor-wait"
            )}
          >
            {isLoading ? (
              <>
                <Loader2
                  className="h-4 w-4 animate-spin text-background"
                  aria-hidden="true"
                />
                <span>{t.form.generatingButton}</span>
              </>
            ) : (
              <>
                <span>{t.form.generateButton}</span>
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </>
            )}
          </button>
        </div>

        {/* Inline Validation / API Error */}
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
                id="url-error-message"
                role="alert"
                className="flex items-center gap-1.5 px-1 pt-1 text-xs text-red-500"
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

        {/* Link Configuration Options */}
        <AdvancedOptions
          options={options}
          onChange={handleOptionsChange}
          slugErrorCode={slugErrorCode}
          disabled={isLoading}
        />
      </form>

      {/* Generated Link Result Card */}
      {generatedLink && (
        <div
          aria-live="polite"
          className="mt-5 rounded-xl bg-surface border border-border p-4 sm:p-5 space-y-3.5 animate-fade-in"
        >
          {/* Primary Focus: Short Link + Actions */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2.5 min-w-0">
              <span
                className="h-1.5 w-1.5 rounded-full shrink-0 bg-emerald-500"
                aria-hidden="true"
              />
              <span className="font-mono text-base sm:text-lg font-medium tracking-tight select-all truncate text-foreground">
                {generatedLink.shortUrl}
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
                aria-label={t.result.newLinkAriaLabel}
                title={t.result.newLinkAriaLabel}
                className="inline-flex items-center justify-center p-1.5 rounded-lg text-foreground-subtle hover:text-foreground hover:bg-input transition-colors duration-150 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border-focus"
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            </div>
          </div>

          {/* Subtle Integrated Metadata Row */}
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-foreground-subtle font-mono">
            <span>
              {generatedLink.remainingViews === 1
                ? t.result.singleRemainingView
                : t.result.multipleRemainingViews(generatedLink.remainingViews)}
            </span>
            <span aria-hidden="true">·</span>
            <span>{t.form.expirationPresets[generatedLink.expiration]}</span>
            <span aria-hidden="true">·</span>
            <span
              className="truncate max-w-[220px] sm:max-w-[280px] text-foreground-muted"
              title={generatedLink.destinationUrl}
            >
              {getDestinationHostname(generatedLink.destinationUrl)}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
