"use client";

import type { AdvancedLinkOptions, ExpirationPreset } from "@/types/link";
import type { SlugValidationErrorCode } from "@/lib/utils/url";
import { useApp } from "@/components/providers/AppProviders";
import { cn } from "@/lib/utils/cn";

interface AdvancedOptionsProps {
  options: AdvancedLinkOptions;
  onChange: (updated: AdvancedLinkOptions) => void;
  slugErrorCode?: SlugValidationErrorCode | null;
  disabled?: boolean;
}

const EXPIRATION_OPTIONS: ExpirationPreset[] = [
  "never",
  "15m",
  "1h",
  "24h",
  "7d",
];

export function AdvancedOptions({
  options,
  onChange,
  slugErrorCode,
  disabled = false,
}: AdvancedOptionsProps) {
  const { t } = useApp();

  return (
    <div
      id="advanced-options-panel"
      role="region"
      aria-label={t.form.advancedOptions}
      className="rounded-xl bg-surface border border-border p-4 sm:p-5 space-y-4"
    >
      {/* Row 1: Custom Slug & Maximum Views */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {/* Custom Slug */}
        <div className="space-y-1.5">
          <label
            htmlFor="custom-slug"
            className="block text-xs font-medium text-foreground-muted"
          >
            {t.form.customSlugLabel}
          </label>
          <div
            className={cn(
              "flex items-center rounded-lg bg-input border transition-colors duration-150",
              slugErrorCode
                ? "border-red-500/60 focus-within:border-red-500"
                : "border-border focus-within:border-border-focus"
            )}
          >
            <span className="pl-3 pr-1 text-xs font-mono text-foreground-subtle select-none">
              once.sh/
            </span>
            <input
              id="custom-slug"
              type="text"
              value={options.customSlug}
              disabled={disabled}
              onChange={(e) =>
                onChange({
                  ...options,
                  customSlug: e.target.value.replace(/\s+/g, ""),
                })
              }
              placeholder={t.form.customSlugPlaceholder}
              maxLength={32}
              autoComplete="off"
              spellCheck={false}
              className="w-full rounded-r-lg bg-transparent py-2 pr-3 text-xs font-mono text-foreground placeholder:text-foreground-subtle focus:outline-none"
            />
          </div>
          {slugErrorCode && (
            <p className="text-[11px] text-red-500">
              {t.form.slugErrors[slugErrorCode]}
            </p>
          )}
        </div>

        {/* Maximum Views */}
        <div className="space-y-1.5">
          <label
            htmlFor="max-views"
            className="block text-xs font-medium text-foreground-muted"
          >
            {t.form.maxViewsLabel}
          </label>
          <div className="flex items-center rounded-lg bg-input border border-border focus-within:border-border-focus transition-colors duration-150">
            <button
              type="button"
              disabled={disabled || options.maxViews <= 1}
              onClick={() =>
                onChange({
                  ...options,
                  maxViews: Math.max(1, options.maxViews - 1),
                })
              }
              aria-label={t.form.decreaseViewsAria}
              className="px-3 py-2 text-xs font-mono text-foreground-muted hover:text-foreground disabled:opacity-30 disabled:hover:text-foreground-muted transition-colors focus:outline-none"
            >
              −
            </button>
            <input
              id="max-views"
              type="number"
              min={1}
              max={1000}
              disabled={disabled}
              value={options.maxViews}
              onChange={(e) => {
                const val = parseInt(e.target.value, 10);
                onChange({
                  ...options,
                  maxViews: Number.isNaN(val)
                    ? 1
                    : Math.min(1000, Math.max(1, val)),
                });
              }}
              className="w-full bg-transparent py-2 text-center text-xs font-mono text-foreground focus:outline-none [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none"
            />
            <button
              type="button"
              disabled={disabled || options.maxViews >= 1000}
              onClick={() =>
                onChange({
                  ...options,
                  maxViews: Math.min(1000, options.maxViews + 1),
                })
              }
              aria-label={t.form.increaseViewsAria}
              className="px-3 py-2 text-xs font-mono text-foreground-muted hover:text-foreground disabled:opacity-30 disabled:hover:text-foreground-muted transition-colors focus:outline-none"
            >
              +
            </button>
          </div>
        </div>
      </div>

      {/* Row 2: Custom Expiration */}
      <div className="space-y-1.5">
        <span className="block text-xs font-medium text-foreground-muted">
          {t.form.customExpirationLabel}
        </span>
        <div
          role="radiogroup"
          aria-label={t.form.customExpirationLabel}
          className="grid grid-cols-5 gap-1.5"
        >
          {EXPIRATION_OPTIONS.map((preset) => {
            const isSelected = options.expiration === preset;
            return (
              <button
                key={preset}
                type="button"
                role="radio"
                aria-checked={isSelected}
                disabled={disabled}
                onClick={() =>
                  onChange({
                    ...options,
                    expiration: preset,
                  })
                }
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

      {/* Row 3: Custom Expired Message */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between">
          <label
            htmlFor="expired-message"
            className="block text-xs font-medium text-foreground-muted"
          >
            {t.form.expiredMessageLabel}
          </label>
          <span className="text-[11px] font-mono text-foreground-subtle">
            {options.expiredMessage.length}/140
          </span>
        </div>
        <input
          id="expired-message"
          type="text"
          disabled={disabled}
          maxLength={140}
          value={options.expiredMessage}
          onChange={(e) =>
            onChange({
              ...options,
              expiredMessage: e.target.value,
            })
          }
          placeholder={t.form.expiredMessagePlaceholder}
          className="w-full rounded-lg bg-input border border-border px-3 py-2 text-xs text-foreground placeholder:text-foreground-subtle transition-colors duration-150 focus:outline-none focus:border-border-focus"
        />
      </div>
    </div>
  );
}
