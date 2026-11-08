"use client";

import Link from "next/link";
import { Moon, Sun } from "lucide-react";
import { useApp } from "@/components/providers/AppProviders";
import { cn } from "@/lib/utils/cn";

export function Footer() {
  const { locale, setLocale, t, theme, toggleTheme } = useApp();

  return (
    <footer className="w-full max-w-2xl mx-auto px-6 py-8">
      <div className="flex flex-wrap items-center justify-center gap-x-5 gap-y-3 text-xs text-foreground-muted">
        <nav
          aria-label={t.meta.footerNavAriaLabel}
          className="flex items-center gap-5"
        >
          <Link
            href="/about"
            className="font-normal text-foreground-muted transition-colors duration-150 hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border-focus rounded-sm"
          >
            {t.meta.about}
          </Link>
          <a
            href="https://github.com"
            target="_blank"
            rel="noopener noreferrer"
            className="font-normal text-foreground-muted transition-colors duration-150 hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border-focus rounded-sm"
          >
            {t.meta.github}
          </a>
        </nav>

        <span
          className="h-3 w-px bg-border select-none"
          aria-hidden="true"
        />

        <div className="flex items-center gap-3">
          {/* Discreet EN / IT Language Selector */}
          <div
            role="group"
            aria-label={t.meta.languageSelectorAriaLabel}
            className="inline-flex items-center gap-1 font-mono text-[11px]"
          >
            <button
              type="button"
              onClick={() => setLocale("en")}
              aria-pressed={locale === "en"}
              className={cn(
                "px-1 py-0.5 rounded-sm transition-colors duration-150 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border-focus",
                locale === "en"
                  ? "text-foreground font-medium"
                  : "text-foreground-subtle hover:text-foreground-muted"
              )}
            >
              EN
            </button>
            <span className="text-foreground-subtle select-none" aria-hidden="true">
              /
            </span>
            <button
              type="button"
              onClick={() => setLocale("it")}
              aria-pressed={locale === "it"}
              className={cn(
                "px-1 py-0.5 rounded-sm transition-colors duration-150 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border-focus",
                locale === "it"
                  ? "text-foreground font-medium"
                  : "text-foreground-subtle hover:text-foreground-muted"
              )}
            >
              IT
            </button>
          </div>

          {/* Discreet Theme Switcher Icon Button */}
          <button
            type="button"
            onClick={toggleTheme}
            aria-label={
              theme === "dark"
                ? t.meta.switchThemeToLight
                : t.meta.switchThemeToDark
            }
            title={
              theme === "dark"
                ? t.meta.switchThemeToLight
                : t.meta.switchThemeToDark
            }
            className="inline-flex items-center justify-center p-1 rounded-md text-foreground-subtle hover:text-foreground transition-colors duration-150 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border-focus"
          >
            {theme === "dark" ? (
              <Sun className="h-3.5 w-3.5" aria-hidden="true" />
            ) : (
              <Moon className="h-3.5 w-3.5" aria-hidden="true" />
            )}
          </button>
        </div>
      </div>
    </footer>
  );
}
