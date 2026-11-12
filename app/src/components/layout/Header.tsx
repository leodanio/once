"use client";

import type { MouseEvent } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useApp } from "@/components/providers/AppProviders";
import { isUnmodifiedPrimaryClick } from "@/lib/utils/theme-transition";
import { cn } from "@/lib/utils/cn";

const HEADER_ITEM_CLASS =
  "inline-flex items-center text-sm font-semibold tracking-[0.18em] uppercase text-foreground transition-opacity duration-150 hover:opacity-80 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border-focus rounded-sm";

export function Header() {
  const { t, navigateWithTransition } = useApp();
  const pathname = usePathname();
  const isSecretsActive = pathname === "/";
  const isLinksActive = pathname === "/links";
  const isFilesActive = pathname === "/files" || pathname.startsWith("/files/");

  const handleNavClick =
    (href: string) => (event: MouseEvent<HTMLAnchorElement>) => {
      if (!isUnmodifiedPrimaryClick(event)) {
        return;
      }
      event.preventDefault();
      navigateWithTransition(href);
    };

  return (
    <header className="w-full max-w-2xl mx-auto px-6 pt-8 pb-4">
      <nav
        aria-label={t.meta.headerNavAriaLabel}
        className="flex items-center justify-center gap-5"
      >
        <Link
          href="/"
          onClick={handleNavClick("/")}
          aria-current={isSecretsActive ? "page" : undefined}
          className={cn(HEADER_ITEM_CLASS)}
        >
          {t.meta.secrets}
        </Link>

        <span
          className="h-3.5 w-px bg-border select-none"
          aria-hidden="true"
        />

        <Link
          href="/links"
          onClick={handleNavClick("/links")}
          aria-current={isLinksActive ? "page" : undefined}
          className={cn(HEADER_ITEM_CLASS)}
        >
          {t.meta.links}
        </Link>

        <span
          className="h-3.5 w-px bg-border select-none"
          aria-hidden="true"
        />

        <Link
          href="/files"
          onClick={handleNavClick("/files")}
          aria-current={isFilesActive ? "page" : undefined}
          className={cn(HEADER_ITEM_CLASS)}
        >
          {t.meta.files}
        </Link>
      </nav>
    </header>
  );
}
