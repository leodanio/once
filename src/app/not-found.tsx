"use client";

import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { Header } from "@/components/layout/Header";
import { Footer } from "@/components/layout/Footer";
import { useApp } from "@/components/providers/AppProviders";

export default function NotFoundPage() {
  const { t } = useApp();

  return (
    <>
      <Header />
      <main className="flex-1 flex flex-col items-center justify-center w-full max-w-xl mx-auto px-6 py-12">
        <div className="w-full rounded-xl bg-surface border border-border p-6 sm:p-8 text-center space-y-5 animate-fade-in">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-input border border-border">
            <span className="text-[11px] font-mono uppercase tracking-wider text-foreground-muted">
              {t.notFoundPage.badge}
            </span>
          </div>

          <div className="space-y-2">
            <h1 className="text-xl sm:text-2xl font-medium tracking-tight text-foreground">
              {t.notFoundPage.title}
            </h1>
            <p className="text-sm text-foreground-muted max-w-md mx-auto leading-relaxed">
              {t.notFoundPage.description}
            </p>
          </div>

          <div className="pt-2">
            <Link
              href="/"
              className="inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-xs sm:text-sm font-medium bg-foreground text-background hover:opacity-90 transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-foreground/40"
            >
              <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{t.notFoundPage.backHomeButton}</span>
            </Link>
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
