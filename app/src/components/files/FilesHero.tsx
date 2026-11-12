"use client";

import { useApp } from "@/components/providers/AppProviders";

export function FilesHero() {
  const { t } = useApp();

  return (
    <section className="text-center space-y-3 mb-8">
      <h1 className="text-3xl sm:text-4xl font-medium tracking-tight text-foreground">
        {t.files.title}
      </h1>
      <p className="text-sm sm:text-base text-foreground-muted font-normal max-w-md mx-auto">
        {t.files.subtitle}
      </p>
    </section>
  );
}
