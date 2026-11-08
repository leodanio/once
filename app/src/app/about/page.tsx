"use client";

import { Header } from "@/components/layout/Header";
import { Footer } from "@/components/layout/Footer";
import { useApp } from "@/components/providers/AppProviders";

export default function AboutPage() {
  const { t } = useApp();

  return (
    <>
      <Header />
      <main
        tabIndex={-1}
        className="flex-1 flex flex-col items-center justify-center w-full max-w-xl mx-auto px-6 py-14 sm:py-20 focus:outline-none"
      >
        <article className="w-full text-center space-y-14 sm:space-y-16">
          <section aria-labelledby="about-once-heading" className="space-y-5">
            <h1
              id="about-once-heading"
              className="text-2xl sm:text-3xl font-semibold tracking-[0.18em] uppercase text-foreground"
            >
              {t.about.title}
            </h1>
            <div className="space-y-4 text-sm sm:text-[15px] text-foreground-muted leading-relaxed">
              <p>{t.about.introParagraph1}</p>
              <p>{t.about.introParagraph2}</p>
            </div>
          </section>

          <section aria-labelledby="about-links-heading" className="space-y-5">
            <h2
              id="about-links-heading"
              className="text-sm sm:text-base font-semibold tracking-[0.18em] uppercase text-foreground"
            >
              {t.about.linksTitle}
            </h2>
            <div className="space-y-4 text-sm sm:text-[15px] text-foreground-muted leading-relaxed">
              <p>{t.about.linksParagraph1}</p>
              <p>{t.about.linksParagraph2}</p>
              <p>{t.about.linksParagraph3}</p>
            </div>
          </section>

          <section aria-labelledby="about-secrets-heading" className="space-y-5">
            <h2
              id="about-secrets-heading"
              className="text-sm sm:text-base font-semibold tracking-[0.18em] uppercase text-foreground"
            >
              {t.about.secretsTitle}
            </h2>
            <div className="space-y-4 text-sm sm:text-[15px] text-foreground-muted leading-relaxed">
              <p>{t.about.secretsParagraph1}</p>
              <p>{t.about.secretsParagraph2}</p>
              <p>{t.about.secretsParagraph3}</p>
              <p>{t.about.secretsParagraph4}</p>
            </div>
          </section>
        </article>
      </main>
      <Footer />
    </>
  );
}
