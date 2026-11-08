import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import { AppProviders } from "@/components/providers/AppProviders";
import "./globals.css";

export const metadata: Metadata = {
  title: "ONCE — Temporary links.",
  description:
    "Create and share links with limited access and automatic expiration.",
};

const themeInitScript = `
(function() {
  try {
    var savedTheme = localStorage.getItem('once-theme');
    var theme = (savedTheme === 'light' || savedTheme === 'dark') ? savedTheme : 'dark';
    var root = document.documentElement;
    root.classList.remove('dark', 'light');
    root.classList.add(theme);
    root.setAttribute('data-theme', theme);
    root.style.colorScheme = theme;

    var savedLocale = localStorage.getItem('once-locale');
    if (savedLocale === 'en' || savedLocale === 'it') {
      root.lang = savedLocale;
    } else {
      var navLang = (navigator.languages && navigator.languages[0]) || navigator.language || 'en';
      root.lang = navLang.toLowerCase().indexOf('it') === 0 ? 'it' : 'en';
    }
  } catch (e) {}
})();
`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`dark ${GeistSans.variable} ${GeistMono.variable}`}
      suppressHydrationWarning
    >
      <head>
        <meta name="color-scheme" content="dark light" />
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
      </head>
      <body className="min-h-dvh bg-background text-foreground font-sans flex flex-col justify-between selection:bg-foreground selection:text-background">
        <AppProviders>{children}</AppProviders>
      </body>
    </html>
  );
}
