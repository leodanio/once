"use client";

import {
  createContext,
  useContext,
  useEffect,
  useLayoutEffect,
  useState,
  useCallback,
  useRef,
  type ReactNode,
} from "react";
import { flushSync } from "react-dom";
import { usePathname, useRouter } from "next/navigation";
import {
  translations,
  type Dictionary,
  type Locale,
} from "@/lib/i18n/translations";
import {
  CIRCULAR_REVEAL_DURATION_MS,
  PAGE_TRANSITION_DURATION_MS,
  CIRCULAR_REVEAL_EASING,
  computeMaxRevealRadius,
  resolveTransitionOrigin,
  type ToggleThemeOrigin,
} from "@/lib/utils/theme-transition";

export type Theme = "dark" | "light";
export type { ToggleThemeOrigin };

type DocumentWithViewTransition = Document & {
  startViewTransition?: (updateCallback: () => void | Promise<void>) => {
    ready: Promise<void>;
    finished: Promise<void>;
    updateCallbackDone: Promise<void>;
    skipTransition?: () => void;
  };
};

const LOCALE_STORAGE_KEY = "once-locale";
const THEME_STORAGE_KEY = "once-theme";
const NAVIGATION_TRANSITION_TIMEOUT_MS = 600;

const useIsomorphicLayoutEffect =
  typeof window !== "undefined" ? useLayoutEffect : useEffect;

interface AppContextValue {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: Dictionary;
  theme: Theme;
  toggleTheme: (origin?: ToggleThemeOrigin) => void;
  navigateWithTransition: (href: string) => void;
  mounted: boolean;
}

const AppContext = createContext<AppContextValue | null>(null);

function detectInitialLocale(): Locale {
  if (typeof window === "undefined") return "en";

  try {
    const saved = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    if (saved === "en" || saved === "it") {
      return saved;
    }
  } catch {
    // Ignore storage access errors
  }

  const browserLang =
    (navigator.languages && navigator.languages[0]) ||
    navigator.language ||
    "en";

  if (browserLang.toLowerCase().startsWith("it")) {
    return "it";
  }

  return "en";
}

function detectInitialTheme(): Theme {
  if (typeof window === "undefined") return "dark";

  try {
    const saved = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (saved === "light" || saved === "dark") {
      return saved;
    }
  } catch {
    // Ignore storage access errors
  }

  return "dark";
}

function applyThemeToDom(theme: Theme) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.classList.remove("dark", "light");
  root.classList.add(theme);
  root.setAttribute("data-theme", theme);
  root.style.colorScheme = theme;
}

export function AppProviders({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>("en");
  const [theme, setThemeState] = useState<Theme>("dark");
  const [mounted, setMounted] = useState(false);
  const themeRef = useRef<Theme>("dark");
  const transitionIdRef = useRef(0);
  const pathname = usePathname();
  const router = useRouter();
  const pathnameRef = useRef(pathname);
  const pendingRouteResolveRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    const initialLocale = detectInitialLocale();
    const initialTheme = detectInitialTheme();

    setLocaleState(initialLocale);
    setThemeState(initialTheme);
    themeRef.current = initialTheme;
    document.documentElement.lang = initialLocale;
    applyThemeToDom(initialTheme);
    setMounted(true);

    router.prefetch("/");
    router.prefetch("/links");

    const handleStorage = (event: StorageEvent) => {
      if (
        event.key === LOCALE_STORAGE_KEY &&
        (event.newValue === "en" || event.newValue === "it")
      ) {
        setLocaleState(event.newValue);
        document.documentElement.lang = event.newValue;
      }
      if (
        event.key === THEME_STORAGE_KEY &&
        (event.newValue === "dark" || event.newValue === "light")
      ) {
        setThemeState(event.newValue);
        themeRef.current = event.newValue;
        applyThemeToDom(event.newValue);
      }
    };

    const handlePopState = () => {
      if (pendingRouteResolveRef.current) {
        const resolve = pendingRouteResolveRef.current;
        pendingRouteResolveRef.current = null;
        resolve();
      }
    };

    window.addEventListener("storage", handleStorage);
    window.addEventListener("popstate", handlePopState);
    return () => {
      window.removeEventListener("storage", handleStorage);
      window.removeEventListener("popstate", handlePopState);
    };
  }, [router]);

  useIsomorphicLayoutEffect(() => {
    pathnameRef.current = pathname;
    if (pendingRouteResolveRef.current) {
      const resolve = pendingRouteResolveRef.current;
      pendingRouteResolveRef.current = null;
      if (typeof document !== "undefined") {
        void document.documentElement.offsetHeight;
      }
      resolve();
    }
  }, [pathname]);

  const setLocale = useCallback((nextLocale: Locale) => {
    setLocaleState(nextLocale);
    if (typeof document !== "undefined") {
      document.documentElement.lang = nextLocale;
    }
    try {
      window.localStorage.setItem(LOCALE_STORAGE_KEY, nextLocale);
    } catch {
      // Ignore storage access errors
    }
  }, []);

  const runCircularReveal = useCallback(
    (
      origin: ToggleThemeOrigin,
      durationMs: number,
      performDomUpdate: () => void | Promise<void>,
      onFinished?: () => void
    ) => {
      const prefersReducedMotion =
        typeof window !== "undefined" &&
        typeof window.matchMedia === "function" &&
        window.matchMedia("(prefers-reduced-motion: reduce)").matches;

      const doc =
        typeof document !== "undefined"
          ? (document as DocumentWithViewTransition)
          : null;

      if (
        prefersReducedMotion ||
        !doc ||
        typeof doc.startViewTransition !== "function" ||
        typeof doc.documentElement.animate !== "function"
      ) {
        void Promise.resolve(performDomUpdate()).finally(() => {
          onFinished?.();
        });
        return;
      }

      const { x, y } = resolveTransitionOrigin(origin);
      const maxRadius = computeMaxRevealRadius(
        x,
        y,
        window.innerWidth,
        window.innerHeight
      );

      const root = doc.documentElement;
      const currentTransitionId = ++transitionIdRef.current;

      root.setAttribute("data-theme-transition", "true");

      try {
        const transition = doc.startViewTransition(async () => {
          await performDomUpdate();
          // Force synchronous style and layout calculation before new view snapshot is captured
          void root.offsetHeight;
        });

        transition.ready
          .then(() => {
            root.animate(
              {
                clipPath: [
                  `circle(0px at ${x}px ${y}px)`,
                  `circle(${maxRadius}px at ${x}px ${y}px)`,
                ],
              },
              {
                duration: durationMs,
                easing: CIRCULAR_REVEAL_EASING,
                fill: "both",
                pseudoElement: "::view-transition-new(root)",
              }
            );
          })
          .catch(() => {
            // Ignore aborted transition if superseded by another interaction
          });

        transition.finished
          .catch(() => {
            // Ignore aborted transition
          })
          .finally(() => {
            if (transitionIdRef.current === currentTransitionId) {
              root.removeAttribute("data-theme-transition");
            }
            onFinished?.();
          });
      } catch {
        if (transitionIdRef.current === currentTransitionId) {
          root.removeAttribute("data-theme-transition");
        }
        void Promise.resolve(performDomUpdate()).finally(() => {
          onFinished?.();
        });
      }
    },
    []
  );

  const toggleTheme = useCallback(
    (origin?: ToggleThemeOrigin) => {
      const nextTheme: Theme = themeRef.current === "dark" ? "light" : "dark";

      const commitThemeChange = (next: Theme) => {
        themeRef.current = next;
        applyThemeToDom(next);
        try {
          window.localStorage.setItem(THEME_STORAGE_KEY, next);
        } catch {
          // Ignore storage access errors
        }
      };

      const activeElementBefore =
        typeof document !== "undefined" &&
        typeof HTMLElement !== "undefined" &&
        document.activeElement instanceof HTMLElement
          ? document.activeElement
          : null;

      runCircularReveal(
        origin,
        CIRCULAR_REVEAL_DURATION_MS,
        () => {
          flushSync(() => {
            setThemeState(nextTheme);
          });
          commitThemeChange(nextTheme);
        },
        () => {
          if (
            typeof document !== "undefined" &&
            activeElementBefore &&
            document.contains(activeElementBefore) &&
            document.activeElement !== activeElementBefore
          ) {
            activeElementBefore.focus({ preventScroll: true });
          }
        }
      );
    },
    [runCircularReveal]
  );

  const navigateWithTransition = useCallback(
    (targetHref: string) => {
      if (pathnameRef.current === targetHref) {
        return;
      }

      if (pendingRouteResolveRef.current) {
        const prevResolve = pendingRouteResolveRef.current;
        pendingRouteResolveRef.current = null;
        prevResolve();
      }

      // Pass undefined origin so resolveTransitionOrigin() centres the circle at (innerWidth/2, innerHeight/2)
      runCircularReveal(
        undefined,
        PAGE_TRANSITION_DURATION_MS,
        () =>
          new Promise<void>((resolve) => {
            let settled = false;
            const finish = () => {
              if (settled) return;
              settled = true;
              window.clearTimeout(timeoutId);
              if (pendingRouteResolveRef.current === finish) {
                pendingRouteResolveRef.current = null;
              }
              resolve();
            };

            const timeoutId = window.setTimeout(
              finish,
              NAVIGATION_TRANSITION_TIMEOUT_MS
            );
            pendingRouteResolveRef.current = finish;
            router.push(targetHref);
          }),
        () => {
          if (typeof document === "undefined") return;
          const mainEl = document.querySelector("main");
          if (mainEl instanceof HTMLElement) {
            mainEl.focus({ preventScroll: true });
          }
        }
      );
    },
    [router, runCircularReveal]
  );

  const value: AppContextValue = {
    locale,
    setLocale,
    t: translations[locale],
    theme,
    toggleTheme,
    navigateWithTransition,
    mounted,
  };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp() {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error("useApp must be used within AppProviders");
  }
  return context;
}
