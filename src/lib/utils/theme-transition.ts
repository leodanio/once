import type { MouseEvent as ReactMouseEvent } from "react";

export const CIRCULAR_REVEAL_DURATION_MS = 620;
export const PAGE_TRANSITION_DURATION_MS = 850;
export const CIRCULAR_REVEAL_EASING = "cubic-bezier(0.22, 1, 0.36, 1)";

export interface ThemeTransitionOrigin {
  x: number;
  y: number;
}

export type ToggleThemeOrigin =
  | ReactMouseEvent<HTMLElement>
  | ThemeTransitionOrigin
  | undefined;

/**
 * Returns true when a click event is a standard unmodified primary-button click
 * that should be handled by client-side view-transition navigation.
 */
export function isUnmodifiedPrimaryClick(
  event: Pick<
    ReactMouseEvent<HTMLElement>,
    "button" | "metaKey" | "ctrlKey" | "shiftKey" | "altKey" | "defaultPrevented"
  >
): boolean {
  return (
    !event.defaultPrevented &&
    event.button === 0 &&
    !event.metaKey &&
    !event.ctrlKey &&
    !event.shiftKey &&
    !event.altKey
  );
}

/**
 * Calculates the exact Euclidean distance from (x, y) to the farthest corner
 * of the viewport so a circular clip-path expands to cover the entire screen.
 */
export function computeMaxRevealRadius(
  x: number,
  y: number,
  viewportWidth: number,
  viewportHeight: number
): number {
  const maxX = Math.max(x, viewportWidth - x);
  const maxY = Math.max(y, viewportHeight - y);
  return Math.hypot(maxX, maxY);
}

/**
 * Resolves the exact (x, y) viewport coordinates of a pointer click/tap,
 * falling back to the target element center on keyboard activation or viewport center.
 */
export function resolveTransitionOrigin(
  origin?: ToggleThemeOrigin
): ThemeTransitionOrigin {
  if (origin && typeof origin === "object") {
    if ("clientX" in origin && "clientY" in origin) {
      if (origin.clientX !== 0 || origin.clientY !== 0) {
        return { x: origin.clientX, y: origin.clientY };
      }
      if (
        typeof HTMLElement !== "undefined" &&
        origin.currentTarget instanceof HTMLElement
      ) {
        const rect = origin.currentTarget.getBoundingClientRect();
        return {
          x: rect.left + rect.width / 2,
          y: rect.top + rect.height / 2,
        };
      }
    } else if ("x" in origin && "y" in origin) {
      return { x: origin.x, y: origin.y };
    }
  }

  if (typeof window === "undefined") {
    return { x: 0, y: 0 };
  }

  return {
    x: window.innerWidth / 2,
    y: window.innerHeight / 2,
  };
}
