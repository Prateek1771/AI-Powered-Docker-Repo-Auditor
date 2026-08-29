"use client";

import { useReducedMotion } from "motion/react";

/** Shared entrance for a page section. */
export const SECTION = {
  hidden: { opacity: 0, y: 12 },
  show: { opacity: 1, y: 0 },
};

export const STAGGER = {
  hidden: {},
  show: { transition: { staggerChildren: 0.05, delayChildren: 0.04 } },
};

/**
 * Every animated component reads this. With reduced motion the same states are
 * reachable, they just arrive without travel - vestibular safety is not a
 * polish item, so the content must never depend on the transform running.
 */
export function useMotionPrefs() {
  const reduced = useReducedMotion();

  return {
    reduced: Boolean(reduced),
    section: reduced
      ? { hidden: { opacity: 0 }, show: { opacity: 1 } }
      : SECTION,
    stagger: reduced ? { hidden: {}, show: {} } : STAGGER,
    spring: reduced
      ? { duration: 0 }
      : { type: "spring" as const, stiffness: 120, damping: 20 },
  };
}
