import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Merge class names, letting later Tailwind utilities win.
 *
 * Plain concatenation leaves both `p-2` and `p-4` in the list and the
 * winner is whichever CSS rule came first, which is not what the caller
 * meant.
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
