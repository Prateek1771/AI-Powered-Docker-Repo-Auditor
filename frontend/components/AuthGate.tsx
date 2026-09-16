"use client";

import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { cognitoConfigured, cognitoIdToken } from "@/lib/auth";

/**
 * Send anyone without a session to /login, once, for every page.
 *
 * In the layout rather than in each page because the alternative is the same
 * four lines in `app/page.tsx`, the scan page, and every hook that fetches -
 * and the one that gets forgotten is the one that renders an error instead of
 * a login form.
 *
 * A no-op unless Cognito is configured, so local DEV_AUTH runs render
 * immediately and are completely unaffected. See docs/audits/audit-02-frontend-worker-observability.md F1.
 */
export function AuthGate({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();

  // Three states, not two: `checking` exists so a signed-in user does not see
  // the page flash away and come back while getSession() refreshes.
  const [state, setState] = useState<"checking" | "in" | "out">(
    cognitoConfigured ? "checking" : "in",
  );

  useEffect(() => {
    if (!cognitoConfigured || pathname === "/login") return;

    let cancelled = false;

    cognitoIdToken().then((token) => {
      if (cancelled) return;

      if (token) {
        setState("in");

        return;
      }

      setState("out");

      // Carry where they were going, so a shared link to a scan survives the
      // detour. The login page only honours same-origin paths.
      router.replace(`/login?next=${encodeURIComponent(pathname)}`);
    });

    return () => {
      cancelled = true;
    };
  }, [pathname, router]);

  if (pathname === "/login") return <>{children}</>;

  // Render nothing rather than a spinner: this resolves from local storage in
  // a millisecond unless a refresh is needed, and a flashed spinner reads as
  // slower than a blank moment.
  if (state !== "in") return null;

  return <>{children}</>;
}
