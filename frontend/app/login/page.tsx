"use client";

import { Loader2, LogIn } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { clearSession } from "@/lib/api";
import { cognitoConfigured, signIn } from "@/lib/auth";

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Only ever a same-origin path. Taking the raw query parameter would let a
  // crafted link bounce someone to another site straight after they signed in.
  const raw = params.get("next") ?? "/";
  const next = raw.startsWith("/") && !raw.startsWith("//") ? raw : "/";

  const submit = async (formEvent: React.FormEvent) => {
    formEvent.preventDefault();

    setBusy(true);
    setError(null);

    // A stale stored session is how signing in appears to work and the next
    // request 401s again.
    clearSession();

    try {
      await signIn(email.trim(), password);

      router.push(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not sign in.");
    } finally {
      setBusy(false);
    }
  };

  if (!cognitoConfigured) {
    return (
      <Card className="p-6">
        <h1 className="text-sm font-medium text-foreground">
          No sign-in needed
        </h1>
        <p className="mt-2 text-sm text-muted">
          This build has no identity pool configured, so it is using the local
          development issuer. Go back and start a scan.
        </p>
        <Button variant="outline" onClick={() => router.push("/")} className="mt-4">
          Back
        </Button>
      </Card>
    );
  }

  return (
    <Card className="p-6">
      <h1 className="font-mono text-lg font-semibold text-foreground">
        Sign in
      </h1>
      <p className="mt-1 text-sm text-faint">
        Your scans are yours. Every report is scoped to this account.
      </p>

      <form onSubmit={submit} className="mt-6 space-y-4">
        <div>
          <label
            htmlFor="email"
            className="block text-xs font-semibold uppercase tracking-[0.12em] text-faint"
          >
            Email
          </label>
          <input
            id="email"
            type="email"
            required
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1.5 w-full rounded-md border border-border bg-surface px-3 py-2 text-sm text-foreground outline-none focus-visible:border-border-strong"
          />
        </div>

        <div>
          <label
            htmlFor="password"
            className="block text-xs font-semibold uppercase tracking-[0.12em] text-faint"
          >
            Password
          </label>
          <input
            id="password"
            type="password"
            required
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1.5 w-full rounded-md border border-border bg-surface px-3 py-2 text-sm text-foreground outline-none focus-visible:border-border-strong"
          />
        </div>

        {/* role="alert" so a screen reader is told about a failed sign-in
            rather than leaving the person to re-read the form. */}
        {error && (
          <p role="alert" className="text-sm text-warn">
            {error}
          </p>
        )}

        <Button type="submit" disabled={busy} className="w-full">
          {busy ? (
            <Loader2 aria-hidden className="size-4 animate-spin" />
          ) : (
            <LogIn aria-hidden className="size-4" />
          )}
          {busy ? "Signing in" : "Sign in"}
        </Button>
      </form>
    </Card>
  );
}

export default function LoginPage() {
  return (
    <main className="mx-auto flex min-h-dvh max-w-md items-center px-6">
      {/* useSearchParams needs a Suspense boundary or the whole route opts out
          of static rendering at build time. */}
      <Suspense fallback={null}>
        <LoginForm />
      </Suspense>
    </main>
  );
}
