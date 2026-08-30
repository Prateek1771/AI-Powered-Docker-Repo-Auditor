"use client";

import { useEffect, useRef, useState } from "react";

import { getToken } from "@/lib/api";
import type { ProgressEvent } from "@/types/scan";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL!;

// 1000 = the job finished and the server closed cleanly. 1008 = auth or
// authorization failure. Neither improves on retry, and retrying 1000 is the
// reference implementation's every-3-seconds-forever bug.
const NO_RETRY_CODES = new Set([1000, 1008]);
const MAX_ATTEMPTS = 6;
const BASE_DELAY_MS = 1000;
const MAX_DELAY_MS = 30000;

type Connection = "connecting" | "open" | "closed" | "abandoned";

/**
 * Exponential backoff with jitter, capped so retries stay polite.
 *
 * The jitter matters when a server restart drops every socket at once:
 * without it they all reconnect on the same schedule.
 */
function backoffMs(attempt: number): number {
  const base = Math.min(BASE_DELAY_MS * 2 ** attempt, MAX_DELAY_MS);

  // Jitter matters when the API restarts: without it every open tab
  // reconnects at the same instant, is refused together, and retries together.
  return base + Math.random() * 0.3 * base;
}

/**
 * Subscribe to a job's live progress over a WebSocket.
 *
 * Reconnects with backoff, except on the close codes that mean trying
 * again cannot help - a normal close and an authorization failure are
 * both final. Reports its connection state so the UI can say the scan is
 * still running when the socket is not.
 */
export function useScanProgress(jobId: string | null) {
  const [event, setEvent] = useState<ProgressEvent | null>(null);
  const [connection, setConnection] = useState<Connection>("closed");

  const attempts = useRef(0);

  useEffect(() => {
    if (!jobId) return;

    // Captured in the effect closure and checked after every await and in
    // every callback. Without it, unmounting during getToken() leaves the
    // resolved socket open with no cleanup path.
    let cancelled = false;
    let socket: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;

    attempts.current = 0;

    const open = async () => {
      if (cancelled) return;

      setConnection("connecting");

      let token: string;

      try {
        token = await getToken();
      } catch {
        if (!cancelled) setConnection("abandoned");

        return;
      }

      if (cancelled) return;

      socket = new WebSocket(
        `${WS_URL}/ws/jobs/${jobId}?token=${encodeURIComponent(token)}`,
      );

      socket.onopen = () => {
        if (cancelled) return;

        // A connection that succeeds then drops an hour later starts over at
        // one second, not thirty.
        attempts.current = 0;

        setConnection("open");
      };

      socket.onmessage = (raw) => {
        if (cancelled) return;

        let parsed: unknown;

        try {
          parsed = JSON.parse(raw.data);
        } catch {
          console.warn("Dropping unparseable progress frame");

          return;
        }

        const data = parsed as Partial<ProgressEvent> & { type?: string };

        if (data.type === "ping") return;

        // Logged, never silently swallowed. A dropped event you cannot see is
        // a UI stuck at 40% with no explanation.
        if (typeof data.progress !== "number" || !data.status) {
          console.warn("Dropping malformed progress event", data);

          return;
        }

        setEvent(data as ProgressEvent);
      };

      socket.onclose = (closeEvent) => {
        if (cancelled) return;

        setConnection("closed");

        if (NO_RETRY_CODES.has(closeEvent.code)) return;

        if (attempts.current >= MAX_ATTEMPTS) {
          setConnection("abandoned");

          return;
        }

        const delay = backoffMs(attempts.current);

        attempts.current += 1;

        timer = setTimeout(open, delay);
      };
    };

    void open();

    return () => {
      cancelled = true;

      if (timer) clearTimeout(timer);

      socket?.close(1000);
    };
  }, [jobId]);

  const isTerminal =
    event?.status === "completed" || event?.status === "failed";

  return { event, connection, isTerminal };
}
