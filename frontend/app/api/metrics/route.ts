import { NextResponse } from "next/server";

import { PANELS, isPanelName, type PanelSpec } from "@/lib/panels";

/**
 * Query Prometheus on the server and hand back JSON.
 *
 * Server-side on purpose. The alternative - letting the browser call
 * Prometheus - needs CORS enabled and Prometheus published to whoever can
 * reach the page. Shipping an open PromQL endpoint from a product whose whole
 * job is finding that kind of mistake would be poor form, and it is also just
 * more moving parts than a fetch on this side of the network.
 *
 * PROMETHEUS_URL is deliberately NOT NEXT_PUBLIC_: it names a host that only
 * this container can reach, and baking it into the bundle would advertise it.
 */

const PROMETHEUS_URL = process.env.PROMETHEUS_URL ?? "";

// Longer than a scrape interval and shorter than a coffee. The data behind
// these panels moves at 15s, so a caller polling faster is asking for the same
// answer.
const REVALIDATE_SECONDS = 10;

export async function GET(request: Request) {
  if (!PROMETHEUS_URL) {
    return NextResponse.json(
      { error: "not_configured" },
      // 501, not 500: nothing is broken. This deployment simply has no metrics
      // backend, which the UI turns into "start the observability profile"
      // rather than an error.
      { status: 501 },
    );
  }

  const name = new URL(request.url).searchParams.get("panel") ?? "";

  if (!isPanelName(name)) {
    return NextResponse.json({ error: "unknown_panel" }, { status: 400 });
  }

  const spec: PanelSpec = PANELS[name];

  const path =
    spec.kind === "range" ? "/api/v1/query_range" : "/api/v1/query";

  const params = new URLSearchParams({ query: spec.query });

  if (spec.kind === "range") {
    const end = Math.floor(Date.now() / 1000);

    // Six hours at one-minute resolution: 360 points, which is about as many
    // as a chart this size can show without drawing on top of itself.
    params.set("start", String(end - 6 * 60 * 60));
    params.set("end", String(end));
    params.set("step", "60");
  }

  try {
    const resp = await fetch(`${PROMETHEUS_URL}${path}?${params}`, {
      next: { revalidate: REVALIDATE_SECONDS },
      // Prometheus is one hop away on the compose network. If it cannot answer
      // in five seconds it is not going to.
      signal: AbortSignal.timeout(5_000),
    });

    if (!resp.ok) {
      return NextResponse.json(
        { error: "upstream", status: resp.status },
        { status: 502 },
      );
    }

    const body = await resp.json();

    return NextResponse.json({
      kind: spec.kind,
      legend: spec.legend ?? null,
      result: body.data?.result ?? [],
    });
  } catch {
    // The observability profile not being up is the common case here, and it
    // is not an error worth a stack trace in the UI.
    return NextResponse.json({ error: "unreachable" }, { status: 503 });
  }
}
