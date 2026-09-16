import { describe, expect, it } from "vitest";

import { PANELS, isPanelName } from "@/lib/panels";

/**
 * The guard that keeps the metrics route from being an open Prometheus.
 *
 * The route takes a panel NAME and looks the expression up here. If
 * isPanelName ever let an arbitrary string through, the handler would forward
 * caller-supplied PromQL to a server that happily runs `{__name__=~".+"}`.
 */
describe("panel whitelist", () => {
  it("accepts only names that are defined", () => {
    expect(isPanelName("scan_outcomes")).toBe(true);
    expect(isPanelName("otel_queue_size")).toBe(true);
  });

  it("rejects anything else, including prototype keys", () => {
    expect(isPanelName("up")).toBe(false);
    expect(isPanelName("")).toBe(false);
    expect(isPanelName('sum(rate(x[5m]))')).toBe(false);

    // `"constructor" in PANELS` is true for a plain object, so a naive `in`
    // check would treat it as a valid panel and then index to a function.
    expect(isPanelName("constructor")).toBe(false);
    expect(isPanelName("toString")).toBe(false);
    expect(isPanelName("__proto__")).toBe(false);
  });

  it("gives every panel a query and a known kind", () => {
    for (const [name, spec] of Object.entries(PANELS)) {
      expect(spec.query, name).toBeTruthy();
      expect(["range", "instant"], name).toContain(spec.kind);
    }
  });
});
