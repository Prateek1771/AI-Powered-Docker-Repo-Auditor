import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * Which token path a build takes, and that a 401 ends the session.
 *
 * The bug these cover shipped green: the frontend's only auth path was
 * `/dev/token`, which 404s wherever DEV_AUTH is unset - so the deployed UI
 * could not authenticate at all while tsc and every test passed, because a
 * token is a `string` on both branches. Nothing asserted WHICH branch ran.
 * See docs/audits/audit-02-frontend-worker-observability.md F1.
 */

// Each test imports lib/api fresh, because the branch is chosen from
// module-scope config read at import time.
async function loadApi(cognito: boolean) {
  vi.resetModules();

  vi.doMock("@/lib/auth", () => ({
    cognitoConfigured: cognito,
    cognitoIdToken: vi.fn().mockResolvedValue(cognito ? "cognito-id-token" : null),
    signOut: vi.fn(),
  }));

  return import("@/lib/api");
}

afterEach(() => {
  vi.doUnmock("@/lib/auth");
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("token path selection", () => {
  it("uses /dev/token when no pool is configured", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ token: "dev-token", expires_in: 3600 }),
    });

    vi.stubGlobal("fetch", fetchMock);

    const api = await loadApi(false);

    await expect(api.getToken()).resolves.toBe("dev-token");

    expect(fetchMock).toHaveBeenCalledOnce();
    expect(String(fetchMock.mock.calls[0][0])).toContain("/dev/token");
  });

  it("uses the Cognito id token when a pool is configured, and never calls /dev/token", async () => {
    const fetchMock = vi.fn();

    vi.stubGlobal("fetch", fetchMock);

    const api = await loadApi(true);

    await expect(api.getToken()).resolves.toBe("cognito-id-token");

    // The whole finding in one assertion: a deployed build must not reach for
    // the development issuer.
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("throws NotAuthenticated rather than a token when nobody is signed in", async () => {
    vi.resetModules();

    vi.doMock("@/lib/auth", () => ({
      cognitoConfigured: true,
      cognitoIdToken: vi.fn().mockResolvedValue(null),
      signOut: vi.fn(),
    }));

    const api = await import("@/lib/api");

    await expect(api.getToken()).rejects.toThrow("Not signed in.");
  });
});

describe("dev token caching", () => {
  it("issues one request for concurrent callers, not one each", async () => {
    let resolveFetch: (value: unknown) => void = () => {};

    const fetchMock = vi.fn().mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveFetch = resolve;
        }),
    );

    vi.stubGlobal("fetch", fetchMock);

    const api = await loadApi(false);

    // The scan page mounts several components that all call getToken() on the
    // same paint. Caching only the resolved value let every one of them miss.
    const all = Promise.all([api.getToken(), api.getToken(), api.getToken()]);

    resolveFetch({
      ok: true,
      json: async () => ({ token: "dev-token", expires_in: 3600 }),
    });

    await expect(all).resolves.toEqual([
      "dev-token",
      "dev-token",
      "dev-token",
    ]);

    expect(fetchMock).toHaveBeenCalledOnce();
  });
});
