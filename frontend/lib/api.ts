import type { FullReport, LocalImage, ScanSummary } from "@/types/scan";

const API_URL = process.env.NEXT_PUBLIC_API_URL!;

let cachedToken: { value: string; expiresAt: number } | null = null;

/**
 * Fetch a dev token, reusing the cached one until it nears expiry.
 *
 * Refreshed a minute early, because a token that expires between our
 * check and the server's produces a 401 that looks like a bug.
 */
export async function getToken(): Promise<string> {
  if (cachedToken && Date.now() < cachedToken.expiresAt) {
    return cachedToken.value;
  }

  const resp = await fetch(`${API_URL}/dev/token`);

  if (!resp.ok) {
    throw new Error(
      "Could not get a token. Is the API running with DEV_AUTH=1?",
    );
  }

  const data = await resp.json();

  cachedToken = {
    value: data.token,
    // Refresh a minute early. A token that expires between our check and the
    // server's produces a 401 that looks like a bug.
    expiresAt: Date.now() + (data.expires_in - 60) * 1000,
  };

  return cachedToken.value;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = await getToken();

  const resp = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      ...init?.headers,
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });

  // Messages name the fix, not the mechanism. "Try again in an hour" tells a
  // person what to do; "HTTP 429" tells them what the protocol did.
  if (resp.status === 429) {
    throw new Error("Scan limit reached. Try again in an hour.");
  }

  if (resp.status === 404) {
    throw new Error("Not found.");
  }

  if (!resp.ok) {
    throw new Error(`Request failed (${resp.status}).`);
  }

  return resp.json() as Promise<T>;
}

/** List the images on the daemon the API can reach, empty in registry mode. */
export function listImages() {
  return request<LocalImage[]>("/api/v1/images");
}

/**
 * Upload a `docker save` tar and get back the target that names it.
 *
 * Its own fetch rather than `request`: that helper pins
 * `Content-Type: application/json`, and multipart has to set its own
 * boundary or the server cannot parse the body.
 */
export async function uploadImage(
  file: File,
): Promise<{ target: string; repo_id: string }> {
  const token = await getToken();

  const body = new FormData();

  body.append("file", file);

  const resp = await fetch(`${API_URL}/api/v1/images/upload`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body,
  });

  if (!resp.ok) {
    const detail = await resp.json().catch(() => null);

    throw new Error(detail?.detail ?? `Upload failed (${resp.status}).`);
  }

  return resp.json();
}

/** Queue a scan and return its job id. */
export function startScan(repoId: string, target: string) {
  return request<{ job_id: string; status: string }>("/api/v1/scans", {
    method: "POST",
    body: JSON.stringify({ repo_id: repoId, target }),
  });
}

/** Fetch a scan's scores and counts. */
export function getSummary(jobId: string) {
  return request<ScanSummary>(`/api/v1/scans/${jobId}`);
}

/** Fetch a scan's full report, including every finding. */
export function getReport(jobId: string) {
  return request<FullReport>(`/api/v1/scans/${jobId}/report`);
}

/** Fetch previous scans of one repository, newest first. */
export function getHistory(repoId: string) {
  return request<ScanSummary[]>(`/api/v1/scans/history/${repoId}`);
}
