import { cognitoConfigured, cognitoIdToken, signOut } from "@/lib/auth";
import type {
  ExportFormat,
  FullReport,
  JobStatusResponse,
  LocalImage,
  ScanSummary,
} from "@/types/scan";

const API_URL = process.env.NEXT_PUBLIC_API_URL!;

/** Thrown when there is no session. The UI turns this into a trip to /login. */
export class NotAuthenticated extends Error {
  constructor() {
    super("Not signed in.");

    this.name = "NotAuthenticated";
  }
}

let cachedToken: { value: string; expiresAt: number } | null = null;

// The in-flight request, not just the result. The scan page mounts several
// components that call getToken() on the same paint, and caching only the
// resolved value let every one of them miss and issue its own request.
let inFlight: Promise<string> | null = null;

async function devToken(): Promise<string> {
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

/**
 * The bearer token for an API call.
 *
 * Two paths. Deployed, `NEXT_PUBLIC_COGNITO_*` are set and this is the signed-in
 * user's Cognito ID token; locally they are empty and it falls back to
 * `/dev/token`, so `docker compose up` behaves exactly as it always has.
 *
 * Cognito's own SDK caches and refreshes, so there is no expiry bookkeeping on
 * that branch - `cognitoIdToken()` returns a valid token or null.
 * See docs/AUDIT_02 F1.
 */
export async function getToken(): Promise<string> {
  if (cognitoConfigured) {
    const token = await cognitoIdToken();

    if (!token) throw new NotAuthenticated();

    return token;
  }

  if (cachedToken && Date.now() < cachedToken.expiresAt) {
    return cachedToken.value;
  }

  inFlight ??= devToken().finally(() => {
    inFlight = null;
  });

  return inFlight;
}

/**
 * Drop the session after the API has rejected it.
 *
 * Exported so the login page can call it too: arriving at /login with a stale
 * session stored is how you get a loop where signing in appears to work and
 * the next request 401s again.
 */
export function clearSession(): void {
  cachedToken = null;
  inFlight = null;

  if (cognitoConfigured) signOut();
}

/**
 * The authenticated fetch, stopping short of decoding the body.
 *
 * Split out because request<T>() ends in resp.json(), so it structurally
 * cannot carry SARIF, CSV or JUnit - the export formats would have needed a
 * second copy of the auth and error handling to exist at all.
 */
async function send(path: string, init?: RequestInit): Promise<Response> {
  const token = await getToken();

  const resp = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      ...init?.headers,
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });

  // A rejected token is not a failed request, it is a lost session. Clearing
  // it here means the next call throws NotAuthenticated before reaching the
  // network, which is what the UI turns into a trip to /login.
  if (resp.status === 401) {
    clearSession();

    throw new NotAuthenticated();
  }

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

  return resp;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await send(path, init);

  return resp.json() as Promise<T>;
}

/**
 * Escape one path segment.
 *
 * `repo_id` is user-entered, and a value containing `/`, `?`, `#` or `..`
 * changes which endpoint is called - fetch normalises `..` before the request
 * leaves the browser. The caller only ever attacks themselves with their own
 * token, so this is correctness rather than security, but the WebSocket token
 * has been encoded correctly all along and these were not.
 * See docs/AUDIT_02 F11.
 */
function seg(value: string): string {
  return encodeURIComponent(value);
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
  return request<ScanSummary>(`/api/v1/scans/${seg(jobId)}`);
}

/** Fetch a scan's full report, including every finding. */
export function getReport(jobId: string) {
  return request<FullReport>(`/api/v1/scans/${seg(jobId)}/report`);
}

/** Poll one job's progress. Carries `stale`, which nothing else does. */
export function getJobStatus(jobId: string) {
  return request<JobStatusResponse>(`/api/v1/scans/jobs/${seg(jobId)}`);
}

/**
 * Download a report in one of the machine-readable formats.
 *
 * Returns the body and the filename the server chose. The filename comes from
 * Content-Disposition, which the browser can only read because the API sets
 * expose_headers for it - without that a download lands under a generated
 * name and nobody can tell two reports apart.
 */
export async function downloadReport(
  jobId: string,
  format: ExportFormat,
): Promise<{ blob: Blob; filename: string }> {
  const resp = await send(`/api/v1/scans/${seg(jobId)}/report?format=${format}`);

  const disposition = resp.headers.get("Content-Disposition") ?? "";
  const match = /filename="([^"]+)"/.exec(disposition);

  return {
    blob: await resp.blob(),
    filename: match?.[1] ?? `${jobId}.${format}`,
  };
}

/** Fetch previous scans of one repository, newest first. */
export function getHistory(repoId: string) {
  return request<ScanSummary[]>(`/api/v1/scans/history/${seg(repoId)}`);
}
