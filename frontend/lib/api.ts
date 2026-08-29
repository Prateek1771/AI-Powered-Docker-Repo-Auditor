import type { FullReport, ScanSummary } from "@/types/scan";

const API_URL = process.env.NEXT_PUBLIC_API_URL!;

let cachedToken: { value: string; expiresAt: number } | null = null;

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

export function startScan(repoId: string, target: string) {
  return request<{ job_id: string; status: string }>("/api/v1/scans", {
    method: "POST",
    body: JSON.stringify({ repo_id: repoId, target }),
  });
}

export function getSummary(jobId: string) {
  return request<ScanSummary>(`/api/v1/scans/${jobId}`);
}

export function getReport(jobId: string) {
  return request<FullReport>(`/api/v1/scans/${jobId}/report`);
}

export function getHistory(repoId: string) {
  return request<ScanSummary[]>(`/api/v1/scans/history/${repoId}`);
}
