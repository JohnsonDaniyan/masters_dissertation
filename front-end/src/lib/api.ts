import type { CatalogCheck, ScanReport } from "./types";

async function parseError(response: Response): Promise<string> {
  try {
    const body = await response.json();
    if (typeof body?.detail === "string") return body.detail;
    if (Array.isArray(body?.detail)) {
      return body.detail.map((item: { msg?: string }) => item.msg ?? JSON.stringify(item)).join("; ");
    }
  } catch {
    /* fall through */
  }
  return `Scanner API returned ${response.status}`;
}

export async function fetchChecks(): Promise<CatalogCheck[]> {
  const response = await fetch("/api/v1/checks", { cache: "no-store" });
  if (!response.ok) {
    throw new Error(await parseError(response));
  }
  const body = (await response.json()) as { checks: CatalogCheck[] };
  return body.checks;
}

export async function runScan(target: string): Promise<ScanReport> {
  const response = await fetch("/api/v1/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target }),
  });
  if (!response.ok) {
    throw new Error(await parseError(response));
  }
  return (await response.json()) as ScanReport;
}
