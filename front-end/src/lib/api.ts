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

export type LabConfig = {
  toggles: Record<string, boolean>;
  mockLab: "connected" | "offline";
};

export async function fetchLabConfig(): Promise<LabConfig> {
  const response = await fetch("/api/v1/lab", { cache: "no-store" });
  if (!response.ok) {
    throw new Error(await parseError(response));
  }
  return (await response.json()) as LabConfig;
}

export async function setLabToggle(key: string, value: boolean): Promise<LabConfig> {
  const response = await fetch("/api/v1/lab", {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key, value }),
  });
  if (!response.ok) {
    throw new Error(await parseError(response));
  }
  return (await response.json()) as LabConfig;
}

export async function resetLabConfig(): Promise<LabConfig> {
  const response = await fetch("/api/v1/lab", { method: "POST" });
  if (!response.ok) {
    throw new Error(await parseError(response));
  }
  return (await response.json()) as LabConfig;
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

function filenameFromDisposition(header: string | null): string | null {
  if (!header) return null;
  const utfMatch = header.match(/filename\*=UTF-8''([^;]+)/i);
  if (utfMatch?.[1]) return decodeURIComponent(utfMatch[1]);
  const quoted = header.match(/filename="([^"]+)"/i);
  if (quoted?.[1]) return quoted[1];
  const plain = header.match(/filename=([^;]+)/i);
  return plain?.[1]?.trim() ?? null;
}

export async function downloadScanPdf(report: ScanReport): Promise<void> {
  const response = await fetch("/api/v1/report/pdf", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(report),
  });
  if (!response.ok) {
    throw new Error(await parseError(response));
  }
  const blob = await response.blob();
  const filename = filenameFromDisposition(response.headers.get("content-disposition")) ?? "fapi-scan.pdf";
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
