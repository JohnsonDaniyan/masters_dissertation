export type CheckStatus = "pass" | "fail" | "error";
export type Severity = "high" | "medium" | "low" | "info";

export type CatalogCheck = {
  check_id: string;
  title: string;
  description: string;
  reference: string;
};

export type TestResult = {
  check_id: string;
  description: string;
  status: CheckStatus;
  severity: Severity;
  endpoint: string;
  detail: string;
  remedy: string;
  reference: string;
};

export type ScanReport = {
  target: string;
  metadata_url: string;
  started_at: string;
  finished_at: string;
  duration_ms: number;
  summary: {
    pass: number;
    fail: number;
    error: number;
    total: number;
  };
  checks: CatalogCheck[];
  results: TestResult[];
};
