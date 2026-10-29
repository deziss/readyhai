export interface ScanReportAvailability {
  html: boolean;
  json: boolean;
  sarif: boolean;
  junit: boolean;
}

export interface ScanCategoryStats {
  category: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  new: number;
  existing: number;
  suppressed: number;
}

export interface ScanSummary {
  id: string;
  target: string;
  kind: "repo" | "image" | "host" | "web" | string;
  profile: string;
  verdict: "PASS" | "WARN" | "FAIL" | "UNKNOWN" | string;
  state: string;
  started: string;
  finished?: string;
  reasons: string[];
  findings_count: number;
  hard_fail_count: number;
  categories: Record<string, unknown>;
  reports: ScanReportAvailability;
}

export interface ScanFinding {
  id?: string;
  rule: string;
  check: string;
  title: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info" | string;
  location: string;
  detail?: string;
  remediation?: string;
  fingerprint?: string;
  status?: string;
  kev?: boolean;
}

export interface ScanCheck {
  id: string;
  title: string;
  duration_ms: number;
  findings: number;
  tool?: string;
  status: {
    state: "passed" | "failed" | "skipped" | "not_applicable" | string;
    reason?: string;
  };
}

export interface ScanDetail {
  id: string;
  target: {
    kind: string;
    raw: string;
    path?: string;
  };
  verdict: string;
  profile: string;
  started: string;
  finished?: string;
  reasons: string[];
  findings: ScanFinding[];
  checks: ScanCheck[];
  categories: ScanCategoryStats[];
  errors: unknown[];
  notes?: string[];
  version?: string;
  reports?: ScanReportAvailability;
}
