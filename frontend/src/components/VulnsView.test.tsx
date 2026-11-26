import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { VulnsView } from "./VulnsView";

// ---------------------------------------------------------------------------
// Fixtures. The wire format (GET /api/vulns, POST /api/vulns/{fingerprint})
// comes from a Rust server whose object key order differs from our TS
// literals, so stub payloads are re-serialized below before being returned.
// ---------------------------------------------------------------------------

interface VulnFixture {
  fingerprint: string;
  target: string;
  target_key: string;
  kind: string;
  rule: string;
  title: string;
  severity: string;
  resource: string;
  first_seen: string;
  last_seen: string;
  occurrences: number;
  status: string;
  message: string;
  verification: string;
  verified_by: string | null;
  verified_at: string | null;
}

function vuln(over: Partial<VulnFixture> & { fingerprint: string }): VulnFixture {
  return {
    target: "https://app.example.com",
    target_key: "app.example.com",
    kind: "http",
    rule: "missing-csp",
    title: "[WARN] Missing Content-Security-Policy header",
    severity: "medium",
    resource: "/api/v1/orders",
    first_seen: "2026-11-20T10:00:00Z",
    last_seen: "2026-11-22T18:30:00Z",
    occurrences: 3,
    status: "open",
    message: "No CSP header was returned on 5 sampled responses.",
    verification: "unverified",
    verified_by: null,
    verified_at: null,
    ...over,
  };
}

const PAYLOAD = {
  count: 3,
  vulns: [
    vuln({ fingerprint: "aa11aa11bb22bb22" }),
    vuln({
      fingerprint: "cc33cc33dd44dd44",
      target: "https://admin.example.com",
      target_key: "admin.example.com",
      rule: "sql-injection-reflected",
      title: "[FAIL] Reflected SQL injection in /search",
      severity: "high",
      resource: "/search",
      occurrences: 12,
    }),
    vuln({
      fingerprint: "ee55ee55ff66ff66",
      rule: "tls-1-0-enabled",
      title: "[WARN] TLS 1.0 still enabled",
      severity: "low",
      occurrences: 1,
      status: "accepted",
    }),
  ],
};

/** Serialize like the server's wire format: keys sorted alphabetically, a
 * different order from our object literals (SettingsView.test lesson). */
function serializeLikeServer(value: unknown): string {
  const sortDeep = (v: unknown, cmp: (a: string, b: string) => number): unknown =>
    v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(
          Object.keys(v)
            .sort(cmp)
            .map((k) => [k, sortDeep((v as Record<string, unknown>)[k], cmp)])
        )
      : Array.isArray(v)
        ? v.map((x) => sortDeep(x, cmp))
        : v;
  return JSON.stringify(sortDeep(value, (a, b) => (a < b ? -1 : 1)));
}

/** Same payload, opposite key order ("status" before "fingerprint", etc):
 * assertions must pass with either ordering on the wire. */
function serializeReversed(value: unknown): string {
  const sortDeep = (v: unknown): unknown =>
    v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(
          Object.keys(v)
            .sort()
            .reverse()
            .map((k) => [k, sortDeep((v as Record<string, unknown>)[k])])
        )
      : Array.isArray(v)
        ? v.map(sortDeep)
        : v;
  return JSON.stringify(sortDeep(value));
}

interface StubOptions {
  /** Response body text for GET /api/vulns. */
  list?: string;
  listStatus?: number;
  listError?: string;
  /** Behavior of POST /api/vulns/{fp}. */
  postStatus?: number;
  postError?: string;
  /** Templates returned by GET /api/exploits/templates ([] when omitted... see default). */
  templates?: unknown[];
  /** HTTP status for GET /api/exploits/templates (404 = backend without exploits). */
  templatesStatus?: number;
  /** HTTP status for POST /api/exploits/run. */
  runStatus?: number;
  /** results[] of POST /api/exploits/run when runStatus is 200. */
  runResults?: unknown[];
  /** Error text for POST /api/exploits/run non-200 (e.g. the 409 exploitation-disabled message). */
  runError?: string;
}

interface Call {
  url: string;
  method: string;
  body?: string;
}

/** A template whose keywords match the fixture row with rule "env-file-read". */
const DOTENV_TEMPLATE = {
  id: "http.dotenv-exposed",
  title: "Exposed .env file",
  family: "exposure",
  applies_keywords: ["env", "dotenv"],
  http: true,
  description: "Fetches the .env file and looks for credential assignments.",
};

function stubBackend(opts: StubOptions = {}) {
  const calls: Call[] = [];
  const list = opts.list ?? serializeLikeServer(PAYLOAD);
  const listStatus = opts.listStatus ?? 200;
  const postStatus = opts.postStatus ?? 200;
  const templatesStatus = opts.templatesStatus ?? (opts.templates ? 200 : 404);
  const runStatus = opts.runStatus ?? 200;

  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const url = String(input);
      const method = init.method ?? "GET";
      calls.push({ url, method, body: typeof init.body === "string" ? init.body : undefined });

      if (url === "/api/exploits/templates") {
        return templatesStatus === 200
          ? new Response(
              serializeLikeServer({ count: (opts.templates ?? []).length, templates: opts.templates ?? [] }),
              { status: 200 }
            )
          : new Response(JSON.stringify({ error: "no such endpoint" }), { status: templatesStatus });
      }
      if (url === "/api/exploits/run" && method === "POST") {
        return runStatus === 200
          ? new Response(
              serializeLikeServer({ executed: (opts.runResults ?? []).length, results: opts.runResults ?? [] }),
              { status: 200 }
            )
          : new Response(JSON.stringify({ error: opts.runError ?? "exploitation is disabled" }), {
              status: runStatus,
            });
      }
      if (url.startsWith("/api/vulns?") || url === "/api/vulns") {
        return listStatus === 200
          ? new Response(list, { status: 200 })
          : new Response(JSON.stringify({ error: opts.listError ?? "boom" }), { status: listStatus });
      }
      if (url.startsWith("/api/vulns/") && method === "POST") {
        return postStatus === 200
          ? new Response(JSON.stringify({ ok: true }), { status: 200 })
          : new Response(JSON.stringify({ error: opts.postError ?? "nope" }), { status: postStatus });
      }
      return new Response("{}", { status: 200 });
    })
  );
  return calls;
}

/** The <tr> containing the given fingerprint text (in a title attribute or aria-label). */
function rowFor(fingerprint: string): HTMLTableRowElement {
  const btn = screen.getByLabelText(`Accept finding ${fingerprint}`);
  const tr = btn.closest("tr");
  if (!tr) throw new Error(`no row for ${fingerprint}`);
  return tr;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("VulnsView", () => {
  it("renders rows from the stubbed payload", async () => {
    stubBackend();
    render(<VulnsView />);

    await screen.findByText("[WARN] Missing Content-Security-Policy header");
    expect(screen.getByText("[FAIL] Reflected SQL injection in /search")).toBeTruthy();

    const row = rowFor("aa11aa11bb22bb22");
    expect(within(row).getByText("Medium").textContent).toBe("Medium");
    expect(within(row).getByText("3")).toBeTruthy();
    expect(within(row).getByText("Open")).toBeTruthy();
    expect(within(row).getByText("missing-csp")).toBeTruthy();

    const highRow = rowFor("cc33cc33dd44dd44");
    expect(within(highRow).getByText("High")).toBeTruthy();
    expect(within(highRow).getByText("12")).toBeTruthy();

    // counts header reflects the loaded data (accepted row is in the payload)
    expect(screen.getByTestId("vuln-counts").textContent).toContain("2 open");
    expect(screen.getByTestId("vuln-counts").textContent).toContain("1 accepted");
  });

  it("renders identically when the server orders keys differently", async () => {
    stubBackend({ list: serializeReversed(PAYLOAD) });
    render(<VulnsView />);

    // "status" before "fingerprint" etc.: every column must still render.
    await screen.findByText("[FAIL] Reflected SQL injection in /search");
    const highRow = rowFor("cc33cc33dd44dd44");
    expect(within(highRow).getByText("High")).toBeTruthy();
    expect(within(highRow).getByText("12")).toBeTruthy();
    expect(within(highRow).getByText("Open")).toBeTruthy();
    expect(within(highRow).getByText("sql-injection-reflected")).toBeTruthy();
  });

  it("Accept posts {status:'accepted'} for that fingerprint and updates the row locally", async () => {
    const calls = stubBackend();
    render(<VulnsView />);
    await screen.findByText("[WARN] Missing Content-Security-Policy header");
    // "all" so the row stays visible after it stops being open
    fireEvent.change(screen.getByLabelText("Filter by status"), { target: { value: "all" } });
    await screen.findByText("[WARN] Missing Content-Security-Policy header");

    fireEvent.click(screen.getByLabelText("Accept finding aa11aa11bb22bb22"));

    await waitFor(() => {
      const post = calls.find((c) => c.method === "POST");
      expect(post).toBeDefined();
      expect(post!.url).toBe("/api/vulns/aa11aa11bb22bb22");
      expect(JSON.parse(post!.body!)).toEqual({ status: "accepted" });
    });
    // local row update: the status chip now says Accepted, with a success strip
    await waitFor(() => expect(within(rowFor("aa11aa11bb22bb22")).getByText("Accepted")).toBeTruthy());
    expect(screen.getByText(/marked Accepted/i)).toBeTruthy();
  });

  it("Forget posts {status:'forgotten'} and updates the row", async () => {
    const calls = stubBackend();
    render(<VulnsView />);
    await screen.findByText("[WARN] Missing Content-Security-Policy header");
    fireEvent.change(screen.getByLabelText("Filter by status"), { target: { value: "all" } });
    await screen.findByLabelText("Forget finding ee55ee55ff66ff66");

    fireEvent.click(screen.getByLabelText("Forget finding ee55ee55ff66ff66"));
    await waitFor(() =>
      expect(calls.some((c) => c.method === "POST" && c.url === "/api/vulns/ee55ee55ff66ff66")).toBe(true)
    );
    const post = calls.find((c) => c.method === "POST")!;
    expect(JSON.parse(post.body!)).toEqual({ status: "forgotten" });
    await waitFor(() => expect(within(rowFor("ee55ee55ff66ff66")).getByText("Forgotten")).toBeTruthy());
  });

  it("shows the admin-required message on 403 and the error message on 404", async () => {
    stubBackend({ postStatus: 403, postError: "role viewer cannot triage findings" });
    const { unmount } = render(<VulnsView />);
    await screen.findByText("[WARN] Missing Content-Security-Policy header");

    fireEvent.click(screen.getByLabelText("Accept finding aa11aa11bb22bb22"));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("requires admin");
    // the row is untouched
    expect(within(rowFor("aa11aa11bb22bb22")).getByText("Open")).toBeTruthy();
    unmount();

    stubBackend({ postStatus: 404, postError: "unknown fingerprint" });
    render(<VulnsView />);
    await screen.findByText("[WARN] Missing Content-Security-Policy header");
    fireEvent.click(screen.getByLabelText("Forget finding aa11aa11bb22bb22"));
    const notFound = await screen.findByRole("alert");
    expect(notFound.textContent).toContain("unknown fingerprint");
  });

  it("filters narrow rows: status, severity and target text", async () => {
    stubBackend({ list: serializeLikeServer({ count: 3, vulns: PAYLOAD.vulns }) });
    render(<VulnsView />);
    await screen.findByText("[WARN] Missing Content-Security-Policy header");

    // status=accepted: only the accepted row remains
    fireEvent.change(screen.getByLabelText("Filter by status"), { target: { value: "accepted" } });
    expect(await screen.findByText(/TLS 1\.0 still enabled/)).toBeTruthy();
    expect(screen.queryByText(/Missing Content-Security-Policy/)).toBeNull();
    expect(screen.queryByText(/Reflected SQL injection/)).toBeNull();

    // status=all + severity=high: only the injection row
    fireEvent.change(screen.getByLabelText("Filter by status"), { target: { value: "all" } });
    fireEvent.change(screen.getByLabelText("Filter by severity"), { target: { value: "high" } });
    await waitFor(() => {
      expect(screen.queryByText(/Missing Content-Security-Policy/)).toBeNull();
      expect(screen.queryByText(/TLS 1.0/)).toBeNull();
    });
    expect(screen.getByText(/Reflected SQL injection/)).toBeTruthy();

    // target text narrows further; here it excludes everything
    fireEvent.change(screen.getByLabelText("Filter by target"), { target: { value: "nope.invalid" } });
    expect(await screen.findByText(/No findings match the current filters/)).toBeTruthy();

    // ...and matches the admin target again
    fireEvent.change(screen.getByLabelText("Filter by target"), { target: { value: "admin.example.com" } });
    expect(await screen.findByText(/Reflected SQL injection/)).toBeTruthy();
    expect(screen.queryByText(/Missing Content-Security-Policy/)).toBeNull();
  });

  it("passes filters through as query params on refetch", async () => {
    const calls = stubBackend();
    render(<VulnsView />);
    await screen.findByText("[WARN] Missing Content-Security-Policy header");
    // default status filter is open, so the initial GET carries it
    expect(calls.some((c) => c.method === "GET" && c.url === "/api/vulns?status=open")).toBe(true);

    fireEvent.change(screen.getByLabelText("Filter by status"), { target: { value: "all" } });
    fireEvent.change(screen.getByLabelText("Filter by severity"), { target: { value: "high" } });
    await waitFor(() =>
      expect(calls.some((c) => c.method === "GET" && c.url.includes("severity=high"))).toBe(true)
    );
  });

  it("renders the empty state when the backend has no findings", async () => {
    stubBackend({ list: serializeLikeServer({ count: 0, vulns: [] }) });
    render(<VulnsView />);
    expect(await screen.findByText(/No vulnerabilities recorded yet/)).toBeTruthy();
    // exact string: the footer note also mentions the CLI, so avoid a regex match on it
    expect(screen.getByText("readyhai vulns list")).toBeTruthy();
  });

  it("renders the fetch failure state", async () => {
    stubBackend({ listStatus: 500, listError: "vuln db locked" });
    render(<VulnsView />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Loading findings failed (HTTP 500)");
    expect(alert.textContent).toContain("vuln db locked");
    expect(screen.queryByText(/No vulnerabilities recorded yet/)).toBeNull();
  });

  it("Refresh button re-requests the list", async () => {
    const calls = stubBackend();
    render(<VulnsView />);
    await screen.findByText("[WARN] Missing Content-Security-Policy header");
    const before = calls.filter((c) => c.method === "GET").length;

    fireEvent.click(screen.getByRole("button", { name: /^Refresh$/ }));
    await waitFor(() => expect(calls.filter((c) => c.method === "GET").length).toBeGreaterThan(before));
  });

  // -------------------------------------------------------------------------
  // Exploitation verification (badges + Verify button)
  // -------------------------------------------------------------------------

  it("shows a verification badge on stamped rows and nothing on unverified rows", async () => {
    const list = serializeLikeServer({
      count: 2,
      vulns: [
        vuln({
          fingerprint: "v1v1v1v1a2a2a2a2",
          rule: "tls-1-0-enabled",
          title: "[WARN] TLS 1.0 still enabled",
          verification: "verified",
          verified_by: "http.tls-legacy-check",
          verified_at: "2026-11-23T09:15:00Z",
        }),
        vuln({ fingerprint: "u1u1u1u1b2b2b2b2" }),
      ],
    });
    stubBackend({ list });
    render(<VulnsView />);
    await screen.findByText("[WARN] TLS 1.0 still enabled");

    const badge = screen.getByTestId("verification-v1v1v1v1a2a2a2a2");
    expect(badge.textContent).toBe("verified");
    expect(badge.getAttribute("title")).toContain("http.tls-legacy-check");
    // unverified rows carry no badge at all
    expect(screen.queryByTestId("verification-u1u1u1u1b2b2b2b2")).toBeNull();
  });

  it("Verify posts the fingerprint and stamps the row with the verdict", async () => {
    const list = serializeLikeServer({
      count: 1,
      vulns: [vuln({ fingerprint: "en01en01en01en01", rule: "env-file-read", title: "[FAIL] .env exposed" })],
    });
    const calls = stubBackend({
      list,
      templates: [DOTENV_TEMPLATE],
      runResults: [
        {
          fingerprint: "en01en01en01en01",
          template: "http.dotenv-exposed",
          verdict: "verified",
          reason: "credentials found in the response body",
          evidence: "AWS_SECRET_ACCESS_KEY=...",
          verified_at: "2026-11-23T09:15:00Z",
        },
      ],
    });
    render(<VulnsView />);
    await screen.findByText("[FAIL] .env exposed");

    const btn = screen.getByLabelText("Verify finding en01en01en01en01");
    fireEvent.click(btn);

    await waitFor(() =>
      expect(calls).toContainEqual(
        expect.objectContaining({ url: "/api/exploits/run", method: "POST" })
      )
    );
    const post = calls.find((c) => c.url === "/api/exploits/run")!;
    expect(JSON.parse(post.body!)).toEqual({ fingerprints: ["en01en01en01en01"] });

    // row is stamped locally from the result, and the verdict surfaces in the notice strip
    await waitFor(() =>
      expect(screen.getByTestId("verification-en01en01en01en01").textContent).toBe("verified")
    );
    expect(await screen.findByText(/Finding en01en01: verified — credentials found/)).toBeTruthy();
  });

  it("surfaces the 409 exploitation-disabled message and a failing run keeps the row", async () => {
    const list = serializeLikeServer({
      count: 1,
      vulns: [vuln({ fingerprint: "en02en02en02en02", rule: "dotenv-exposed", title: "[WARN] dotenv exposed" })],
    });
    stubBackend({ list, templates: [DOTENV_TEMPLATE], runStatus: 409, runError: "enable exploitation in settings first" });
    const { unmount } = render(<VulnsView />);
    await screen.findByText("[WARN] dotenv exposed");

    fireEvent.click(screen.getByLabelText("Verify finding en02en02en02en02"));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("enable exploitation in settings first");
    expect(screen.queryByTestId("verification-en02en02en02en02")).toBeNull();
    unmount();
  });

  it("hides Verify buttons when the backend has no templates endpoint", async () => {
    const list = serializeLikeServer({
      count: 1,
      vulns: [vuln({ fingerprint: "en03en03en03en03", rule: "env-file-read", title: "[FAIL] .env exposed" })],
    });
    stubBackend({ list }); // default templatesStatus 404
    render(<VulnsView />);
    await screen.findByText("[FAIL] .env exposed");
    expect(screen.queryByLabelText("Verify finding en03en03en03en03")).toBeNull();
  });
});
