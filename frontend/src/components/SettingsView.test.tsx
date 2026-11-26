import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SettingsView } from "./SettingsView";

const SETTINGS_V3 = {
  path: "/data/settings.toml",
  exists: true,
  editable: true,
  version: 3,
  effective: {
    integrations: { tools: "auto", plugins: "off", intrusive: "auto" },
    toggle: [{ id: "tool.nuclei", enabled: "on" }],
  },
  override_count: 1,
  shadowing_env: false,
};

const CHECKS = {
  checks: [
    {
      id: "tool.nuclei",
      title: "Nuclei template scanner",
      source: "builtin",
      kinds: ["web"],
      profile: "standard",
      intrusive: false,
      enabled: true,
      decided_by: "settings",
      reason: null,
    },
    {
      id: "plugin.waf-probe",
      title: "WAF prober",
      source: "plugin",
      kinds: ["web", "api"],
      profile: "deep",
      intrusive: true,
      enabled: false,
      decided_by: "integrations",
      reason: "intrusive plugins are off",
    },
  ],
};

const RBAC = {
  enabled: true,
  mode: "auto",
  file: "/data/rbac.toml",
  boot_admin: true,
  keys: [{ name: "ci-runner", role: "operator", fingerprint: "a1b2c3d4" }],
  counts: { viewer: 1, operator: 1, admin: 1 },
};

type PutBehavior =
  | { kind: "ok" }
  | { kind: "400"; message: string }
  | { kind: "403"; message: string };

interface StubOptions {
  put?: PutBehavior;
  rbacStatus?: number;
  /** Whole GET /api/settings payload override (e.g. with a vulndb section). */
  settingsDoc?: unknown;
  /** HTTP status for GET /api/vulns* (404 simulates a backend without the endpoint). */
  vulnsStatus?: number;
  /** open-count reported by GET /api/vulns when vulnsStatus is 200. */
  vulnsCount?: number;
}

interface Call {
  url: string;
  method: string;
  body?: string;
}

/**
 * Serialize like the server's wire format, which orders object keys
 * differently from our object literals (observed on the live API:
 * `enabled` before `id`, `intrusive` before `plugins` before `tools`).
 * A dirty check that is sensitive to property insertion order only fails
 * against responses serialized this way, so tests must reproduce it.
 */
function serializeLikeServer(value: unknown): string {
  const sortDeep = (v: unknown): unknown =>
    v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(
          Object.keys(v)
            .sort()
            .map((k) => [k, sortDeep((v as Record<string, unknown>)[k])])
        )
      : Array.isArray(v)
        ? v.map(sortDeep)
        : v;
  return JSON.stringify(sortDeep(value));
}

function stubBackend(opts: StubOptions = {}) {
  const calls: Call[] = [];
  const put = opts.put ?? { kind: "ok" };
  const rbacStatus = opts.rbacStatus ?? 200;
  const vulnsStatus = opts.vulnsStatus ?? 200;
  const vulnsCount = opts.vulnsCount ?? 7;
  let saved: unknown = opts.settingsDoc ?? SETTINGS_V3;

  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const url = String(input);
      const method = init.method ?? "GET";
      calls.push({ url, method, body: typeof init.body === "string" ? init.body : undefined });

      if (url === "/api/settings" && method === "GET") {
        return new Response(serializeLikeServer(saved), { status: 200 });
      }
      if (url === "/api/settings" && method === "PUT") {
        if (put.kind === "400") {
          return new Response(JSON.stringify({ error: put.message }), { status: 400 });
        }
        if (put.kind === "403") {
          return new Response(JSON.stringify({ error: put.message }), { status: 403 });
        }
        const body = JSON.parse(String(init.body));
        saved = {
          ...(SETTINGS_V3 as object),
          version: (saved as typeof SETTINGS_V3).version + 1,
          effective: body,
          override_count: (body.toggle as unknown[]).length,
        };
        return new Response(serializeLikeServer(saved), { status: 200 });
      }
      if (url === "/api/settings/checks") {
        return new Response(JSON.stringify(CHECKS), { status: 200 });
      }
      if (url === "/api/rbac") {
        return rbacStatus === 403
          ? new Response(JSON.stringify({ error: "role viewer needs admin to read rbac status" }), { status: 403 })
          : new Response(JSON.stringify(RBAC), { status: 200 });
      }
      if (url.startsWith("/api/vulns")) {
        return vulnsStatus === 200
          ? new Response(serializeLikeServer({ count: vulnsCount, vulns: [] }), { status: 200 })
          : new Response(JSON.stringify({ error: "no such endpoint" }), { status: vulnsStatus });
      }
      return new Response("{}", { status: 200 });
    })
  );
  return calls;
}

/** The segmented auto/on/off buttons of one integration row. */
function segment(label: string) {
  return within(screen.getByRole("group", { name: `Integration setting for ${label}` }));
}

/** True when the named segment of an integration row is the selected one. */
function pressed(label: "Auto" | "On" | "Off", row: string): boolean {
  return segment(row).getByRole("button", { name: label }).getAttribute("aria-pressed") === "true";
}

beforeEach(() => {
  vi.stubGlobal("confirm", vi.fn(() => true));
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("SettingsView", () => {
  it("renders the effective settings into the controls and the checks table", async () => {
    stubBackend();
    render(<SettingsView />);

    // integrations: tools=auto and plugins=off are pressed, and the file line shows the path
    await waitFor(() => expect(pressed("Auto", "Tools")).toBe(true));
    expect(pressed("Off", "Plugins")).toBe(true);
    expect(pressed("Auto", "Intrusive")).toBe(true);
    expect(screen.getByText("/data/settings.toml")).toBeTruthy();
    expect(screen.getByText("v3")).toBeTruthy();

    // checks table renders the mock list with badges and the saved toggle state
    expect(await screen.findByText("Nuclei template scanner")).toBeTruthy();
    expect(screen.getByText("WAF prober")).toBeTruthy();
    expect(screen.getByText("plugin", { selector: "span" })).toBeTruthy();
    expect(within(screen.getByRole("combobox", { name: "Toggle for tool.nuclei" })).getByRole("option", { name: "On", selected: true })).toBeTruthy();
    expect(within(screen.getByRole("combobox", { name: "Toggle for plugin.waf-probe" })).getByRole("option", { name: "Auto", selected: true })).toBeTruthy();
    // the off check explains itself
    expect(screen.getByText("intrusive plugins are off")).toBeTruthy();
    // nothing dirty: no Save button yet
    expect(screen.queryByRole("button", { name: /^Save$/ })).toBeNull();
  });

  it("flipping a check to off makes the view dirty and Saves a whole-doc PUT", async () => {
    const calls = stubBackend();
    render(<SettingsView />);
    const sel = await screen.findByRole("combobox", { name: "Toggle for tool.nuclei" });
    expect(screen.queryByRole("button", { name: /^Save$/ })).toBeNull();

    fireEvent.change(sel, { target: { value: "off" } });
    expect(await screen.findByText("unsaved changes")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /^Save$/ }));
    await waitFor(() =>
      expect(calls).toContainEqual(
        expect.objectContaining({ url: "/api/settings", method: "PUT" })
      )
    );
    const putBody = JSON.parse(calls.find((c) => c.method === "PUT")!.body!);
    // exact contract shape: { integrations: {...}, toggle: [...] }
    expect(putBody).toEqual({
      integrations: { tools: "auto", plugins: "off", intrusive: "auto" },
      toggle: [{ id: "tool.nuclei", enabled: "off" }],
    });

    // success: version bumps from the response, draft resets, the saved line shows
    expect(await screen.findByText(/Settings saved \(version 4\)/)).toBeTruthy();
    expect(await screen.findByText("v4")).toBeTruthy();
    expect(screen.queryByText("unsaved changes")).toBeNull();
  });

  it("never selects intrusive=on: it warns and keeps the value", async () => {
    const calls = stubBackend();
    render(<SettingsView />);
    await screen.findByText("Nuclei template scanner");

    fireEvent.click(segment("Intrusive").getByRole("button", { name: "On" }));
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.getByText(/cannot be forced on/i)).toBeTruthy();
    // still auto, and no draft change (no Save appeared)
    expect(pressed("Auto", "Intrusive")).toBe(true);
    expect(screen.queryByRole("button", { name: /^Save$/ })).toBeNull();
    // intrusive "off" is a legitimate draft edit
    fireEvent.click(segment("Intrusive").getByRole("button", { name: "Off" }));
    expect(await screen.findByRole("button", { name: /^Save$/ })).toBeTruthy();
    expect(pressed("Off", "Intrusive")).toBe(true);
    expect(calls.filter((c) => c.method === "PUT")).toHaveLength(0);
  });

  it("surfaces the 400 message from the server on Save", async () => {
    stubBackend({ put: { kind: "400", message: 'invalid toggle glob "plugin.("' } });
    render(<SettingsView />);
    fireEvent.change(await screen.findByRole("combobox", { name: "Toggle for tool.nuclei" }), {
      target: { value: "off" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^Save$/ }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain('invalid toggle glob "plugin.("');
    // still dirty afterwards: the draft is kept so the operator can fix it
    expect(screen.getByText("unsaved changes")).toBeTruthy();
  });

  it("surfaces the 403 admin-required message from the server on Save", async () => {
    stubBackend({ put: { kind: "403", message: "role operator needs admin to write settings" } });
    render(<SettingsView />);
    fireEvent.change(await screen.findByRole("combobox", { name: "Toggle for tool.nuclei" }), {
      target: { value: "off" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^Save$/ }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("needs admin to write settings");
  });

  it("renders the RBAC panel for admins", async () => {
    stubBackend();
    render(<SettingsView />);
    expect(await screen.findByText("RBAC enabled")).toBeTruthy();
    expect(screen.getByText("ci-runner")).toBeTruthy();
    expect(screen.getByText("a1b2c3d4")).toBeTruthy();
    expect(screen.getByText(/edit rbac.toml on the server and restart/i)).toBeTruthy();
    expect(screen.getByText("boot admin enabled")).toBeTruthy();
  });

  it("renders the admin-only note when RBAC returns 403", async () => {
    stubBackend({ rbacStatus: 403 });
    render(<SettingsView />);
    expect(await screen.findByText(/RBAC details require admin/)).toBeTruthy();
    expect(screen.queryByText("ci-runner")).toBeNull();
  });

  it("adds a custom glob toggle row and sends it in the PUT payload", async () => {
    const calls = stubBackend();
    render(<SettingsView />);
    await screen.findByText("Nuclei template scanner");

    // empty id is rejected client-side
    fireEvent.click(screen.getByRole("button", { name: /^Add$/ }));
    expect(await screen.findByText(/Enter a check id or glob/)).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Add custom toggle"), { target: { value: "plugin.*" } });
    fireEvent.click(screen.getByRole("button", { name: /^Add$/ }));
    expect(await screen.findByText(/not matched yet/)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /^Save$/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    const putBody = JSON.parse(calls.find((c) => c.method === "PUT")!.body!);
    expect(putBody.toggle).toContainEqual({ id: "plugin.*", enabled: "on" });
  });

  it("shows the vuln database card with path and open count", async () => {
    stubBackend({
      settingsDoc: { ...SETTINGS_V3, vulndb: { enabled: true, path: "/data/vulns.db" } },
      vulnsCount: 7,
    });
    render(<SettingsView />);

    expect(await screen.findByText("Vulnerability database")).toBeTruthy();
    expect(screen.getByText("vuln database enabled")).toBeTruthy();
    expect(screen.getByText("/data/vulns.db")).toBeTruthy();
    // live open count from the stubbed GET /api/vulns
    const countLine = await screen.findByText(/Open findings/);
    expect(countLine.textContent).toContain("7");
  });

  it("renders the vulndb fallback when the settings payload lacks the section", async () => {
    // default SETTINGS_V3 has no vulndb key; also simulate a 404 on /api/vulns
    stubBackend({ vulnsStatus: 404 });
    render(<SettingsView />);

    expect(await screen.findByText(/not reported by this backend version/)).toBeTruthy();
    expect(screen.queryByText("vuln database enabled")).toBeNull();
  });

  it("renders the exploitation card and sends the section in every PUT", async () => {
    const docWithExploits = {
      ...SETTINGS_V3,
      effective: {
        ...SETTINGS_V3.effective,
        exploits: { enabled: true, max_probes: 10 },
      },
    };
    const calls = stubBackend({ settingsDoc: docWithExploits });
    render(<SettingsView />);

    // card renders the effective values: on-pill and the probe bound
    expect(await screen.findByText("Exploitation")).toBeTruthy();
    const pill = screen.getByRole("switch", { name: "Exploitation enabled" });
    expect(pill.getAttribute("aria-checked")).toBe("true");
    expect(pill.textContent).toBe("exploitation enabled");
    const probes = screen.getByLabelText(/Max probes/) as HTMLInputElement;
    expect(probes.value).toBe("10");
    // the section is not dirty on load
    expect(screen.queryByRole("button", { name: /^Save$/ })).toBeNull();

    // editing the toggle marks the view dirty and rides along in the PUT
    fireEvent.click(pill);
    expect(await screen.findByText("unsaved changes")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /^Save$/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    const putBody = JSON.parse(calls.find((c) => c.method === "PUT")!.body!);
    expect(putBody.exploits).toEqual({ enabled: false, max_probes: 10 });

    // saved document comes back through applyDoc: pill follows the server value
    expect(await screen.findByText("exploitation disabled")).toBeTruthy();
    expect(screen.queryByText("unsaved changes")).toBeNull();
  });

  it("hides the exploitation card for backends without the section", async () => {
    stubBackend();
    render(<SettingsView />);
    await screen.findByText("Nuclei template scanner");
    expect(screen.queryByText("Exploitation")).toBeNull();
    expect(screen.queryByRole("switch", { name: "Exploitation enabled" })).toBeNull();
  });
});
