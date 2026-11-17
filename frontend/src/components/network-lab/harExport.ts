import type { RegressReport } from "@/types/network";

export function exportHar(regressReport: RegressReport, method: string) {
  const harData = {
    log: {
      version: "1.2",
      creator: { name: "ReadyHai Network Lab", version: "0.1.0" },
      pages: [
        {
          startedDateTime: regressReport.iterations[0]?.timestamp || new Date().toISOString(),
          id: "page_readyhai_regression",
          title: `ReadyHai Regression Audit - ${regressReport.target}`,
          pageTimings: {
            onContentLoad: Number(regressReport.p50_latency_ms),
            onLoad: Number(regressReport.p90_latency_ms),
          },
        },
      ],
      entries: regressReport.iterations.map((it) => {
        const wait = Number(it.ttfb_ms);
        const total = Number(it.duration_ms);
        const receive = Math.max(0, total - wait);
        return {
          startedDateTime: it.timestamp,
          time: total,
          request: {
            method: method || "GET",
            url: regressReport.target,
            httpVersion: "HTTP/1.1",
            cookies: [],
            headers: Object.entries(it.response_headers || {}).map(([k, v]) => ({ name: k, value: v })),
            queryString: [],
            headersSize: -1,
            bodySize: 0,
          },
          response: {
            status: it.status_code,
            statusText: it.success ? "OK" : "Error",
            httpVersion: "HTTP/1.1",
            cookies: [],
            headers: Object.entries(it.response_headers || {}).map(([k, v]) => ({ name: k, value: v })),
            content: {
              size: (it.response_body_snippet || "").length,
              mimeType: it.response_headers?.["content-type"] || "",
              text: it.response_body_snippet || "",
            },
            redirectURL: "",
            headersSize: -1,
            bodySize: (it.response_body_snippet || "").length,
          },
          cache: {},
          timings: {
            blocked: 0,
            dns: Number(it.dns_lookup_ms),
            connect: Number(it.tcp_connect_ms),
            ssl: 0,
            send: 1,
            wait: wait,
            receive: receive,
          },
          connection: it.session_id,
        };
      }),
    },
  };

  const blob = new Blob([JSON.stringify(harData, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `readyhai-trace-${Date.now()}.har`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
