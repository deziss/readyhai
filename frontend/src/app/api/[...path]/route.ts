import { NextRequest, NextResponse } from "next/server";
import { Agent, fetch as undiciFetch } from "undici";

// Agent runs are synchronous on the backend and can take far longer than Node fetch's default
// 300 s headers timeout (a deep run is often 5-10 min), which surfaced as "fetch failed" / 502
// while the run itself completed. Wait as long as the backend's own run limit
// (READYHAI_RUN_TIMEOUT_SECS, default 3600) plus a margin.
const runTimeoutMs =
  (Number(process.env.READYHAI_RUN_TIMEOUT_SECS) > 0
    ? Number(process.env.READYHAI_RUN_TIMEOUT_SECS)
    : 3600) *
    1000 +
  120_000;
const backendAgent = new Agent({
  headersTimeout: runTimeoutMs,
  bodyTimeout: runTimeoutMs,
  keepAliveTimeout: 60_000,
  keepAliveMaxTimeout: 60_000,
});

export async function proxy(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const backendUrl = process.env.READYHAI_BACKEND_URL || "http://127.0.0.1:8080";
  const { path } = await params;
  const targetUrl = new URL(`/api/${path.join("/")}`, backendUrl);
  targetUrl.search = request.nextUrl.search;

  const reqHeaders = new Headers(request.headers);
  // Strip hop-by-hop and client transport headers to avoid undici socket conflicts
  reqHeaders.delete("host");
  reqHeaders.delete("connection");
  reqHeaders.delete("keep-alive");
  reqHeaders.delete("transfer-encoding");
  reqHeaders.delete("content-length"); // Let undici accurately set Content-Length from the body buffer

  // Server-side auth: when the UI container has READYHAI_TOKEN, attach it here so the
  // token never has to be pasted into (or stored by) the browser. A token the user
  // set in Settings still takes precedence.
  const serverToken = process.env.READYHAI_TOKEN?.trim();
  if (serverToken && !reqHeaders.has("authorization")) {
    reqHeaders.set("authorization", `Bearer ${serverToken}`);
  }

  try {
    const isBodyAllowed = !["GET", "HEAD"].includes(request.method);
    const body = isBodyAllowed ? await request.arrayBuffer() : undefined;

    const res = await undiciFetch(targetUrl.toString(), {
      method: request.method,
      headers: reqHeaders,
      body: body ? Buffer.from(body) : undefined,
      dispatcher: backendAgent,
    });

    const resHeaders = new Headers();
    res.headers.forEach((value, key) => {
      const lower = key.toLowerCase();
      // Drop hop-by-hop headers, content-encoding, and content-length.
      // Next.js will set Content-Length automatically for the returned buffer,
      // avoiding ERR_CONTENT_LENGTH_MISMATCH or chunked encoding conflicts in Chrome.
      if (
        lower !== "content-encoding" &&
        lower !== "content-length" &&
        lower !== "transfer-encoding" &&
        lower !== "connection" &&
        lower !== "keep-alive"
      ) {
        resHeaders.append(key, value);
      }
    });

    const resBuffer = await res.arrayBuffer();

    return new NextResponse(resBuffer, {
      status: res.status,
      statusText: res.statusText,
      headers: resHeaders,
    });
  } catch (error: unknown) {
    const cause =
      error instanceof Error && error.cause instanceof Error ? ` (${error.cause.message})` : "";
    const message = (error instanceof Error ? error.message : String(error)) + cause;
    return NextResponse.json(
      { error: `Backend proxy connection failed: ${message}` },
      { status: 502 }
    );
  }
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
export const HEAD = proxy;
export const OPTIONS = proxy;
