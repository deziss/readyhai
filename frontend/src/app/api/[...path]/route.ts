import { NextRequest, NextResponse } from "next/server";

export async function proxy(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const backendUrl = process.env.READYHAI_BACKEND_URL || "http://127.0.0.1:8080";
  const { path } = await params;
  const targetUrl = new URL(`/api/${path.join("/")}`, backendUrl);
  targetUrl.search = request.nextUrl.search;

  const reqHeaders = new Headers(request.headers);
  reqHeaders.delete("host");
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

    const res = await fetch(targetUrl.toString(), {
      method: request.method,
      headers: reqHeaders,
      body,
      // @ts-expect-error duplex required for Node fetch with body
      duplex: isBodyAllowed && body ? "half" : undefined,
    });

    const resHeaders = new Headers(res.headers);
    resHeaders.delete("content-encoding");

    return new NextResponse(res.body, {
      status: res.status,
      statusText: res.statusText,
      headers: resHeaders,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
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
