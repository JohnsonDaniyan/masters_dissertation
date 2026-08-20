const SCANNER_API_URL =
  process.env.SCANNER_API_URL ?? process.env.NEXT_PUBLIC_SCANNER_API_URL ?? "http://127.0.0.1:8080";

async function proxy(path: string, init?: RequestInit): Promise<Response> {
  let upstream: Response;
  try {
    upstream = await fetch(`${SCANNER_API_URL}${path}`, {
      ...init,
      cache: "no-store",
    });
  } catch {
    return Response.json(
      {
        detail:
          "Cannot reach the FAPI scanner API. Start it with: uvicorn scanner.api:app --app-dir fapi-scanner --port 8080",
      },
      { status: 502 },
    );
  }

  const text = await upstream.text();
  return new Response(text, {
    status: upstream.status,
    headers: {
      "content-type": upstream.headers.get("content-type") ?? "application/json",
    },
  });
}

export async function GET(request: Request) {
  const target = new URL(request.url).searchParams.get("target") ?? "";
  return proxy(`/api/v1/scan?target=${encodeURIComponent(target)}`);
}

export async function POST(request: Request) {
  const body = await request.text();
  return proxy("/api/v1/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
}
