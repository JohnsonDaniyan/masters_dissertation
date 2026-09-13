import { notifyMockLab, readEnvFile, restoreBaseline, writeToggle } from "@/lib/labEnv";

export async function GET() {
  try {
    const { toggles } = readEnvFile();
    const ping = await notifyMockLab("/lab/reload", { method: "POST" });
    return Response.json({ toggles, mockLab: ping.notified ? "connected" : "offline" });
  } catch (error) {
    return Response.json(
      { detail: error instanceof Error ? error.message : "Cannot read mock-lab/.env" },
      { status: 500 },
    );
  }
}

export async function PATCH(request: Request) {
  try {
    const body = (await request.json()) as { key?: string; value?: boolean };
    if (!body.key || typeof body.value !== "boolean") {
      return Response.json({ detail: "Expected { key, value }" }, { status: 400 });
    }
    const toggles = writeToggle(body.key, body.value);
    const ping = await notifyMockLab("/lab/reload", { method: "POST" });
    return Response.json({ toggles, mockLab: ping.notified ? "connected" : "offline" });
  } catch (error) {
    return Response.json(
      { detail: error instanceof Error ? error.message : "Cannot update mock-lab/.env" },
      { status: 500 },
    );
  }
}

export async function POST() {
  try {
    const labReset = await notifyMockLab("/lab/config/reset", { method: "POST" });
    const toggles = labReset.notified ? readEnvFile().toggles : restoreBaseline();
    if (!labReset.notified) {
      await notifyMockLab("/lab/reload", { method: "POST" });
    }
    return Response.json({
      toggles,
      mockLab: labReset.notified ? "connected" : "offline",
    });
  } catch (error) {
    return Response.json(
      { detail: error instanceof Error ? error.message : "Cannot restore mock-lab/.env" },
      { status: 500 },
    );
  }
}
