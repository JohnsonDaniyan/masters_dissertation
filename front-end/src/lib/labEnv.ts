import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

export const BOOL_TOGGLE_KEYS = [
  "METADATA_ENABLED",
  "METADATA_INCOMPLETE",
  "ISSUER_MISMATCH",
  "ISSUER_MALFORMED",
  "PAR_ENFORCED",
  "REQUEST_URI_REUSABLE",
  "PKCE_ENFORCED",
  "ALLOW_PLAIN_PKCE",
  "JWT_REPLAY_PROTECTION",
  "MTLS_CLIENT_AUTH_ENFORCED",
  "ALLOW_WEAK_CLIENT_AUTH",
  "DPOP_REPLAY_PROTECTION",
  "DPOP_VALIDATION_STRICT",
  "MTLS_BINDING_ENFORCED",
  "INTROSPECTION_AUTH_REQUIRED",
  "RS_TRUSTS_AS_BLINDLY",
  "ISS_PARAM_OMITTED",
  "REDIRECT_URI_LOOSE_MATCH",
  "JARM_SIGNATURE_CHECK",
  "DCR_OPEN_REGISTRATION",
  "DCM_AUTH_REQUIRED",
] as const;

export type ToggleKey = (typeof BOOL_TOGGLE_KEYS)[number];

let baseline: string | null = null;

export function envPath() {
  return process.env.MOCK_LAB_ENV_PATH ?? path.resolve(process.cwd(), "..", "mock-lab", ".env");
}

export function mockLabUrl() {
  return process.env.MOCK_LAB_URL ?? "http://127.0.0.1:8000";
}

export function parseToggles(contents: string): Record<string, boolean> {
  const toggles: Record<string, boolean> = {};
  const allowed = new Set<string>(BOOL_TOGGLE_KEYS);
  for (const raw of contents.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || !line.includes("=")) continue;
    const eq = line.indexOf("=");
    const key = line.slice(0, eq).trim();
    if (!allowed.has(key)) continue;
    const value = line.slice(eq + 1).split("#")[0].trim();
    toggles[key] = value.toLowerCase() === "true";
  }
  return toggles;
}

export function readEnvFile() {
  const filePath = envPath();
  const contents = readFileSync(filePath, "utf8");
  if (baseline === null) baseline = contents;
  return { filePath, contents, toggles: parseToggles(contents) };
}

export function writeToggle(key: string, value: boolean) {
  if (!BOOL_TOGGLE_KEYS.includes(key as ToggleKey)) {
    throw new Error(`Unknown toggle ${key}`);
  }
  const { filePath, contents } = readEnvFile();
  const rendered = value ? "true" : "false";
  const hadTrailingNewline = contents.endsWith("\n");
  const lines = contents.replace(/\n$/, "").split("\n");
  let found = false;
  const next = lines.map((line) => {
    if (line.trimStart().startsWith("#") || !line.includes("=")) return line;
    const eq = line.indexOf("=");
    if (line.slice(0, eq).trim() !== key) return line;
    found = true;
    const rest = line.slice(eq + 1);
    const hash = rest.indexOf("#");
    if (hash >= 0) {
      const comment = rest.slice(hash);
      const spacing = comment.startsWith(" ") || comment.startsWith("\t") ? "" : " ";
      return `${line.slice(0, eq + 1)}${rendered}${spacing}${comment}`;
    }
    return `${line.slice(0, eq + 1)}${rendered}`;
  });
  if (!found) next.push(`${key}=${rendered}`);
  writeFileSync(filePath, next.join("\n") + (hadTrailingNewline ? "\n" : ""), "utf8");
  return parseToggles(readFileSync(filePath, "utf8"));
}

export function restoreBaseline() {
  if (baseline === null) {
    return readEnvFile().toggles;
  }
  writeFileSync(envPath(), baseline, "utf8");
  return parseToggles(baseline);
}

export async function notifyMockLab(pathSuffix: string, init?: RequestInit) {
  const url = `${mockLabUrl()}${pathSuffix}`;
  try {
    const response = await fetch(url, {
      ...init,
      cache: "no-store",
      signal: AbortSignal.timeout(2500),
    });
    if (!response.ok) return { notified: false as const, status: response.status };
    return { notified: true as const, status: response.status };
  } catch {
    return { notified: false as const, status: 0 };
  }
}
