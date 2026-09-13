"use client";

import { useEffect, useState } from "react";
import { fetchLabConfig, resetLabConfig, setLabToggle } from "@/lib/api";

const GROUPS: { title: string; keys: string[] }[] = [
  {
    title: "Discovery",
    keys: ["METADATA_ENABLED", "METADATA_INCOMPLETE", "ISSUER_MISMATCH", "ISSUER_MALFORMED"],
  },
  {
    title: "PAR",
    keys: ["PAR_ENFORCED", "REQUEST_URI_REUSABLE"],
  },
  {
    title: "PKCE",
    keys: ["PKCE_ENFORCED", "ALLOW_PLAIN_PKCE"],
  },
  {
    title: "Client auth",
    keys: ["JWT_REPLAY_PROTECTION", "MTLS_CLIENT_AUTH_ENFORCED", "ALLOW_WEAK_CLIENT_AUTH"],
  },
  {
    title: "Sender constraining",
    keys: ["DPOP_REPLAY_PROTECTION", "DPOP_VALIDATION_STRICT", "MTLS_BINDING_ENFORCED"],
  },
  {
    title: "Tokens",
    keys: ["INTROSPECTION_AUTH_REQUIRED", "RS_TRUSTS_AS_BLINDLY"],
  },
  {
    title: "Responses",
    keys: ["ISS_PARAM_OMITTED", "REDIRECT_URI_LOOSE_MATCH", "JARM_SIGNATURE_CHECK"],
  },
  {
    title: "Registration",
    keys: ["DCR_OPEN_REGISTRATION", "DCM_AUTH_REQUIRED"],
  },
];

function prettyKey(key: string) {
  return key
    .toLowerCase()
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export default function MockLabCard() {
  const [toggles, setToggles] = useState<Record<string, boolean>>({});
  const [mockLab, setMockLab] = useState<"connected" | "offline" | "loading">("loading");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);

  async function apply(next: Promise<{ toggles: Record<string, boolean>; mockLab: "connected" | "offline" }>) {
    const result = await next;
    setToggles(result.toggles);
    setMockLab(result.mockLab);
  }

  useEffect(() => {
    let cancelled = false;
    fetchLabConfig()
      .then((result) => {
        if (cancelled) return;
        setToggles(result.toggles);
        setMockLab(result.mockLab);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Could not load lab config");
        setMockLab("offline");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function onToggle(key: string, value: boolean) {
    const previous = toggles[key];
    setToggles((current) => ({ ...current, [key]: value }));
    setPending(key);
    setError(null);
    try {
      await apply(setLabToggle(key, value));
    } catch (err) {
      setToggles((current) => ({ ...current, [key]: previous }));
      setError(err instanceof Error ? err.message : "Could not update toggle");
    } finally {
      setPending(null);
    }
  }

  async function onReset() {
    setPending("reset");
    setError(null);
    try {
      await apply(resetLabConfig());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not reset lab config");
    } finally {
      setPending(null);
    }
  }

  return (
    <aside className="lab-card">
      <header className="lab-card-head">
        <h2>Mock Lab</h2>
        <span className={`lab-status ${mockLab}`}>{mockLab}</span>
      </header>
      <p className="lab-card-lead">
        Toggles write <code>mock-lab/.env</code> and the mock AS reloads them without a restart. Reset restores the file from when this page first loaded.
      </p>
      {error ? <p className="lab-card-error">{error}</p> : null}
      {GROUPS.map((group) => {
        const keys = group.keys.filter((key) => key in toggles);
        if (keys.length === 0) return null;
        return (
          <section key={group.title} className="lab-group">
            <h3>{group.title}</h3>
            {keys.map((key) => (
              <label key={key} className="lab-toggle">
                <span>{prettyKey(key)}</span>
                <input
                  type="checkbox"
                  role="switch"
                  checked={Boolean(toggles[key])}
                  disabled={pending === key}
                  onChange={(event) => void onToggle(key, event.target.checked)}
                />
              </label>
            ))}
          </section>
        );
      })}
      <button type="button" className="lab-reset" onClick={() => void onReset()} disabled={pending !== null}>
        Reset
      </button>
    </aside>
  );
}
