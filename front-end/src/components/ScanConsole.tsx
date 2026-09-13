"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import MockLabCard from "@/components/MockLabCard";
import { runScan } from "@/lib/api";
import type { CheckStatus, ScanReport, TestResult } from "@/lib/types";

const DEFAULT_TARGET = "http://127.0.0.1:8000";

const DISCOVERY_PATHS = [
  "/.well-known/oauth-authorization-server",
  "/.well-known/openid-configuration",
  "issuer",
  "pushed_authorization_request_endpoint",
  "authorization_endpoint",
  "token_endpoint",
  "jwks_uri",
] as const;

function statusLabel(status: CheckStatus) {
  if (status === "pass") return "Pass";
  if (status === "fail") return "Fail";
  return "Error";
}

function originFromTarget(target: string) {
  try {
    return new URL(target).origin;
  } catch {
    return target.replace(/\/$/, "");
  }
}

function discoveryStep(target: string, index: number) {
  const origin = originFromTarget(target);
  const path = DISCOVERY_PATHS[Math.min(index, DISCOVERY_PATHS.length - 1)];
  if (path.startsWith("/")) {
    return `Discovering ${origin}${path}`;
  }
  return `Reading ${path} from metadata`;
}

function wait(ms: number) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function Finding({ result, index }: { result: TestResult; index: number }) {
  return (
    <article className={`finding ${result.status}`} id={result.check_id.toLowerCase()}>
      <h3>
        <span className="finding-num">{index + 1}</span>
        {result.check_id}
        <span className={`verdict-inline ${result.status}`}>{statusLabel(result.status)}</span>
      </h3>
      <p>{result.detail}</p>
      <p className="finding-endpoint">
        <code>{result.endpoint}</code>
      </p>
    </article>
  );
}

export default function ScanConsole() {
  const [target, setTarget] = useState(DEFAULT_TARGET);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [stepIndex, setStepIndex] = useState(0);

  useEffect(() => {
    if (!loading) return;
    setStepIndex(0);
    const timer = window.setInterval(() => {
      setStepIndex((current) => Math.min(current + 1, DISCOVERY_PATHS.length - 1));
    }, 420);
    return () => window.clearInterval(timer);
  }, [loading]);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    const started = Date.now();
    try {
      const nextReport = await runScan(target);
      const remaining = DISCOVERY_PATHS.length * 420 - (Date.now() - started);
      if (remaining > 0) await wait(remaining);
      setReport(nextReport);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  const verdict = useMemo(() => {
    if (!report) return null;
    if (report.summary.fail > 0) return "Non-conformant";
    if (report.summary.error > 0) return "Incomplete";
    return "Conformant";
  }, [report]);

  return (
    <div className="page">
      <header className="running-head">
        <span>FAPI Lens</span>
        <span>FAPI 2.0</span>
      </header>

      <div className="workspace">
        <MockLabCard />
        <article className="paper">
          <h1>Authorisation-server scan</h1>

        <form className="specimen" onSubmit={onSubmit}>
          <label htmlFor="target" className="sr-only">
            Base URL
          </label>
          <div className="specimen-row">
            <input
              id="target"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="http://127.0.0.1:8000"
              autoComplete="off"
              spellCheck={false}
            />
            <button type="submit" disabled={loading || !target.trim()}>
              {loading ? "Analysing…" : "Analyse"}
            </button>
          </div>
          {loading ? (
            <p className="discovery-progress" aria-live="polite">
              <span className="discovery-pulse" aria-hidden="true" />
              URL discovery · {discoveryStep(target, stepIndex)}
            </p>
          ) : null}
        </form>
        {error ? <p className="erratum">{error}</p> : null}

        {report ? (
          <section>
            <h2>Findings</h2>
            <p className="lead-finding">
              {verdict}
              <span className="summary-inline">
                {report.summary.pass} pass · {report.summary.fail} fail · {report.summary.error} error ·{" "}
                {report.duration_ms} ms
              </span>
            </p>
            {report.results.map((result, index) => (
              <Finding key={result.check_id} result={result} index={index} />
            ))}
          </section>
        ) : null}
      </article>
      </div>
    </div>
  );
}
