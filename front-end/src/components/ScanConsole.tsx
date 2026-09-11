"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import { fetchChecks, runScan } from "@/lib/api";
import type { CatalogCheck, CheckStatus, ScanReport, TestResult } from "@/lib/types";

const DEFAULT_TARGET = "http://127.0.0.1:8000";

function statusLabel(status: CheckStatus) {
  if (status === "pass") return "Pass";
  if (status === "fail") return "Fail";
  return "Error";
}

function Finding({ result, index }: { result: TestResult; index: number }) {
  return (
    <article className={`finding ${result.status}`} id={result.check_id.toLowerCase()}>
      <h3>
        <span className="finding-num">3.{index + 1}</span>
        {result.check_id}. {result.description}
        <span className={`verdict-inline ${result.status}`}>{statusLabel(result.status)}</span>
      </h3>
      <p>{result.detail}</p>
      <table className="finding-meta">
        <tbody>
          <tr>
            <th scope="row">Endpoint</th>
            <td>
              <code>{result.endpoint}</code>
            </td>
          </tr>
          <tr>
            <th scope="row">Severity</th>
            <td>{result.severity}</td>
          </tr>
          <tr>
            <th scope="row">Recommended remedy</th>
            <td>{result.remedy}</td>
          </tr>
          {result.reference ? (
            <tr>
              <th scope="row">Literature</th>
              <td>{result.reference}</td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </article>
  );
}

export default function ScanConsole() {
  const [target, setTarget] = useState(DEFAULT_TARGET);
  const [checks, setChecks] = useState<CatalogCheck[]>([]);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchChecks()
      .then(setChecks)
      .catch((err: Error) => setError(err.message));
  }, []);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const nextReport = await runScan(target);
      setReport(nextReport);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  const verdict = useMemo(() => {
    if (!report) return null;
    if (report.summary.fail > 0) {
      return "The specimen fails one or more FAPI 2.0 discovery requirements.";
    }
    if (report.summary.error > 0) {
      return "The instrument could not complete every check against this specimen.";
    }
    return "The specimen satisfies the FAPI 2.0 checks in the present catalogue.";
  }, [report]);

  return (
    <div className="page">
      <header className="running-head">
        <span>FAPI Lens</span>
        <span>Working paper · visual instrument</span>
        <span>Discovery and PAR conformance</span>
      </header>

      <article className="paper">
        
        <h1>Automated Adversarial Testing of FAPI 2.0 Security Profile Conformance in Financial API Implementations</h1>
        <p className="subtitle">
          A visual instrument for presenting FAPI 2.0 Security Profile discovery
          and pushed-authorisation findings against a live authorisation server
        </p>
        <p className="byline">
          Master’s project interface · black-box adversarial testing of
          authorisation-server metadata
        </p>

        <section className="abstract">
          <h2>Abstract</h2>
          <p>
            This page is not a dashboard. It is a reading of the scanner’s
            structured results in the register of a short research note.
            Discovery-time checks—metadata reachability, issuer identifier
            format, and the advertisement of pushed authorisation requests—are
            followed by live probes of PAR, PKCE, client authentication, DPoP,
            resource-server binding, authorization-response integrity, and
            dynamic client registration. Those probes map onto preconditions
            identified by Hosseyni, Küsters and Würtele (2025), including
            attacker token injection, DPoP proof replay, and the Cuckoo’s Token
            attack.
          </p>
        </section>

        <section>
          <h2>
            <span>1.</span> Method
          </h2>
          <p>
            The instrument first fetches the RFC 8414 well-known document, then
            exercises the advertised PAR and authorization endpoints. Each row
            in the catalogue is an independent proposition. Failures are treated
            as evidence of non-conformance; transport errors are reported
            separately so that an unreachable host is not conflated with a
            malformed document. A PAR bypass (authorize without request_uri) or
            a reusable request_uri is reported as a finding, not as a lab
            convenience.
          </p>
          <table className="catalogue">
            <caption>Table 1. Check catalogue</caption>
            <thead>
              <tr>
                <th>ID</th>
                <th>Proposition</th>
                <th>Principal reference</th>
              </tr>
            </thead>
            <tbody>
              {checks.map((check) => (
                <tr key={check.check_id}>
                  <td>
                    <code>{check.check_id}</code>
                  </td>
                  <td>
                    <strong>{check.title}.</strong> {check.description}
                  </td>
                  <td>{check.reference}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        <section>
          <h2>
            <span>2.</span> Specimen
          </h2>
          <p>
            Supply the base URL of the authorisation server under test. The
            default addresses the project’s mock Open Banking lab. The scanner
            API remains the source of truth; this interface only renders its
            report.
          </p>
          <form className="specimen" onSubmit={onSubmit}>
            <label htmlFor="target">Base URL of the authorisation server</label>
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
                {loading ? "Evaluating…" : "Evaluate specimen"}
              </button>
            </div>
          </form>
          {error ? <p className="erratum">{error}</p> : null}
        </section>

        <section>
          <h2>
            <span>3.</span> Findings
          </h2>
          {!report ? (
            <p className="placeholder">
              No specimen has been evaluated in this session. Results will be
              set out below as numbered findings, each with a verdict, the
              observed detail, and a recommended remedy.
            </p>
          ) : (
            <>
              <p className="lead-finding">{verdict}</p>
              <table className="summary-table">
                <caption>Table 2. Summary of the present run</caption>
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>Pass</th>
                    <th>Fail</th>
                    <th>Error</th>
                    <th>Duration</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>
                      <code>{report.target}</code>
                    </td>
                    <td>{report.summary.pass}</td>
                    <td>{report.summary.fail}</td>
                    <td>{report.summary.error}</td>
                    <td>{report.duration_ms}&nbsp;ms</td>
                  </tr>
                </tbody>
              </table>
              <p className="smallprint">
                Metadata document retrieved from <code>{report.metadata_url}</code>.
                Evaluation window {new Date(report.started_at).toUTCString()}–
                {new Date(report.finished_at).toUTCString()}.
              </p>
              {report.results.map((result, index) => (
                <Finding key={result.check_id} result={result} index={index} />
              ))}
            </>
          )}
        </section>

        <footer className="notes">
          <h2>Notes</h2>
          <ol>
            <li>
              Hosseyni, P., Küsters, R. and Würtele, T. (2025). Formal security
              analysis of the OpenID Financial-grade API 2.0. The checks on this
              page address discovery preconditions of the modelled attacks, not
              the attacks themselves.
            </li>
            <li>
              IETF RFC 8414 (OAuth 2.0 Authorization Server Metadata); RFC 9126
              (Pushed Authorization Requests); RFC 9207 (Authorization Server
              Issuer Identification).
            </li>
            <li>
              OpenID Foundation, FAPI 2.0 Security Profile. Conformance here is
              limited to the advertised discovery surface and the PAR
              front-channel probes in the catalogue, and should not be read as a
              certification result.
            </li>
          </ol>
        </footer>
      </article>
    </div>
  );
}
