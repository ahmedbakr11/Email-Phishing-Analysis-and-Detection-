// PhishingReport.jsx
import React, { useMemo } from "react";
import { Section, RiskBar } from "../../components/reports/Report.jsx";

function computeRisk(report) {
  const vtDomains = report?.vt_domain_results || {};
  let maliciousCount = 0;
  let suspiciousCount = 0;
  Object.values(vtDomains).forEach((v) => {
    if (!v) return;
    maliciousCount += Number(v.malicious || 0);
    suspiciousCount += Number(v.suspicious || 0);
  });
  const headerIssues = report?.header_issues?.length || 0;
  const contentIssues = report?.content_issues?.length || 0;
  const attachmentIssues = report?.attachment_issues?.length || 0;
  let risk100 = 10 * maliciousCount + 5 * suspiciousCount + 2 * headerIssues + 3 * contentIssues + 20 * attachmentIssues;
  risk100 = Math.min(100, risk100);
  const risk = Math.min(10, Math.round(risk100 / 10));
  return { risk, maliciousCount, suspiciousCount };
}

function severityForIssue(source) {
  if (source === "attachment_issues") return "high";
  if (source === "header_issues" || source === "spoofing_issues") return "medium";
  if (source === "content_issues") return "low";
  if (source === "url_issues") return "low";
  return "low";
}

// Section and RiskBar are imported from shared components

function Badge({ children, color = "var(--brand-700)", bg = "color-mix(in oklab, var(--brand-600) 15%, white)" }) {
  return (
    <span style={{
      display: "inline-block",
      padding: "0.15rem 0.5rem",
      borderRadius: 9999,
      fontSize: 12,
      fontWeight: 600,
      color,
      background: bg,
    }}>{children}</span>
  );
}

function PhishingReport({ report, analyzedAt }) {
  const { risk } = useMemo(() => computeRisk(report), [report]);

  const alerts = useMemo(() => {
    const combine = [];
    const sources = [
      ["url_issues", report?.url_issues || []],
      ["header_issues", report?.header_issues || []],
      ["spoofing_issues", report?.spoofing_issues || []],
      ["content_issues", report?.content_issues || []],
      ["attachment_issues", report?.attachment_issues || []],
    ];
    for (const [src, arr] of sources) {
      for (const item of arr) {
        combine.push({ src, text: item, sev: severityForIssue(src) });
      }
    }
    return combine;
  }, [report]);

  const vtDomain = report?.vt_domain_results || {};
  const vtEmail = report?.vt_email_results || {};

  return (
    <div>
      <Section title="Summary">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px,1fr))", gap: "0.5rem" }}>
          <div><strong>From:</strong> <span>{report.from || ""}</span></div>
          <div><strong>To:</strong> <span>{report.to || ""}</span></div>
          <div><strong>Subject:</strong> <span>{report.subject || ""}</span></div>
        </div>
        <div style={{ marginTop: "0.75rem" }}>
          <RiskBar value={risk} max={10} />
        </div>
        <div style={{ marginTop: 8, fontSize: 12, color: "var(--text-700)" }}>
          <span>Analyzed at: {analyzedAt ? new Date(analyzedAt).toLocaleString() : new Date().toLocaleString()}</span>
        </div>
      </Section>

      <Section title="Alerts">
        {alerts.length === 0 ? (
          <Badge>No issues found</Badge>
        ) : (
          <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "grid", gap: 6 }}>
            {alerts.map((a, idx) => {
              const colors = a.sev === "high"
                ? ["var(--accent-error)", "var(--accent-error-bg)"]
                : a.sev === "medium"
                ? ["var(--accent-warning)", "var(--accent-warning-bg)"]
                : ["var(--brand-700)", "color-mix(in oklab, var(--brand-600) 12%, white)"];
              return (
                <li key={idx} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <Badge color={colors[0]} bg={colors[1]}>{a.sev.toUpperCase()}</Badge>
                  <span>{a.text}</span>
                </li>
              );
            })}
          </ul>
        )}
      </Section>

      <Section title="Auth Checks">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px,1fr))", gap: "0.5rem" }}>
          <div><strong>SPF:</strong> <span>{report.spf || ""}</span></div>
          <div><strong>DKIM:</strong> <span>{report.dkim || ""}</span></div>
          <div><strong>DMARC:</strong> <span>{report.dmarc || ""}</span></div>
        </div>
      </Section>

      <Section title="Domains & Emails">
        <div style={{ marginBottom: 6 }}>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Domains</div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {(report.all_domains || []).map((d) => (
              <Badge key={d}>{d}</Badge>
            ))}
          </div>
        </div>
        <div>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Emails</div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {(report.all_emails || []).map((e) => (
              <Badge key={e}>{e}</Badge>
            ))}
          </div>
        </div>
      </Section>

      <Section title="VirusTotal Domain Results">
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                {['target','malicious','suspicious','undetected','harmless'].map((h) => (
                  <th key={h} style={{ textAlign: 'left', padding: 8, borderBottom: '1px solid var(--border)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {Object.values(vtDomain).length === 0 && (
                <tr><td colSpan={5} style={{ padding: 8, color: 'var(--text-700)' }}>No results</td></tr>
              )}
              {Object.values(vtDomain).map((v) => {
                const mal = Number(v.malicious || 0);
                const rowBg = mal > 0 ? "var(--accent-error-bg)" : undefined;
                return (
                  <tr key={v.domain} style={{ background: rowBg }}>
                    <td style={{ padding: 8 }}>{v.domain}</td>
                    <td style={{ padding: 8 }}>{v.malicious}</td>
                    <td style={{ padding: 8 }}>{v.suspicious}</td>
                    <td style={{ padding: 8 }}>{v.undetected}</td>
                    <td style={{ padding: 8 }}>{v.harmless}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="VirusTotal Email Results">
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                {['email','related_records','error'].map((h) => (
                  <th key={h} style={{ textAlign: 'left', padding: 8, borderBottom: '1px solid var(--border)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {Object.values(vtEmail).length === 0 && (
                <tr><td colSpan={3} style={{ padding: 8, color: 'var(--text-700)' }}>No results</td></tr>
              )}
              {Object.values(vtEmail).map((v) => (
                <tr key={v.email}>
                  <td style={{ padding: 8 }}>{v.email}</td>
                  <td style={{ padding: 8 }}>{v.related_records ?? ''}</td>
                  <td style={{ padding: 8 }}>{v.error ?? ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="Raw JSON">
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 6 }}>
          <button
            type="button"
            onClick={() => navigator.clipboard?.writeText(JSON.stringify(report, null, 2))}
            className="btn btn-outline-primary btn-sm"
          >
            Copy JSON
          </button>
        </div>
        <pre style={{ background: 'var(--text-900)', color: 'var(--surface-1)', padding: '0.75rem', borderRadius: 8, overflowX: 'auto' }}>
{JSON.stringify(report, null, 2)}
        </pre>
      </Section>
    </div>
  );
}

export default PhishingReport;
