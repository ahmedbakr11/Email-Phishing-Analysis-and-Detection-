import React from "react";
import { VERDICT_LABELS } from "../utils/constants";
import { extractDomain, toneForVerdict } from "../utils/phishingUtils";

const RiskBanner = ({ report }) => {
  const score = report?.score ?? report?.raw_report?.detection?.score?.score ?? 0;
  const verdict = report?.status || report?.raw_report?.detection?.score?.verdict || "review";
  const tone = toneForVerdict(verdict);
  const headers = report?.raw_report?.parsing?.headers || {};
  const auth = report?.raw_report?.parsing?.auth || {};
  const domains = [headers.from_domain, headers.return_domain, headers.reply_domain].filter(Boolean);
  const uniqueDomains = Array.from(new Set(domains));
  const suspiciousDomains = new Set(
    (report?.findings?.suspicious_links || [])
      .map((l) => extractDomain(l.link || l.absolute || l.href))
      .filter(Boolean)
  );
  const riskyDomains = new Set(
    (report?.findings?.extra_flags?.typosquatting || [])
      .map((item) => item.domain)
      .filter(Boolean)
  );
  const domainBadges = uniqueDomains.map((domain) => {
    if (riskyDomains.has(domain)) return { domain, tone: "danger", label: "malicious" };
    if (suspiciousDomains.has(domain)) return { domain, tone: "warning", label: "suspicious" };
    return { domain, tone: "soft", label: "safe" };
  });

  const interpretAuth = (value) => {
    if (!value) return { label: "Not present", tone: "muted" };
    const lowered = String(value).toLowerCase();
    if (lowered.includes("pass")) return { label: "Pass", tone: "safe" };
    if (lowered.includes("fail") || lowered.includes("softfail")) return { label: "Fail", tone: "danger" };
    if (lowered.includes("neutral") || lowered.includes("none")) return { label: "Neutral", tone: "warning" };
    return { label: "Review", tone: "info" };
  };

  const authPills = [
    { key: "SPF", raw: auth.spf },
    { key: "DKIM", raw: auth.dkim },
    { key: "DMARC", raw: auth.dmarc },
  ].map((item) => {
    const state = interpretAuth(item.raw);
    return { key: item.key, label: state.label, tone: state.tone };
  });

  return (
    <div className={`phish-risk-banner tone-${tone}`}>
      <div>
        <p className="eyebrow">Risk summary</p>
        <div className="risk-score">
          <div className="risk-score__value">{score}</div>
          <div className="risk-score__meta">
            <div className="risk-score__label">{VERDICT_LABELS[verdict?.toLowerCase()] || "Needs Review"}</div>
            <div className="risk-score__desc">
              {tone === "danger"
                ? "High-risk indicators found - proceed with caution."
                : tone === "warning"
                ? "Some suspicious patterns require review."
                : "No major red flags detected from automated checks."}
            </div>
          </div>
        </div>
        <div className="risk-domains">
          <span className="risk-domains__label">Domains</span>
          <div className="risk-domain-badges">
            {domainBadges.length === 0 && <span className="badge badge-muted">None detected</span>}
            {domainBadges.map((entry) => (
              <span key={entry.domain} className={`badge badge-${entry.tone}`}>
                {entry.domain} - {entry.label}
              </span>
            ))}
          </div>
        </div>
      </div>
      <div className="risk-auth">
        {authPills.map((pill) => (
          <div key={pill.key} className={`auth-pill tone-${pill.tone}`}>
            <span className="auth-pill__label">{pill.key}</span>
            <span className="auth-pill__value">{pill.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default RiskBanner;
