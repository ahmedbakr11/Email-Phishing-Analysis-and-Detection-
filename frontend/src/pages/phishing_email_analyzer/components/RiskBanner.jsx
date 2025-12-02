import React from "react";
import { VERDICT_LABELS } from "../utils/constants";
import { toneForVerdict } from "../utils/phishingUtils";

const RiskBanner = ({ report }) => {
  const score = report?.score ?? report?.raw_report?.detection?.score?.score ?? 0;
  const verdict = report?.status || report?.raw_report?.detection?.score?.verdict || "review";
  const tone = toneForVerdict(verdict);
  const auth = report?.raw_report?.parsing?.auth || {};

  const interpretAuth = (value) => {
    if (!value) return { label: "Not present", tone: "muted" };
    const lowered = String(value).toLowerCase();
    if (lowered.includes("pass")) return { label: "Pass", tone: "safe" };
    if (lowered.includes("fail") || lowered.includes("softfail")) return { label: "Fail", tone: "danger" };
    if (lowered.includes("neutral") || lowered.includes("none")) return { label: "Neutral", tone: "warning" };
    return { label: "Review", tone: "info" };
  };

  const headerForgery = report?.findings?.extra_flags?.header_forgery
    || report?.raw_report?.detection?.extra_flags?.header_forgery
    || [];
  const forgeryByMethod = headerForgery.reduce((acc, item) => {
    const method = (item?.method || "").toUpperCase();
    if (!method) return acc;
    acc[method] = item.result || "failure";
    return acc;
  }, {});
  const hasForgeryData = headerForgery.length > 0;

  const authPills = [
    { key: "SPF", raw: auth.spf },
    { key: "DKIM", raw: auth.dkim },
    { key: "DMARC", raw: auth.dmarc },
  ].map((item) => {
    const rawVal = item.raw;
    if (hasForgeryData) {
      if (forgeryByMethod[item.key] === "failure") return { key: item.key, label: "Failure", tone: "danger" };
      if (!rawVal) return { key: item.key, label: "Not present", tone: "muted" };
      return { key: item.key, label: "Success", tone: "safe" };
    }
    const state = interpretAuth(rawVal);
    return { key: item.key, label: state.label, tone: state.tone };
  });

  return (
    <div className={`phish-risk-banner tone-${tone}`}>
      <div>
        <p className="eyebrow">Risk Summary</p>
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
