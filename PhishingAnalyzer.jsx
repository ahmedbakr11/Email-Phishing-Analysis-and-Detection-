import React, { useEffect, useMemo, useRef, useState } from "react";
import Header from "../components/header.jsx";
import api from "../api/axios";
import { addHistoryEntry } from "../utils/history.js";
import "../styles/phishing-email-analyzer.css";

const ICONS = {
  danger: "!",
  safe: "OK",
  info: "i",
  attachment: "ATT",
  link: "LINK",
  shield: "SHD",
  spark: "*",
  code: "</>",
  compare: "<>",
};

const UploadIcon = () => (
  <svg className="icon icon-upload" viewBox="0 0 64 64" role="img" aria-hidden="true">
    <defs>
      <linearGradient id="uploadGradient" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stopColor="#5eead4" />
        <stop offset="100%" stopColor="#60a5fa" />
      </linearGradient>
    </defs>
    <rect x="8" y="24" width="48" height="28" rx="10" fill="url(#uploadGradient)" opacity="0.18" />
    <path
      d="M32 38V14m0 0-9.5 9.5M32 14l9.5 9.5"
      stroke="url(#uploadGradient)"
      strokeWidth="4"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <rect x="18" y="34" width="28" height="16" rx="6" fill="url(#uploadGradient)" opacity="0.28" />
  </svg>
);

const SparkIcon = () => (
  <svg className="icon icon-spark" viewBox="0 0 64 64" role="img" aria-hidden="true">
    <path
      d="M32 6 36 20l14-2-10 10 10 10-14-2-4 14-4-14-14 2 10-10-10-10 14 2Z"
      fill="none"
      stroke="currentColor"
      strokeWidth="3"
      strokeLinejoin="round"
      strokeLinecap="round"
    />
  </svg>
);

const VERDICT_LABELS = {
  low: "Low Risk",
  clean: "Low Risk",
  safe: "Low Risk",
  ok: "Low Risk",
  review: "Needs Review",
  suspicious: "Suspicious",
  danger: "High Risk",
};

const toneForVerdict = (verdict) => {
  const key = (verdict || "").toLowerCase();
  if (["danger", "suspicious"].includes(key)) return "danger";
  if (["review", "warning"].includes(key)) return "warning";
  return "safe";
};

const formatBytes = (bytes) => {
  if (!bytes && bytes !== 0) return "-";
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / k ** i).toFixed(1)} ${sizes[i]}`;
};

const extractDomain = (link) => {
  if (!link) return "";
  try {
    const url = new URL(link.startsWith("http") ? link : `https://${link}`);
    return url.hostname;
  } catch (_) {
    const parts = link.split("/")[0];
    return parts;
  }
};

const StatusBadge = ({ status }) => {
  const normalized = (status || "").toLowerCase();
  const variant = toneForVerdict(normalized);
  const label = VERDICT_LABELS[normalized] || status || "Unknown";
  return (
    <span className={`status-pill status-pill--${variant}`}>
      <span className="status-pill__dot" aria-hidden="true" />
      <span className="status-pill__text">{label}</span>
    </span>
  );
};

const CollapsiblePane = ({ title, icon = ICONS.info, tone = "info", hint, children, defaultOpen = false }) => {
  const [open, setOpen] = useState(defaultOpen);
  const contentRef = useRef(null);
  const [height, setHeight] = useState(0);

  useEffect(() => {
    const nextHeight = open && contentRef.current ? contentRef.current.scrollHeight : 0;
    setHeight(nextHeight);
  }, [open, children]);

  return (
    <div className={`phish-collapsible ${open ? "is-open" : ""}`}>
      <button
        type="button"
        className="phish-collapsible__trigger"
        onClick={() => setOpen((prev) => !prev)}
        title={hint}
      >
        <span className="phish-collapsible__title-wrap">
          <span className={`phish-collapsible__icon tone-${tone}`}>{icon}</span>
          <span className="phish-collapsible__title">{title}</span>
        </span>
        <span className="phish-collapsible__hint">{open ? "Hide" : "Show"}</span>
      </button>
      <div
        className="phish-collapsible__body"
        style={{ maxHeight: open ? `${height}px` : "0px" }}
        aria-hidden={!open}
      >
        <div ref={contentRef} className="phish-collapsible__inner">
          {children}
        </div>
      </div>
    </div>
  );
};

const Loader = ({ label = "Analyzing email..." }) => (
  <div className="phish-loader" aria-live="polite">
    <span className="phish-loader__spinner" aria-hidden="true" />
    <span className="phish-loader__dot" aria-hidden="true" />
    <span>{label}</span>
  </div>
);
const UploadCard = ({ selectedFile, onSelectFile, onUpload, isLoading, error, onReset }) => {
  const [isDragging, setIsDragging] = useState(false);
  const inputRef = useRef(null);

  const onChange = (event) => {
    const file = event.target.files?.[0];
    if (file && !file.name.toLowerCase().endsWith(".eml")) {
      onSelectFile(null, "Only .eml files are supported.");
      return;
    }
    onSelectFile(file || null, null);
    event.target.value = "";
  };

  const onDrop = (event) => {
    event.preventDefault();
    setIsDragging(false);
    const [file] = event.dataTransfer?.files || [];
    if (file && !file.name.toLowerCase().endsWith(".eml")) {
      onSelectFile(null, "Only .eml files are supported.");
      return;
    }
    onSelectFile(file || null, null);
  };

  const onDrag = (event) => {
    event.preventDefault();
    setIsDragging(event.type === "dragover");
  };

  const handleUpload = () => onUpload?.();

  return (
    <section className="phish-card phish-card--input fade-in">
      <div className="phish-card__header phish-card__header--hero">
        <div className="phish-hero">
          <p className="eyebrow">Premium phishing defense</p>
          <div className="hero-title-row">
            <h1 className="tool-page__title">Phishing Email Analyzer</h1>
            <span className="status-chip status-chip--live">
              <span className="status-chip__dot" aria-hidden="true" />
              Live monitor
            </span>
          </div>
          <p className="tool-page__description phish-lede">
            Upload or drag-and-drop a .eml file to inspect headers, links, and attachments with a calm, guided triage workflow.
          </p>
          <div className="hero-inline">
            <span className="status-chip status-chip--success">
              <span className="status-chip__dot" aria-hidden="true" />
              Real-time spoof checks
            </span>
            <span className="status-chip status-chip--neutral">.eml only</span>
            <span className="status-chip status-chip--soft">No third-party sharing</span>
          </div>
        </div>
        <div className="phish-hero-note">
          <div className="hero-note__icon">
            <SparkIcon />
          </div>
          <div className="hero-note__copy">
            <p className="hero-note__title">Trusted signals</p>
            <p className="hero-note__text">
              Real-time checks for spoofed headers, malicious attachments, redirect tricks, and typosquatting domains.
            </p>
          </div>
        </div>
      </div>

      <div className="phish-upload-panel">
        <div
          className={`phish-dropzone ${isDragging ? "is-dragging" : ""}`}
          onDragOver={onDrag}
          onDragLeave={onDrag}
          onDrop={onDrop}
          role="button"
          tabIndex={0}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              inputRef.current?.click();
            }
          }}
          title="Drop your .eml file here or click to browse"
          onClick={() => inputRef.current?.click()}
        >
          <div className="drop-visual">
            <span className="drop-glow" aria-hidden="true" />
            <div className="drop-icon">
              <UploadIcon />
            </div>
          </div>
          <div className="drop-copy">
            <p className="drop-title">Drop or upload your email</p>
            <p className="drop-subtitle">True drag-and-drop with hover feedback. Your file stays on this workspace.</p>
            <div className="drop-pill-row">
              <span className="chip chip-soft">Drag & drop</span>
              <span className="chip chip-muted">Max 25 MB</span>
              <span className="chip chip-muted">Message/RFC822</span>
            </div>
          </div>
          <div className="drop-cta">
            <button
              type="button"
              className="btn btn-primary drop-btn"
              onClick={(event) => {
                event.stopPropagation();
                inputRef.current?.click();
              }}
              disabled={isLoading}
            >
              Browse file
            </button>
            <span className="drop-hint">or press space to open file picker</span>
          </div>
          <input
            ref={inputRef}
            id="eml-file-input"
            type="file"
            accept=".eml"
            onChange={onChange}
            className="visually-hidden"
          />
        </div>

        <div className="phish-hints">
          <div className="hint-card">
            <div className="hint-title">What we check</div>
            <ul className="hint-list">
              <li>SPF / DKIM / DMARC alignment</li>
              <li>Redirect chains & mismatched anchors</li>
              <li>Risky extensions & suspicious hashes</li>
            </ul>
            <div className="hint-pills">
              <span className="status-chip status-chip--soft">
                <span className="status-chip__dot" aria-hidden="true" />
                Secure channel
              </span>
              <span className="status-chip status-chip--neutral">Local history only</span>
            </div>
          </div>
        </div>
      </div>

      {selectedFile && (
        <div className="phish-file-preview">
          <div className="file-chip">
            <span className="file-icon">EML</span>
            <div className="file-meta">
              <div className="file-name break-all">{selectedFile.name}</div>
              <div className="file-details">
                {formatBytes(selectedFile.size)} · {selectedFile.type || "message/rfc822"}
              </div>
            </div>
          </div>
          <div className="file-actions">
            <button
              type="button"
              className="btn btn-ghost phish-secondary-btn"
              onClick={onReset}
              disabled={isLoading}
            >
              Clear
            </button>
            <button
              type="button"
              className="btn btn-primary btn-strong"
              onClick={handleUpload}
              disabled={isLoading}
            >
              {isLoading ? "Scanning..." : "Upload & Scan"}
            </button>
          </div>
        </div>
      )}

      <div className="phish-upload-footer">
        <div className="phish-meta">Validates SPF, DKIM, DMARC · Flags redirects · Scores links, headers, and attachments.</div>
        {isLoading && <Loader />}
        {error && (
          <div className="form-error phish-error" role="alert">
            {error}
          </div>
        )}
      </div>
    </section>
  );
};

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

const SummaryGrid = ({ report }) => {
  const summaryItems = [
    { label: "Sender", value: report?.sender || report?.raw_report?.parsing?.headers?.from || "N/A", isBreakAll: true },
    { label: "Subject", value: report?.subject || report?.raw_report?.parsing?.auth?.subject || "N/A", isBreakAll: true },
    { label: "Status", value: <StatusBadge status={report?.status} />, isNode: true },
    { label: "Score", value: report?.score ?? report?.raw_report?.detection?.score?.score ?? "N/A" },
    { label: "Links Found", value: report?.links ?? report?.raw_report?.extraction?.raw_links?.length ?? 0 },
    { label: "Attachments Found", value: report?.attachments ?? report?.raw_report?.extraction?.attachments?.length ?? 0 },
  ];
  return (
    <div className="phish-summary-grid">
      {summaryItems.map((item) => (
        <div key={item.label} className="phish-summary">
          <span className="phish-summary__label">{item.label}</span>
          <span className={`phish-summary__value ${item.isBreakAll ? "break-all" : ""}`}>
            {item.isNode ? item.value : item.value}
          </span>
        </div>
      ))}
    </div>
  );
};
const SuspiciousLinksPanel = ({ links }) => {
  if (!links || !links.length) {
    return <div className="phish-empty">No suspicious links detected.</div>;
  }
  return (
    <div className="phish-card-grid">
      {links.map((link, idx) => {
        const domain = extractDomain(link.link || link.absolute || link.href);
        const favicon = domain ? `https://www.google.com/s2/favicons?domain=${domain}` : null;
        const tags = [];
        if (link.reason) tags.push(link.reason);

        return (
          <div key={`sus-link-${idx}`} className="phish-item-card phish-item-card--link">
            <div className="phish-link-meta">
              <div className="link-leading">
                {favicon && <img src={favicon} alt="" className="favicon" />}
                <a href={link.link} target="_blank" rel="noreferrer" className="phish-link break-all">
                  {link.text || link.link}
                </a>
              </div>
              {domain && <span className="badge badge-ghost">{domain}</span>}
            </div>
            {link.link && (
              <div className="phish-meta break-all">
                URL: <span className="phish-mono">{link.link}</span>
              </div>
            )}
            {link.absolute && link.absolute !== link.link && (
              <div className="phish-meta break-all">
                Resolved: <span className="phish-mono">{link.absolute}</span>
              </div>
            )}
            {tags.length > 0 && (
              <div className="chip-row">
                {tags.map((tag) => (
                  <span key={tag} className="chip chip-warning">{tag}</span>
                ))}
              </div>
            )}
            {link.reason && <div className="phish-reason">Reason: {link.reason}</div>}
          </div>
        );
      })}
    </div>
  );
};

const attachmentIcon = (filename = "") => {
  const ext = filename.toLowerCase().split(".").pop();
  if (["pdf"].includes(ext)) return "PDF";
  if (["zip", "rar", "7z"].includes(ext)) return "ZIP";
  if (["exe", "bat", "cmd", "js"].includes(ext)) return "!";
  if (["doc", "docx"].includes(ext)) return "DOC";
  return ICONS.attachment;
};

const AttachmentsPanel = ({ attachments }) => {
  if (!attachments || !attachments.length) {
    return <div className="phish-empty">No risky attachments detected.</div>;
  }
  return (
    <div className="phish-card-grid">
      {attachments.map((att, idx) => {
        const ext = (att.filename || "").toLowerCase().split(".").pop();
        const isHighRisk = ["exe", "bat", "cmd", "js", "vbs", "scr"].includes(ext);
        return (
          <div key={`att-${idx}`} className={`phish-item-card phish-item-card--attachment ${isHighRisk ? "is-risk" : ""}`}>
            <div className="phish-link-title break-all">
              <span className="file-icon">{attachmentIcon(att.filename)}</span>
              {att.filename || "Unknown file"}
            </div>
            <div className="phish-meta">MIME: {att.content_type || att.mime_type || "Unknown type"}</div>
            {att.sha256 && (
              <div className="phish-meta break-all">
                SHA-256: <span className="phish-mono">{att.sha256}</span>
              </div>
            )}
            {att.reason && <div className="phish-reason">Reason: {att.reason}</div>}
            <div className="chip-row">
              <span className={`chip ${isHighRisk ? "chip-danger" : "chip-soft"}`}>
                {isHighRisk ? "High-risk extension" : "Review attachment"}
              </span>
              <span className="chip chip-muted">VT: pending</span>
            </div>
          </div>
        );
      })}
    </div>
  );
};
const severityForFlag = (reason = "") => {
  if (["header_auth_failure", "double_extension"].includes(reason)) return "high";
  if (["anchor_redirect_mismatch", "brand_lookalike", "display_name_spoofing"].includes(reason)) return "medium";
  return "low";
};

const actionForFlag = (key) => {
  const actions = {
    anchor_redirect: "Hover links before clicking; confirm landing domain.",
    typosquatting: "Manually type the trusted domain into your browser.",
    header_forgery: "Verify sender via out-of-band channel before trusting.",
    double_extension: "Do not open without sandboxing or AV scan.",
    html_forms: "Avoid submitting credentials from this email.",
    clickable_images: "Treat clickable images as links; verify destination.",
    social_engineering: "Educate recipient on urgency-based lures.",
    brand_lookalike: "Confirm branding with legitimate sender contact.",
    display_spoof: "Cross-check display name with verified address.",
  };
  return actions[key] || "Review carefully before responding.";
};

const ExtraFlagsPanel = ({ flags }) => {
  const grouped = useMemo(() => {
    const out = { high: [], medium: [], low: [] };
    Object.entries(flags || {}).forEach(([key, list]) => {
      (list || []).forEach((item) => {
        const sev = severityForFlag(item.reason || key);
        out[sev].push({ key, ...item });
      });
    });
    return out;
  }, [flags]);

  const renderGroup = (label, items, tone) => (
    <div className="flag-group">
      <div className="flag-group__head">
        <span className={`badge badge-${tone}`}>{label}</span>
        <span className="flag-count">{items.length} finding{items.length === 1 ? "" : "s"}</span>
      </div>
      {items.length === 0 ? (
        <div className="phish-empty">Nothing flagged.</div>
      ) : (
        <div className="phish-card-grid">
          {items.map((item, idx) => (
            <div key={`${item.key}-${idx}`} className="phish-item-card">
              <div className="phish-link-title">{item.key.replace(/_/g, " ")}</div>
              {item.domain && (
                <div className="phish-meta break-all">
                  Domain: <span className="phish-mono">{item.domain}</span>
                </div>
              )}
              {item.link && (
                <div className="phish-meta break-all">
                  Link: <a href={item.link} target="_blank" rel="noreferrer" className="phish-link">{item.link}</a>
                </div>
              )}
              {item.display && (
                <div className="phish-meta break-all">
                  Display: <span className="phish-mono">{item.display}</span>
                </div>
              )}
              {item.reason && <div className="phish-reason">Reason: {item.reason}</div>}
              <div className="flag-action">Recommended: {actionForFlag(item.key)}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );

  const total = Object.values(grouped).flat().length;
  if (total === 0) return <div className="phish-empty">No extra flags.</div>;
  return (
    <div className="flag-groups">
      {renderGroup("High", grouped.high, "danger")}
      {renderGroup("Medium", grouped.medium, "warning")}
      {renderGroup("Low", grouped.low, "safe")}
    </div>
  );
};

const escapeHtml = (str) =>
  str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

const highlightSearch = (text, query) => {
  if (!query) return escapeHtml(text);
  const safe = escapeHtml(text);
  const escaped = query.replace(/[-/\\^$*+?.()|[\\]{}]/g, "\\$&");
  const regex = new RegExp(`(${escaped})`, "gi");
  return safe.replace(regex, "<mark>$1</mark>");
};

const RawReportViewer = ({ data, search, onSearch, showModal, onToggleModal }) => {
  if (!data) return null;
  const pretty = JSON.stringify(data, null, 2);
  const highlighted = highlightSearch(pretty, search);

  const copyJson = () => {
    try {
      navigator.clipboard?.writeText(pretty);
    } catch (_) {
      /* noop */
    }
  };

  const downloadJson = () => {
    const blob = new Blob([pretty], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "phishing_report.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="phish-raw-wrap">
      <div className="raw-actions">
        <input
          type="search"
          className="raw-search"
          placeholder="Search JSON..."
          value={search}
          onChange={(e) => onSearch(e.target.value)}
        />
        <div className="raw-buttons">
          <button type="button" className="btn btn-secondary phish-secondary-btn" onClick={copyJson}>
            Copy
          </button>
          <button type="button" className="btn btn-outline-primary" onClick={downloadJson}>
            Download
          </button>
          <button type="button" className="btn btn-outline-secondary" onClick={onToggleModal}>
            {showModal ? "Close" : "Fullscreen"}
          </button>
        </div>
      </div>
      <div className={`phish-raw-pane ${showModal ? "is-modal" : ""}`}>
        <pre
          className="phish-raw"
          dangerouslySetInnerHTML={{ __html: highlighted }}
        />
      </div>
    </div>
  );
};

const Recommendations = ({ report }) => {
  const verdict = (report?.status || report?.raw_report?.detection?.score?.verdict || "").toLowerCase();
  const extraFlags = report?.findings?.extra_flags || report?.raw_report?.detection?.extra_flags || {};
  const hasAttachments = (report?.attachments ?? report?.raw_report?.extraction?.attachments?.length ?? 0) > 0;
  const hasLinks = (report?.links ?? report?.raw_report?.extraction?.raw_links?.length ?? 0) > 0;

  const recs = [];
  if (verdict === "malicious" || verdict === "danger" || verdict === "suspicious") {
    recs.push("Do not interact with links or attachments; notify your security team.");
  } else {
    recs.push("Review sender intent and context before trusting the email.");
  }
  if (extraFlags.typosquatting?.length) {
    recs.push("Manually type known domains into your browser instead of clicking links.");
  }
  if (extraFlags.header_forgery?.length) {
    recs.push("Validate sender identity via another channel (chat/phone).");
  }
  if (hasAttachments) {
    recs.push("Open attachments only in a sandbox or after AV scanning.");
  }
  if (hasLinks) {
    recs.push("Hover links to verify destination domains match the sender.");
  }

  return (
    <ul className="phish-issue-list">
      {recs.map((item, idx) => (
        <li key={`rec-${idx}`}>{item}</li>
      ))}
    </ul>
  );
};

function PhishingAnalyzer() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [collapseKey, setCollapseKey] = useState(0);
  const [rawSearch, setRawSearch] = useState("");
  const [rawModalOpen, setRawModalOpen] = useState(false);

  const uploadEmail = async (file) => {
    const form = new FormData();
    form.append("eml", file);
    const { data } = await api.post("/tools/Phishing-email/eml-scan", form, {
      headers: { "Content-Type": "multipart/form-data" },
    });
    return data;
  };

  const handleSelectFile = (file, errMsg) => {
    setSelectedFile(file);
    setReport(null);
    setError(errMsg || null);
    setCollapseKey((k) => k + 1);
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      setError("Please choose a .eml file to scan.");
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      const data = await uploadEmail(selectedFile);
      setReport(data);
      addHistoryEntry({
        tool: "Phishing Email Analyzer",
        date: new Date().toISOString(),
        risk: data?.score ?? 0,
        status: data?.status || "review",
      });
      setCollapseKey((k) => k + 1);
    } catch (err) {
      const msg =
        err?.response?.data?.detail ||
        err?.response?.data?.error ||
        err?.message ||
        "Upload failed. Please try again.";
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  };

  const findings = report?.findings || {};
  const suspiciousLinks = findings.suspicious_links || [];
  const headerIssues = findings.header_issues || [];
  const riskyAttachments = findings.risky_attachments || [];
  const extraFlags = findings.extra_flags || {};
  

  return (
    <>
      <Header />
      <main className="tool-page__content phish-page">
        <UploadCard
          selectedFile={selectedFile}
          onSelectFile={handleSelectFile}
          onUpload={handleUpload}
          isLoading={isLoading}
          error={error}
          onReset={() => handleSelectFile(null, null)}
        />

        {report && (
          <section className="phish-card phish-card--result fade-in">
            <div className="phish-card__header">
              <h2 className="phish-card__title">Scan Result</h2>
              <p className="phish-card__description">
                Summary of detected signals and risk markers for the uploaded email.
              </p>
            </div>

            <RiskBanner report={report} />
            <SummaryGrid report={report} />

            <div className="phish-section">
              <h3 className="phish-section__title">Findings</h3>
              <div className="phish-findings">
                <CollapsiblePane
                  key={`links-${collapseKey}`}
                  title={`Suspicious Links (${suspiciousLinks.length})`}
                  icon={ICONS.link}
                  tone="warning"
                  hint="Links with mismatched domains or redirect behavior."
                >
                  <SuspiciousLinksPanel links={suspiciousLinks} />
                </CollapsiblePane>

                <CollapsiblePane
                  key={`header-${collapseKey}`}
                  title={`Header Issues (${headerIssues.length})`}
                  icon={ICONS.info}
                  tone="warning"
                  hint="Misaligned From / Return-Path / Reply-To or SPF/DKIM/DMARC anomalies."
                >
                  {headerIssues.length === 0 ? (
                    <div className="phish-empty">No header inconsistencies found.</div>
                  ) : (
                    <ul className="phish-issue-list">
                      {headerIssues.map((issue, idx) => (
                        <li key={`header-issue-${idx}`}>{issue}</li>
                      ))}
                    </ul>
                  )}
                </CollapsiblePane>

                <CollapsiblePane
                  key={`attachments-${collapseKey}`}
                  title={`Attachments (${riskyAttachments.length})`}
                  icon={ICONS.attachment}
                  tone="danger"
                  hint="Risky extensions, large payloads, and suspicious hashes."
                >
                  <AttachmentsPanel attachments={riskyAttachments} />
                </CollapsiblePane>

                <CollapsiblePane
                  key={`flags-${collapseKey}`}
                  title={`Extra Flags (${Object.values(extraFlags).flat().length})`}
                  icon={ICONS.spark}
                  tone="info"
                  hint="Heuristic indicators like clickable images, typosquatting, or brand lookalikes."
                >
                  <ExtraFlagsPanel flags={extraFlags} />
                </CollapsiblePane>
              </div>
            </div>

            {report.raw_report && (
              <div className="phish-section">
                <CollapsiblePane key={`raw-${collapseKey}`} title="Raw report JSON" icon={ICONS.code} tone="info">
                  <RawReportViewer
                    data={report.raw_report}
                    search={rawSearch}
                    onSearch={setRawSearch}
                    showModal={rawModalOpen}
                    onToggleModal={() => setRawModalOpen((v) => !v)}
                  />
                </CollapsiblePane>
              </div>
            )}

            <div className="phish-section">
              <h3 className="phish-section__title">Recommendations</h3>
              <Recommendations report={report} />
            </div>
          </section>
        )}
      </main>
    </>
  );
}
export default PhishingAnalyzer;



