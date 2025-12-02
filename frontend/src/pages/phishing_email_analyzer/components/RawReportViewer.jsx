import React from "react";

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

const RawReportViewer = ({ data, search, onSearch }) => {
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
        </div>
      </div>
      <div className="phish-raw-pane">
        <pre
          className="phish-raw"
          dangerouslySetInnerHTML={{ __html: highlighted }}
        />
      </div>
    </div>
  );
};

export default RawReportViewer;
