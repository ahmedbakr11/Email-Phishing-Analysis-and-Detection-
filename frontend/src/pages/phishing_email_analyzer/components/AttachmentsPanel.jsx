import React from "react";
import { ICONS } from "../utils/constants";

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

export default AttachmentsPanel;
