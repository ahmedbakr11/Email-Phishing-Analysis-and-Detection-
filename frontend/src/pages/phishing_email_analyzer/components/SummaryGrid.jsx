import React from "react";
import StatusBadge from "./StatusBadge";

const SummaryGrid = ({ report }) => {
  const summaryItems = [
    { label: "Sender", value: report?.sender || report?.raw_report?.parsing?.headers?.from || "N/A", isBreakAll: true },
    { label: "Subject", value: report?.subject || report?.raw_report?.parsing?.auth?.subject || "N/A", isBreakAll: true },
    { label: "Status", value: <StatusBadge status={report?.status} />, isNode: true },
    { label: "Score", value: report?.score ?? report?.raw_report?.detection?.score?.score ?? "N/A" },
    { label: "Links Found", value: report?.links ?? report?.raw_report?.extraction?.raw_links?.length ?? 0 },
    { label: "Attachments Found", value: report?.attachments ?? report?.raw_report?.extraction?.attachments?.length ?? 0 },
  ];

  const formatKey = (label) => label.toLowerCase().replace(/\s+/g, "_");

  return (
    <div className="phish-summary-grid phish-summary-grid--stacked">
      <div className="summary-json-block">
        <div className="summary-json-brace">{'{'}</div>
        <div className="summary-json-lines">
          {summaryItems.map((item, idx) => (
            <div key={item.label} className="summary-json-line">
              <span className="summary-json-key">"{formatKey(item.label)}"</span>
              <span className="summary-json-sep">:</span>
              <span className={`summary-json-val ${item.isBreakAll ? "break-all" : ""}`}>
                {item.isNode ? item.value : JSON.stringify(item.value)}
              </span>
              {idx < summaryItems.length - 1 && <span className="summary-json-comma">,</span>}
            </div>
          ))}
        </div>
        <div className="summary-json-brace">{'}'}</div>
      </div>
    </div>
  );
};

export default SummaryGrid;
