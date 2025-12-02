import React from "react";
import { VERDICT_LABELS } from "../utils/constants";
import { toneForVerdict } from "../utils/phishingUtils";

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

export default StatusBadge;
