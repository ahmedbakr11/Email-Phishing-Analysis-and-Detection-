import React, { useMemo } from "react";
import { actionForFlag, severityForFlag } from "../utils/phishingUtils";

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

export default ExtraFlagsPanel;
