import React from "react";
import { toneForVerdict } from "../utils/phishingUtils";

const RecentScans = ({ entries }) => {
  if (!entries || !entries.length) return null;

  return (
    <section className="phish-card phish-card--history">
      <div className="phish-card__header">
        <h3 className="phish-card__title">Recent Scans</h3>
        <p className="phish-card__description">Local history stored in your browser.</p>
      </div>
      <div className="recent-grid">
        {entries.map((item, idx) => (
          <div key={idx} className="recent-item">
            <div className="recent-head">
              <span className="badge badge-soft">{item.tool}</span>
              <span className={`status-pill status-pill--${toneForVerdict(item.status)}`}>
                <span className="status-pill__dot" />
                <span className="status-pill__text">{item.status}</span>
              </span>
            </div>
            <div className="recent-meta">
              <span>{new Date(item.date).toLocaleString()}</span>
              <span className="badge badge-ghost">Risk {item.risk}</span>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
};

export default RecentScans;
