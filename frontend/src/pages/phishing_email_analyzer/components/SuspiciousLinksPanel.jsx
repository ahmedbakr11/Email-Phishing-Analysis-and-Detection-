import React from "react";
import { extractDomain } from "../utils/phishingUtils";

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

export default SuspiciousLinksPanel;
