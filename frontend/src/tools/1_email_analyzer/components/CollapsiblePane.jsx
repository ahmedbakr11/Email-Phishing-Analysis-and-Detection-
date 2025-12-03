import React, { useEffect, useRef, useState } from "react";

const CollapsiblePane = ({ title, icon = null, tone = "info", hint, children, defaultOpen = false }) => {
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
          {icon ? <span className={`phish-collapsible__icon tone-${tone}`}>{icon}</span> : null}
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

export default CollapsiblePane;
