import React from "react";

const Loader = ({ label = "Analyzing email..." }) => (
  <div className="phish-loader" aria-live="polite">
    <span className="phish-loader__spinner" aria-hidden="true" />
    <span className="phish-loader__dot" aria-hidden="true" />
    <span>{label}</span>
  </div>
);

export default Loader;
