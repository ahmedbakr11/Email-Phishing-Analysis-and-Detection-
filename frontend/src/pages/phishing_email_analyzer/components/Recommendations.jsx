import React from "react";

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

export default Recommendations;
