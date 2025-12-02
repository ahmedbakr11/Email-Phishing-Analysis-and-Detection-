export const toneForVerdict = (verdict) => {
  const key = (verdict || "").toLowerCase();
  if (["danger", "suspicious"].includes(key)) return "danger";
  if (["review", "warning"].includes(key)) return "warning";
  return "safe";
};

export const formatBytes = (bytes) => {
  if (!bytes && bytes !== 0) return "-";
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / k ** i).toFixed(1)} ${sizes[i]}`;
};

export const extractDomain = (link) => {
  if (!link) return "";
  try {
    const url = new URL(link.startsWith("http") ? link : `https://${link}`);
    return url.hostname;
  } catch (_) {
    const parts = link.split("/")[0];
    return parts;
  }
};

export const severityForFlag = (reason = "") => {
  if (["header_auth_failure", "double_extension"].includes(reason)) return "high";
  if (["anchor_redirect_mismatch", "brand_lookalike", "display_name_spoofing"].includes(reason)) return "medium";
  return "low";
};

export const actionForFlag = (key) => {
  const actions = {
    anchor_redirect: "Hover links before clicking; confirm landing domain.",
    typosquatting: "Manually type the trusted domain into your browser.",
    header_forgery: "Verify sender via out-of-band channel before trusting.",
    double_extension: "Do not open without sandboxing or AV scan.",
    html_forms: "Avoid submitting credentials from this email.",
    clickable_images: "Treat clickable images as links; verify destination.",
    social_engineering: "Educate recipient on urgency-based lures.",
    brand_lookalike: "Confirm branding with legitimate sender contact.",
    display_spoof: "Cross-check display name with verified address.",
  };
  return actions[key] || "Review carefully before responding.";
};
