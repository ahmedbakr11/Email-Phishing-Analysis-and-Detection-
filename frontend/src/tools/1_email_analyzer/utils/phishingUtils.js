export const toneForVerdict = (verdict) => {
  const key = (verdict || "").toLowerCase();
  if (["danger", "suspicious"].includes(key)) return "danger";
  if (["review", "warning"].includes(key)) return "warning";
  return "safe";
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
