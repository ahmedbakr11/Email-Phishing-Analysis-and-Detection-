const HISTORY_KEY = "phish_history";

const safeParse = (value) => {
  try {
    return JSON.parse(value);
  } catch (_) {
    return [];
  }
};

export const getHistory = () => {
  if (typeof window === "undefined" || !window.localStorage) return [];
  const raw = window.localStorage.getItem(HISTORY_KEY);
  if (!raw) return [];
  const parsed = safeParse(raw);
  return Array.isArray(parsed) ? parsed : [];
};

export const addHistoryEntry = (entry) => {
  if (!entry || typeof window === "undefined" || !window.localStorage) return;
  const next = [entry, ...getHistory()].slice(0, 20);
  try {
    window.localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
  } catch (_) {
    /* ignore write errors */
  }
  return next;
};

export const clearHistory = () => {
  if (typeof window === "undefined" || !window.localStorage) return;
  try {
    window.localStorage.removeItem(HISTORY_KEY);
  } catch (_) {
    /* ignore removal errors */
  }
};
