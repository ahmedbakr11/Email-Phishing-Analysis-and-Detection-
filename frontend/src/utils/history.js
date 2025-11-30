// history.js

const KEY = "history_entries";

export function getHistory() {
  try {
    const raw = localStorage.getItem(KEY);
    return Array.isArray(JSON.parse(raw)) ? JSON.parse(raw) : [];
  } catch (_) {
    return [];
  }
}

export function addHistoryEntry(entry) {
  try {
    const arr = getHistory();
    const normalized = {
      tool: entry.tool || "Unknown",
      date: entry.date || new Date().toISOString(),
      risk: typeof entry.risk === 'number' ? entry.risk : 0,
      status: entry.status || "Unknown",
    };
    arr.unshift(normalized);
    const capped = arr.slice(0, 300);
    localStorage.setItem(KEY, JSON.stringify(capped));
  } catch (_) {
    // ignore
  }
}

