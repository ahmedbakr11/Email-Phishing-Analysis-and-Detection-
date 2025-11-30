// Background service worker: receives scan requests, calls backend, caches results.
const API_URL = "http://127.0.0.1:5000/api/tools/Phishing-email/ext-scan";

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg || !msg.action) return;

    if (msg.action === "scan_email") {
        console.log("[bg] received scan request:", msg.gmail_message_id);
        handleScanRequest(msg.gmail_message_id).then(sendResponse);
        return true; // keep sendResponse alive for async
    }
});

const scanCache = new Map();

async function handleScanRequest(messageId) {
    if (scanCache.has(messageId)) {
        return scanCache.get(messageId);
    }

    const stored = await loadFromStorage(messageId);
    if (stored) {
        scanCache.set(messageId, stored);
        return stored;
    }

    const fresh = await callBackendScan(messageId);

    scanCache.set(messageId, fresh);
    saveToStorage(messageId, fresh);

    return fresh;
}

// calls the backend sending it the emailID and gets the result of the backend
async function callBackendScan(messageId) {
    try {
        console.log("[bg] callBackendScan ->", messageId);

        const response = await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                provider: "gmail",
                gmail_message_id: messageId
            })
        });

        console.log("[bg] fetch status", response.status);

        const data = await response.json();
        console.log("[bg] backend payload", data);

        return {
            status: data.status || "uncertain",
            score: data.score || 0,
            cached: data.cached || false
        };
    } catch (e) {
        console.error("[bg] callBackendScan failed", e);
        return {
            status: "uncertain",
            score: 0,
            cached: false
        };
    }
}

/// Persistent caching across tabs
chrome.storage.local.get("scanResults", (res) => {
    if (!res.scanResults) {
        chrome.storage.local.set({ scanResults: {} });
    }
});

function saveToStorage(messageId, data) {
    chrome.storage.local.get("scanResults", (res) => {
        const updated = res.scanResults || {};
        updated[messageId] = data;
        chrome.storage.local.set({ scanResults: updated });
    });
}

function loadFromStorage(messageId) {
    return new Promise(resolve => {
        chrome.storage.local.get("scanResults", (res) => {
            const store = res.scanResults || {};
            resolve(store[messageId]);
        });
    });
}

/// Initiating the background process
async function init() {
    const stored = await new Promise(resolve => {
        chrome.storage.local.get("scanResults", (res) => resolve(res.scanResults || {}));
    });

    for (const [id, result] of Object.entries(stored)) {
        scanCache.set(id, result);
    }
}

init();
