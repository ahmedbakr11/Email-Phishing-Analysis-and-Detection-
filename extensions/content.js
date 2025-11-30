///////////////////////
///////HELPERS////////

//phase1
function waitFor(selector, timeout = 10000) {
    return new Promise((resolve, reject) => {
        const interval = 50;
        let elapsed = 0;

        const check = () => {
            const el = document.querySelector(selector);
            if (el) return resolve(el);

            elapsed += interval;
            if (elapsed >= timeout) return reject("Element not found");

            setTimeout(check, interval);
        };

        check();
    });
}

//phase2
function observeInbox() {
    const inboxNode = document.querySelector('div[role="main"]');
    if (!inboxNode) return console.log("[cs] cant find inbox node");

    console.log("[cs] observing inbox for changes");

    const observer = new MutationObserver(() => {
        processVisibleEmails();
    });

    observer.observe(inboxNode, { childList: true, subtree: true });
}

function getMessageRows() {
    return Array.from(document.querySelectorAll('tr.zA'));
}

function extractMessageId(row) {
  // Prefer the last message id on descendants (common in Gmail rows)
  const lastMsg = row.querySelector("[data-legacy-last-message-id]")?.getAttribute("data-legacy-last-message-id");
  const legacyThread = row.getAttribute("data-legacy-thread-id") || row.querySelector("[data-legacy-thread-id]")?.getAttribute("data-legacy-thread-id");
  const thread = row.querySelector("[data-thread-id]")?.getAttribute("data-thread-id");

  const raw = lastMsg || legacyThread || thread || "";
  // Strip possible '#thread-...' prefixes and leading '#'
  return raw.replace(/^#?thread-[^:]*:/, "").replace(/^#/, "");
}

function extractSender(row) {
    // Sender appears inside span.zF (unread) or span.yP (read), both under .bA4
    const senderEl = row.querySelector("span.zF, span.yP");
    return senderEl ? senderEl.textContent.trim() : "(unknown sender)";
}

//phase3 function
const scannedCache = new Set();

function processVisibleEmails() {
    const rows = getMessageRows();
    console.log("[cs] processing visible rows:", rows.length);

    rows.forEach(row => {
        const id = extractMessageId(row);
        if (!id) return console.log("[cs] cant find ID");

        const sender = extractSender(row);
        console.log("[cs] detected Gmail row ID:", id, "sender:", sender);

        if (!scannedCache.has(id)) {
            scannedCache.add(id);
            sendForScan(id, row);
        }
    });
}

//phase4 function
function sendForScan(messageId, rowElement) {
    console.log("[cs] sending message to background:", messageId);
    chrome.runtime.sendMessage(
        {
            action: "scan_email",
            gmail_message_id: messageId
        },
        response => {
            if (!response) return console.log("[cs] no response from background process", chrome.runtime.lastError);
            console.log("[cs] background response:", response);
            applyTag(rowElement, response.status);
        }
    );
}

//phase5 function
function applyTag(row, status) {
    // Anchor near subject/sender; fall back to main cell/row
    const container =
        row.querySelector("td.yX") ||           // main content cell
        row.querySelector("span.bqe") ||        // subject span
        row.querySelector("span.bA4") ||        // sender wrapper
        row;

    if (!container) return console.log("[cs] cant apply tag (no container)");

    // Reuse existing tag if present
    let tag = container.querySelector("span.phish-tag");
    if (!tag) {
        tag = document.createElement("span");
        tag.className = "phish-tag";
        container.prepend(tag);
    }

    tag.textContent = status.toUpperCase();
    tag.dataset.phishStatus = status;
    // Inline styles to avoid Gmail CSS collisions
    tag.style.display = "inline-block";
    tag.style.marginRight = "6px";
    tag.style.padding = "2px 5px";
    tag.style.borderRadius = "4px";
    tag.style.fontSize = "10px";
    tag.style.fontWeight = "700";
    tag.style.color = "#fff";
    tag.style.textTransform = "uppercase";

    // Status-based colors
    const colors = {
        safe: "#281ae8ff",
        suspicious: "#fbbc04",
        malicious: "#d93025",
        uncertain: "#9e9e9e"
    };
    tag.style.backgroundColor = colors[status] || colors.uncertain;

    console.log("[cs] applied tag", status, "to", container.className || container.tagName);
}

///////////////////////
////////LOGIC/////////

waitFor('div[role="main"]').then(() => {
    console.log("[cs] main inbox found, starting observers");
    observeInbox();
    processVisibleEmails();
}).catch(err => console.log("[cs] waitFor main failed", err));

// Manual test ping to background on load
//chrome.runtime.sendMessage(
//  { action: "scan_email", gmail_message_id: "test-id-777" },
//  (res) => console.log("[cs] bg response", res, chrome.runtime.lastError)
//);

///////////////////////
/////////CSS//////////
(function injectStyles() {
    const css = `
        .phish-tag {
            margin-right: 6px;
            padding: 2px 5px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: bold;
            color: white;
        }
        .phish-tag.safe { background-color: #1a28e8ff; }
        .phish-tag.suspicious { background-color: #fbbc04; }
        .phish-tag.malicious { background-color: #d93025; }
    `;
    const style = document.createElement("style");
    style.textContent = css;
    document.head.appendChild(style);
})();
