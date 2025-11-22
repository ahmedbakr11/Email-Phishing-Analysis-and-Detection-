"""
PHASE 1 - Extraction utilities.
Responsible for converting email input into raw bytes, parsing MIME parts,
and extracting raw artifacts (links, emails, IPs, attachments).
"""

import logging
import os
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Dict, Iterable, List, Tuple, Union

from bs4 import BeautifulSoup


# ---------------------------------------------------------
# 1. LOGGER & GLOBAL REGEXPATTERNS
# ---------------------------------------------------------

logger = logging.getLogger(__name__)

URL_RE = re.compile(r"https?://[^\s<>'\"()]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

EmailBytes = Union[bytes, bytearray]


# ---------------------------------------------------------
# 2. CORE LOADER — NORMALIZE ANY INPUT INTO RAW EMAIL BYTES
# ---------------------------------------------------------

def load_email_bytes(source: Union[str, os.PathLike, EmailBytes]) -> bytes:
    """Normalize input (path, bytes, text, file-like) into raw email bytes."""
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)

    if isinstance(source, str):
        path = Path(source)
        if path.exists():
            return path.read_bytes()
        return source.encode("utf-8")

    if isinstance(source, os.PathLike):
        return Path(source).read_bytes()

    read = getattr(source, "read", None)
    if callable(read):
        payload = read()
        return payload.encode("utf-8") if isinstance(payload, str) else bytes(payload or b"")

    raise TypeError(f"Unsupported email source type: {type(source).__name__}")


# ---------------------------------------------------------
# 3. MIME PARSER — SPLIT HEADERS + PARTS (TEXT / HTML / ATTACHMENTS)
# ---------------------------------------------------------

def extract_raw_message(raw_bytes: EmailBytes) -> Tuple[Dict[str, str], List[Dict[str, Union[str, bytes]]]]:
    """Parse the MIME email and return raw headers plus structured parts."""
    msg = BytesParser(policy=policy.default).parsebytes(bytes(raw_bytes))
    headers = {k: v for k, v in msg.items()}
    parts: List[Dict[str, Union[str, bytes]]] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue

            disposition = part.get_content_disposition()
            filename = part.get_filename()
            content_type = part.get_content_type()

            if disposition == "attachment" or filename:
                parts.append(
                    {
                        "part_type": "attachment",
                        "filename": filename or "",
                        "content_type": content_type,
                        "payload": part.get_payload(decode=True) or b"",
                    }
                )

            elif content_type == "text/plain":
                parts.append({"part_type": "text", "text": part.get_content() or ""})

            elif content_type == "text/html":
                parts.append({"part_type": "html", "html": part.get_content() or ""})

    else:
        ctype = msg.get_content_type()

        if ctype == "text/plain":
            parts.append({"part_type": "text", "text": msg.get_content() or ""})

        elif ctype == "text/html":
            parts.append({"part_type": "html", "html": msg.get_content() or ""})

        else:
            parts.append(
                {
                    "part_type": "attachment",
                    "filename": msg.get_filename() or "",
                    "content_type": ctype,
                    "payload": msg.get_payload(decode=True) or b"",
                }
            )

    return headers, parts


# ---------------------------------------------------------
# 4. RAW ARTIFACT EXTRACTION HELPERS
# ---------------------------------------------------------

def extract_raw_links(text: str) -> List[str]:
    """Extract URLs from arbitrary text."""
    return URL_RE.findall(text or "") if text else []


def extract_raw_emails(text: str) -> List[str]:
    """Extract email addresses from arbitrary text."""
    return EMAIL_RE.findall(text or "") if text else []


def extract_raw_ips(text: str) -> List[str]:
    """Extract IPv4 addresses from arbitrary text."""
    return IP_RE.findall(text or "") if text else []


# ---------------------------------------------------------
# 5. ARTIFACT AGGREGATOR — FULL EXTRACTION ACROSS HEADERS + PARTS
# ---------------------------------------------------------

def extract_artifacts(
    headers: Dict[str, str],
    parts: Iterable[Dict[str, Union[str, bytes]]]
) -> Dict[str, Union[List[str], List[Dict[str, str]]]]:
    """
    Collect raw artifacts (text, html, attachments, emails, URLs, IPs)
    from all headers and MIME parts.
    """
    text_chunks: List[str] = []
    html_chunks: List[str] = []
    attachments: List[Dict[str, str]] = []
    link_candidates: List[str] = []
    email_hits: List[str] = []
    ip_hits: List[str] = []

    # Extract from headers
    for value in headers.values():
        link_candidates.extend(extract_raw_links(value))
        email_hits.extend(extract_raw_emails(value))
        ip_hits.extend(extract_raw_ips(value))

    # Extract from MIME parts
    for part in parts:
        if part["part_type"] == "text":
            text = str(part.get("text") or "")
            text_chunks.append(text)

            link_candidates.extend(extract_raw_links(text))
            email_hits.extend(extract_raw_emails(text))
            ip_hits.extend(extract_raw_ips(text))

        elif part["part_type"] == "html":
            html = str(part.get("html") or "")
            html_chunks.append(html)

            visible_text = BeautifulSoup(html, "html.parser").get_text(" ", strip=True)

            link_candidates.extend(extract_raw_links(visible_text))
            email_hits.extend(extract_raw_emails(visible_text))
            ip_hits.extend(extract_raw_ips(visible_text))

        elif part["part_type"] == "attachment":
            attachments.append(
                {
                    "filename": str(part.get("filename") or ""),
                    "content_type": str(part.get("content_type") or ""),
                }
            )

    # Deduplicate in order
    return {
        "text_parts": text_chunks,
        "html_parts": html_chunks,
        "attachments": attachments,
        "raw_links": list(dict.fromkeys(link_candidates)),
        "raw_emails": list(dict.fromkeys(email_hits)),
        "raw_ips": list(dict.fromkeys(ip_hits)),
    }


# ---------------------------------------------------------
# 6. FILE LOADER HELPERS (trusted domains / suspicious words / labels)
# ---------------------------------------------------------

def load_trusted_domains(path: str) -> List[str]:
    """Load trusted-sender domains from a reference file."""
    domains = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                entry = line.strip()
                if not entry or entry.startswith("#"):
                    continue
                domains.append(entry.lower())
    except Exception:
        logger.warning("Trusted domains file could not be loaded; continuing with empty list.")
        return []
    return domains


def load_sus_words(path: str) -> List[str]:
    """Load suspicious-language keywords from a reference file."""
    words = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                entry = line.strip()
                if not entry or entry.startswith("#"):
                    continue
                words.append(entry.lower())
    except Exception:
        logger.warning("Suspicious words file could not be loaded; continuing with empty list.")
        return []
    return words


def load_generic_labels(path: str) -> List[str]:
    """Load generic anchor labels such as 'click here', 'open', 'view'."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        return []


# ---------------------------------------------------------
# 7. PUBLIC EXPORTS
# ---------------------------------------------------------

__all__ = [
    "EmailBytes",
    "URL_RE",
    "EMAIL_RE",
    "IP_RE",
    "load_email_bytes",
    "extract_raw_message",
    "extract_raw_links",
    "extract_raw_emails",
    "extract_raw_ips",
    "extract_artifacts",
    "load_trusted_domains",
    "load_sus_words",
    "load_generic_labels",
]
