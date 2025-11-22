"""
PHASE 2 - Parsing logic for headers, authentication results, body content,
HTML link normalization, and attachment metadata extraction.
"""

import hashlib
import re
from email.utils import parseaddr
from typing import Dict, Iterable, List, Union
from urllib.parse import urljoin, unquote, urlparse

from bs4 import BeautifulSoup


# ---------------------------------------------------------
# 1. LOW-LEVEL HELPERS
# ---------------------------------------------------------

def _sha256_bytes(data: bytes) -> str:
    """Return SHA256 hash (hex) for attachment hashing."""
    h = hashlib.sha256()
    h.update(data or b"")
    return h.hexdigest()


def _extract_domain_from_text(text: str) -> str:
    """
    Extract a domain-like substring from visible link text.
    Example: "Visit paypal.com now" → "paypal.com".
    Returns empty string if none found.
    """
    if not text:
        return ""
    lowered = text.lower()
    match = re.search(r"([a-z0-9.-]+\.[a-z]{2,})", lowered)
    return match.group(1) if match else ""


# ---------------------------------------------------------
# 2. HEADER PARSING (FROM / RETURN-PATH / REPLY-TO)
# ---------------------------------------------------------

def parse_header_identities(headers: Dict[str, str]) -> Dict[str, Union[str, None]]:
    """Normalize addressing info and extract domain components."""

    from_addr = parseaddr(headers.get("From", ""))[1]
    return_path = parseaddr(headers.get("Return-Path", ""))[1]
    reply_to = parseaddr(headers.get("Reply-To", ""))[1]

    def _domain(addr: str) -> Union[str, None]:
        local, _, domain = addr.partition("@")
        return domain.lower() if local and domain else None

    return {
        "from": from_addr or None,
        "from_domain": _domain(from_addr),
        "return_path": return_path or None,
        "return_domain": _domain(return_path) if return_path else None,
        "reply_to": reply_to or None,
        "reply_domain": _domain(reply_to) if reply_to else None,
    }


# ---------------------------------------------------------
# 3. AUTHENTICATION PARSING (SPF / DKIM / DMARC)
# ---------------------------------------------------------

def parse_authentication_results(headers: Dict[str, str]) -> Dict[str, Union[str, None]]:
    """Extract SPF, DKIM, and DMARC result fields for detection."""
    return {
        "spf": headers.get("Received-SPF") or headers.get("Authentication-Results"),
        "dkim": headers.get("DKIM-Signature") or headers.get("X-DKIM-Result"),
        "dmarc": headers.get("DMARC-Filter") or headers.get("Authentication-Results"),
        "message_id": headers.get("Message-ID"),
        "subject": headers.get("Subject"),
        "date": headers.get("Date"),
    }


# ---------------------------------------------------------
# 4. BODY PARSING (TEXT, HTML, AND NORMALIZED LINKS)
# ---------------------------------------------------------

def parse_body_content(
    parts: Iterable[Dict[str, Union[str, bytes]]]
) -> Dict[str, Union[List[str], List[Dict[str, str]]]]:
    """
    Normalize text content, capture raw HTML, and canonicalize links discovered in HTML.
    Produces:
        - text parts
        - raw HTML parts
        - normalized HTML link objects
    """

    html_links: List[Dict[str, str]] = []
    text_content: List[str] = []
    html_text: List[str] = []

    for part in parts:
        if part["part_type"] == "text":
            text = str(part.get("text") or "")
            text_content.append(text.strip())

        elif part["part_type"] == "html":
            html = str(part.get("html") or "")
            html_text.append(html)

            soup = BeautifulSoup(html, "html.parser")

            for anchor in soup.find_all("a", href=True):
                href = anchor["href"].strip()
                if not href:
                    continue

                lowered_href = href.lower()
                # Skip irrelevant or dangerous pseudo-links
                if lowered_href.startswith("#") or lowered_href.startswith("javascript:"):
                    continue

                # Skip malformed or relative links with no hostname
                parsed_href = urlparse(href)
                if (
                    not parsed_href.scheme
                    and not parsed_href.hostname
                    and not parsed_href.netloc
                ):
                    continue

                # Canonicalize link
                abs_href = urljoin("", href)
                abs_unquoted = unquote(abs_href)
                parsed_absolute = urlparse(abs_unquoted)

                hostname = parsed_absolute.hostname or ""
                text_value = anchor.get_text(" ", strip=True)
                text_domain = _extract_domain_from_text(text_value)

                html_links.append(
                    {
                        "href": href,
                        "absolute": abs_unquoted,
                        "text": text_value,
                        "absolute_domain": hostname.lower() if hostname else "",
                        "text_domain": text_domain.lower() if text_domain else "",
                    }
                )

    return {
        "text": text_content,
        "html": html_text,
        "links": html_links,
    }


# ---------------------------------------------------------
# 5. ATTACHMENT METADATA PARSING
# ---------------------------------------------------------

def parse_attachment_metadata(
    parts: Iterable[Dict[str, Union[str, bytes]]]
) -> List[Dict[str, Union[str, int]]]:
    """Compute attachment metadata such as filename, MIME type, size, and SHA256 hash."""
    parsed: List[Dict[str, Union[str, int]]] = []

    for part in parts:
        if part["part_type"] != "attachment":
            continue

        payload = part.get("payload") or b""

        parsed.append(
            {
                "filename": str(part.get("filename") or ""),
                "content_type": str(part.get("content_type") or ""),
                "size": len(payload),
                "sha256": _sha256_bytes(payload),
            }
        )

    return parsed


# ---------------------------------------------------------
# 6. EXPORT LIST
# ---------------------------------------------------------

__all__ = [
    "parse_header_identities",
    "parse_authentication_results",
    "parse_body_content",
    "parse_attachment_metadata",
]
