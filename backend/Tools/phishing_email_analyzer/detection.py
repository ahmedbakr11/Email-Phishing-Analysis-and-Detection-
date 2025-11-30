"""PHASE 3 - Detection heuristics."""
import os
from typing import Dict, Iterable, List, Union

from bs4 import BeautifulSoup

HOMOGLYPHS = ["\u0430", "\u0435", "\u0456", "\u03bf", "\u0440", "\u0455", "\u0443"]  # Cyrillic, Greek forms


def detect_suspicious_links(links: List[Dict[str, str]], allowed_domains: List[str]) -> List[Dict[str, str]]:
    """Flag links whose domains differ from allowed domains (trusted + sender domains)."""
    findings: List[Dict[str, str]] = []
    allowed = {d.lower() for d in allowed_domains if d}
    for link in links:
        domain = (link.get("absolute_domain") or "").strip().lower()
        if not domain:
            continue
        if domain not in allowed:
            findings.append(
                {
                    "link": link.get("absolute") or link.get("href"),
                    "text": link.get("text"),
                    "reason": "domain_not_allowed",
                }
            )
    return findings


def detect_anchor_redirect_mismatch(links: List[Dict[str, str]], generic_labels: List[str]) -> List[Dict[str, str]]:
    """Flag anchors where display text implies one domain but URL points to another."""
    findings: List[Dict[str, str]] = []

    GENERIC_LABELS = {label.lower() for label in generic_labels}

    for link in links:
        display_text = (link.get("text") or "").strip()
        url = (link.get("absolute") or "").strip()
        display_domain = (link.get("text_domain") or "").strip().lower()
        url_domain = (link.get("absolute_domain") or "").strip().lower()

        if not display_text or not url:
            continue

        if display_text.lower() in GENERIC_LABELS:
            continue

        if not display_domain or not url_domain:
            continue

        if display_domain == url_domain:
            continue

        findings.append(
            {
                "display_text": display_text,
                "url": url,
                "display_domain": display_domain,
                "url_domain": url_domain,
                "reason": "anchor_redirect_mismatch",
            }
        )

    return findings


def detect_attachment_risks(
    attachments: List[Dict[str, Union[str, int]]], dangerous_exts: Union[Iterable[str], None] = None
) -> List[Dict[str, str]]:
    """Flag potentially risky attachments based on extension and size."""
    risky: List[Dict[str, str]] = []
    bad_ext = {ext.lower() for ext in (dangerous_exts or [])}
    if not bad_ext:
        bad_ext = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".com", ".apk", ".jar"}
    for att in attachments:
        name = att.get("filename") or ""
        ext = os.path.splitext(name.lower())[1]
        if ext in bad_ext or (att.get("size", 0) or 0) > 10 * 1024 * 1024:
            risky.append({"filename": name, "reason": "risky_extension_or_size"})
    return risky


def detect_double_extension(attachments: List[Dict[str, Union[str, int]]]) -> List[Dict[str, str]]:
    """Detect filenames using double extensions to hide risky payloads."""
    findings: List[Dict[str, str]] = []
    for att in attachments:
        name = att.get("filename", "").lower()
        if "." in name and name.count(".") >= 2:
            exts = name.split(".")
            last = exts[-1]
            prev = exts[-2]
            dangerous = {"exe", "scr", "js", "bat", "cmd"}
            if last in dangerous and prev not in dangerous:
                findings.append({"filename": name, "reason": "double_extension"})
    return findings


def detect_header_inconsistencies(id_headers: Dict[str, Union[str, None]]) -> List[str]:
    """Detect differences between From, Return-Path, and Reply-To domains."""
    issues: List[str] = []
    domains = {
        key: val
        for key, val in {
            "from": id_headers.get("from_domain"),
            "return": id_headers.get("return_domain"),
            "reply": id_headers.get("reply_domain"),
        }.items()
        if val
    }
    if len(set(domains.values())) > 1:
        issues.append("header_domain_mismatch")
    return issues


def detect_typosquatting(domains: Iterable[str]) -> List[Dict[str, str]]:
    """Identify potential typosquatting through homoglyphs or numeric tricks."""
    findings: List[Dict[str, str]] = []
    for domain in domains:
        if any(char in domain for char in HOMOGLYPHS):
            findings.append({"domain": domain, "reason": "unicode_homograph"})
        if any(num in domain for num in ["0", "1", "3", "5"]):
            findings.append({"domain": domain, "reason": "numeric_typosquatting"})
    return findings


def detect_display_name_spoofing(headers: Dict[str, str]) -> List[Dict[str, str]]:
    """Spot brand keywords in display name that are absent from domain."""
    findings: List[Dict[str, str]] = []
    display_name = headers.get("from", "") or ""
    domain = headers.get("from_domain", "") or ""
    if display_name and domain:
        lowered = display_name.lower()
        if any(keyword in lowered for keyword in ["paypal", "apple", "microsoft"]):
            if all(keyword not in domain for keyword in ["paypal", "apple", "microsoft"]):
                findings.append(
                    {
                        "display_name": display_name,
                        "domain": domain,
                        "reason": "display_name_spoofing",
                    }
                )
    return findings


def detect_header_forgery(auth_headers: Dict[str, Union[str, None]]) -> List[Dict[str, str]]:
    """Evaluate SPF, DKIM, and DMARC results for failure indicators."""
    findings = []

    spf = str(auth_headers.get("spf", "")).lower()
    dkim = str(auth_headers.get("dkim", "")).lower()
    dmarc = str(auth_headers.get("dmarc", "")).lower()

    # SPF failure signals (official RFC 7208)
    spf_fail_values = ["fail", "softfail", "none", "neutral", "permerror", "temperror"]

    if any(v in spf for v in spf_fail_values):
        findings.append({"method": "SPF", "result": "failure", "reason": spf})

    # DKIM failure signals
    # DKIM does NOT use softfail/neutral/none
    dkim_fail_values = ["fail", "permerror", "temperror"]

    if any(v in dkim for v in dkim_fail_values):
        findings.append({"method": "DKIM", "result": "failure", "reason": dkim})

    # DMARC failure signal
    # DMARC uses "pass" or "fail". "none" is a policy, *not* failure.
    if "fail" in dmarc:
        findings.append({"method": "DMARC", "result": "failure", "reason": dmarc})

    return findings


def detect_html_forms(html_parts: Iterable[str]) -> List[Dict[str, str]]:
    """Flag HTML bodies containing form submissions."""
    findings: List[Dict[str, str]] = []
    for html in html_parts:
        soup = BeautifulSoup(html, "html.parser")
        if soup.find("form"):
            findings.append({"reason": "html_form_submission"})
    return findings


def detect_clickable_images(html_parts: Iterable[str]) -> List[Dict[str, str]]:
    """Detect images wrapped in anchor tags (clickable images)."""
    findings: List[Dict[str, str]] = []
    for html in html_parts:
        soup = BeautifulSoup(html, "html.parser")
        for anchor in soup.find_all("a", href=True):
            if anchor.find("img"):
                findings.append({"link": anchor["href"], "reason": "clickable_image_link"})
    return findings


def detect_social_engineering_language(text_parts: Iterable[str], keywords: List[str]) -> List[Dict[str, str]]:
    """Identify urgent or coercive language patterns."""
    findings: List[Dict[str, str]] = []
    for text in text_parts:
        lowered = text.lower()
        if any(keyword in lowered for keyword in keywords):
            findings.append(
                {"reason": "social_engineering_language", "snippet": text[:120]}
            )
    return findings


def detect_brand_impersonation_variants(headers: Dict[str, str], variants: Iterable[str]) -> List[Dict[str, str]]:
    """Flag display names containing known brand lookalike variants not present in the domain."""
    findings: List[Dict[str, str]] = []
    display = (headers.get("from") or "").lower()
    domain = (headers.get("from_domain") or "").lower()

    for variant in {v.lower() for v in variants if v}:
        if variant in display and variant not in domain:
            findings.append({"display_name": display, "domain": domain, "variant": variant, "reason": "brand_impersonation_variant"})
    return findings


def detect_risky_tlds(links: List[Dict[str, str]], risky_tlds: Iterable[str]) -> List[Dict[str, str]]:
    """Detect links whose domains use risky top-level domains."""
    findings: List[Dict[str, str]] = []
    risky_set = {tld.lower().lstrip(".") for tld in risky_tlds if tld}
    if not risky_set:
        return findings

    for link in links:
        domain = (link.get("absolute_domain") or "").lower()
        if not domain or "." not in domain:
            continue
        tld = domain.rsplit(".", 1)[-1]
        if tld in risky_set:
            findings.append({"link": link.get("absolute") or link.get("href"), "domain": domain, "tld": tld, "reason": "risky_tld"})
    return findings


__all__ = [
    "detect_anchor_redirect_mismatch",
    "detect_attachment_risks",
    "detect_brand_impersonation_variants",
    "detect_clickable_images",
    "detect_display_name_spoofing",
    "detect_double_extension",
    "detect_header_forgery",
    "detect_header_inconsistencies",
    "detect_html_forms",
    "detect_risky_tlds",
    "detect_social_engineering_language",
    "detect_suspicious_links",
    "detect_typosquatting",
]
