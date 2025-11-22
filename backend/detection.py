"""
PHASE 3 - Detection heuristics, scoring, and rule engine.
All detectors are grouped logically by category for clarity.
"""

import os
import re
from typing import Dict, Iterable, List, Union
from bs4 import BeautifulSoup


# ---------------------------------------------------------
# 1. GLOBAL RULE CONTAINERS (reserved for future dynamic rules)
# ---------------------------------------------------------

KEYWORDS: Dict[str, re.Pattern] = {}
URL_PATTERNS: Dict[str, re.Pattern] = {}
HEADER_RULES: Dict[str, re.Pattern] = {}
ATTACHMENT_RULES: Dict[str, re.Pattern] = {}
OBFUSCATION_PATTERNS: Dict[str, re.Pattern] = {}
SCOREMAP: Dict[str, float] = {}
DESCRIPTIONS: Dict[str, str] = {}
_RULES_LOADED = False

# Unicode homoglyphs for typosquatting detection
HOMOGLYPHS = ["\u0430", "\u0435", "\u0456", "\u03bf", "\u0440", "\u0455", "\u0443"]


# ---------------------------------------------------------
# 2. LOW-LEVEL HELPERS (regex compilation + rule storage)
# ---------------------------------------------------------

def _compile_regex(pattern: str, flags: str = "") -> Union[re.Pattern, None]:
    """Compile a regex pattern safely with optional flags."""
    flag_value = re.IGNORECASE if "i" in flags.lower() else 0
    try:
        return re.compile(pattern.strip(), flag_value)
    except re.error:
        return None


def _store_rule(container: Dict[str, re.Pattern], name: str, pattern: str, flags: str = "") -> None:
    """Store a compiled rule if valid and not already present."""
    compiled = _compile_regex(pattern.strip(), flags)
    if compiled and name not in container:
        container[name] = compiled


# ---------------------------------------------------------
# 3. HEADER-BASED DETECTORS (address spoofing, authentication)
# ---------------------------------------------------------

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


def detect_header_forgery(auth_headers: Dict[str, Union[str, None]]) -> List[Dict[str, str]]:
    """Evaluate SPF, DKIM, and DMARC results for failure indicators."""
    findings = []

    spf = str(auth_headers.get("spf", "")).lower()
    dkim = str(auth_headers.get("dkim", "")).lower()
    dmarc = str(auth_headers.get("dmarc", "")).lower()

    spf_fail_values = ["fail", "softfail", "none", "neutral", "permerror", "temperror"]
    if any(v in spf for v in spf_fail_values):
        findings.append({"method": "SPF", "result": "failure", "reason": spf})

    dkim_fail_values = ["fail", "permerror", "temperror"]
    if any(v in dkim for v in dkim_fail_values):
        findings.append({"method": "DKIM", "result": "failure", "reason": dkim})

    if "fail" in dmarc:
        findings.append({"method": "DMARC", "result": "failure", "reason": dmarc})

    return findings


def detect_display_name_spoofing(headers: Dict[str, str]) -> List[Dict[str, str]]:
    """Spot brand keywords in display name that are absent from the domain."""
    findings: List[Dict[str, str]] = []
    display_name = headers.get("from", "") or ""
    domain = headers.get("from_domain", "") or ""
    if display_name and domain:
        lowered = display_name.lower()
        brands = ["paypal", "apple", "microsoft"]
        if any(keyword in lowered for keyword in brands):
            if all(keyword not in domain for keyword in brands):
                findings.append(
                    {
                        "display_name": display_name,
                        "domain": domain,
                        "reason": "display_name_spoofing",
                    }
                )
    return findings


def detect_brand_lookalike_pairing(headers: Dict[str, str]) -> List[Dict[str, str]]:
    """Pair display names with domains to detect brand impersonation."""
    findings: List[Dict[str, str]] = []
    display = headers.get("from", "") or ""
    domain = headers.get("from_domain", "") or ""
    lowered = display.lower()
    brands = ["apple", "paypal", "google", "amazon"]
    if any(brand in lowered for brand in brands):
        if all(brand not in domain for brand in brands):
            findings.append(
                {"display": display, "domain": domain, "reason": "brand_lookalike_pairing"}
            )
    return findings


# ---------------------------------------------------------
# 4. ATTACHMENT-BASED DETECTORS (file risks)
# ---------------------------------------------------------

def detect_attachment_risks(attachments: List[Dict[str, Union[str, int]]]) -> List[Dict[str, str]]:
    """Flag potentially risky attachments based on extension and size."""
    findings: List[Dict[str, str]] = []
    bad_ext = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".com", ".apk", ".jar"}

    for att in attachments:
        name = att.get("filename") or ""
        ext = os.path.splitext(name.lower())[1]
        size = att.get("size", 0) or 0

        if ext in bad_ext or size > 10 * 1024 * 1024:
            findings.append({"filename": name, "reason": "risky_extension_or_size"})
    return findings


def detect_double_extension(attachments: List[Dict[str, Union[str, int]]]) -> List[Dict[str, str]]:
    """Detect filenames using double extensions to hide risky payloads."""
    findings: List[Dict[str, str]] = []
    dangerous = {"exe", "scr", "js", "bat", "cmd"}

    for att in attachments:
        name = att.get("filename", "").lower()
        if "." in name and name.count(".") >= 2:
            parts = name.split(".")
            prev = parts[-2]
            last = parts[-1]
            if last in dangerous and prev not in dangerous:
                findings.append({"filename": name, "reason": "double_extension"})
    return findings


# ---------------------------------------------------------
# 5. HTML / BODY CONTENT DETECTORS
# ---------------------------------------------------------

def detect_html_forms(html_parts: Iterable[str]) -> List[Dict[str, str]]:
    """Flag HTML bodies containing form submissions."""
    findings: List[Dict[str, str]] = []
    for html in html_parts:
        soup = BeautifulSoup(html, "html.parser")
        if soup.find("form"):
            findings.append({"reason": "html_form_submission"})
    return findings


def detect_clickable_images(html_parts: Iterable[str]) -> List[Dict[str, str]]:
    """Detect images wrapped inside anchor tags."""
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


# ---------------------------------------------------------
# 6. LINK-BASED DETECTORS
# ---------------------------------------------------------

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
    """Flag when visible link text implies one domain but URL points to another."""
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


# ---------------------------------------------------------
# 7. DOMAIN / TYPO / IMPERSONATION DETECTORS
# ---------------------------------------------------------

def detect_typosquatting(domains: Iterable[str]) -> List[Dict[str, str]]:
    """Identify potential typosquatting through homoglyphs or numeric tricks."""
    findings: List[Dict[str, str]] = []
    for domain in domains:
        if any(char in domain for char in HOMOGLYPHS):
            findings.append({"domain": domain, "reason": "unicode_homograph"})
        if any(num in domain for num in ["0", "1", "3", "5"]):
            findings.append({"domain": domain, "reason": "numeric_typosquatting"})
    return findings


# ---------------------------------------------------------
# 8. SIMPLE SCORE (LEGACY - superseded by calc_score.py)
# ---------------------------------------------------------

def score_email(findings: Dict[str, Union[List, Dict]]) -> Dict[str, Union[int, str]]:
    """Simple fallback risk score (legacy method)."""
    score = 0
    score += len(findings.get("suspicious_links", [])) * 2
    score += len(findings.get("risky_attachments", [])) * 2
    score += len(findings.get("header_issues", [])) * 1
    verdict = "suspicious" if score >= 3 else "review" if score else "low"
    return {"score": score, "verdict": verdict}


# ---------------------------------------------------------
# 9. EXPORTS
# ---------------------------------------------------------

__all__ = [
    "KEYWORDS",
    "URL_PATTERNS",
    "HEADER_RULES",
    "ATTACHMENT_RULES",
    "OBFUSCATION_PATTERNS",
    "SCOREMAP",
    "DESCRIPTIONS",
    "detect_suspicious_links",
    "detect_header_inconsistencies",
    "detect_attachment_risks",
    "score_email",
    "detect_anchor_redirect_mismatch",
    "detect_typosquatting",
    "detect_display_name_spoofing",
    "detect_header_forgery",
    "detect_double_extension",
    "detect_html_forms",
    "detect_clickable_images",
    "detect_social_engineering_language",
    "detect_brand_lookalike_pairing",
]
