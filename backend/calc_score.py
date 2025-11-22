from typing import Any, Dict, List, Union


# -----------------------------------------------------
# 1. Scoring Weights Configuration
# -----------------------------------------------------

FindingValue = Union[List, Dict, float, int, str, None]

CUSTOM_SCORES: Dict[str, int] = {
    "suspicious_links": 2,
    "header_issues": 3,
    "risky_attachments": 12,
    "anchor_redirect": 8,
    "typosquatting": 3,
    "display_spoof": 8,
    "header_forgery_spf": 3,
    "header_forgery_dkim": 4,
    "header_forgery_dmarc": 3,
    "double_extension": 12,
    "html_forms": 8,
    "clickable_images": 5,
    "social_engineering": 7,
    "brand_lookalike": 9,
}


# -----------------------------------------------------
# 2. Utility: Count Detection Hits
# -----------------------------------------------------

def _count_items(value: Any) -> int:
    """Count items in lists/dicts or treat truthy scalar values as one hit."""
    if not value:
        return 0
    if isinstance(value, (list, tuple, set)):
        return len(value)
    if isinstance(value, dict):
        return 1
    return 1


# -----------------------------------------------------
# 3. Utility helpers for filtering
# -----------------------------------------------------

def _filter_auth_failures(findings: Any) -> List[Dict[str, Any]]:
    """Ignore missing/neutral auth results and keep only real failures."""
    if not findings:
        return []

    filtered: List[Dict[str, Any]] = []
    fail_terms = ("fail", "softfail", "permerror", "temperror")
    ignore_terms = ("none", "neutral")

    for item in findings:
        if not isinstance(item, dict):
            continue
        method = item.get("method")
        reason = str(item.get("reason") or "").lower()

        if not method:
            continue
        if any(term in reason for term in ignore_terms):
            continue
        if not any(term in reason for term in fail_terms):
            continue

        filtered.append(item)

    return filtered


def _filter_typosquatting(findings: Any) -> List[Dict[str, Any]]:
    """Drop typosquatting hits that belong to trusted Microsoft-operated domains."""
    if not findings:
        return []

    filtered: List[Dict[str, Any]] = []
    trusted_suffixes = ("outlook.com", "office.com", "microsoft.com")

    for item in findings:
        if not isinstance(item, dict):
            continue

        domain = str(item.get("domain") or "").lower()
        if not domain:
            continue

        if (
            domain == "ms"
            or domain.endswith(".ms")
            or any(domain.endswith(suffix) for suffix in trusted_suffixes)
        ):
            continue

        filtered.append(item)

    return filtered


# -----------------------------------------------------
# 4. Utility: Map Numeric Score to Verdict Label
# -----------------------------------------------------

def _verdict_from_score(normalized: float) -> str:
    """Return a human-readable verdict based on normalized score."""
    if normalized >= 60:
        return "malicious"
    if normalized >= 40:
        return "high-risk"
    if normalized >= 20:
        return "medium"
    return "low"


def _has_high_risk_override(normalized: Dict[str, Any], counts: Dict[str, int]) -> bool:
    """Detect high-confidence malicious patterns that should force a malicious verdict."""
    extra_flags = normalized.get("extra_flags") or {}
    risky_exts = {".exe", ".js", ".scr", ".bat", ".cmd"}
    attachments = normalized.get("risky_attachments") or []

    has_exec_attachment = any(
        isinstance(att, dict)
        and any(str(att.get("filename", "")).lower().endswith(ext) for ext in risky_exts)
        for att in attachments
    )

    header_forgery = extra_flags.get("header_forgery") or []
    auth_failures = _filter_auth_failures(header_forgery)

    has_spf_fail = any(item.get("method") == "SPF" for item in auth_failures)
    has_dkim_fail = any(item.get("method") == "DKIM" for item in auth_failures)

    high_risk_signals = [
        counts.get("double_extension", 0) > 0,
        has_exec_attachment,
        counts.get("html_forms", 0) > 0,
        counts.get("anchor_redirect", 0) > 0,
        has_spf_fail and has_dkim_fail,
        counts.get("suspicious_links", 0) >= 4 and counts.get("social_engineering", 0) >= 1,
    ]

    return sum(1 for flag in high_risk_signals if flag) >= 2


# -----------------------------------------------------
# 5. Core Scoring Logic
# -----------------------------------------------------

def compute_custom_score(detections: Dict[str, Any]) -> Dict[str, Any]:
    """
    Core scoring engine.
    Weights each detection category, sums results, normalizes 0-100,
    and derives a verdict label.
    """

    normalized = {
        "suspicious_links": detections.get("suspicious_links") or [],
        "header_issues": detections.get("header_issues") or [],
        "risky_attachments": detections.get("risky_attachments") or [],
        "extra_flags": detections.get("extra_flags") or {},
        **detections,
    }

    extra_flags = normalized["extra_flags"]

    filtered_typos = _filter_typosquatting(extra_flags.get("typosquatting"))
    auth_failures = _filter_auth_failures(extra_flags.get("header_forgery"))

    counts: Dict[str, int] = {
        "suspicious_links": _count_items(normalized.get("suspicious_links")),
        "header_issues": _count_items(normalized.get("header_issues")),
        "risky_attachments": _count_items(normalized.get("risky_attachments")),

        "anchor_redirect": _count_items(extra_flags.get("anchor_redirect")),
        "typosquatting": _count_items(filtered_typos),
        "display_spoof": _count_items(extra_flags.get("display_spoof")),

        "header_forgery_spf": _count_items([
            item for item in auth_failures if item.get("method") == "SPF"
        ]),
        "header_forgery_dkim": _count_items([
            item for item in auth_failures if item.get("method") == "DKIM"
        ]),
        "header_forgery_dmarc": _count_items([
            item for item in auth_failures if item.get("method") == "DMARC"
        ]),

        "double_extension": _count_items(extra_flags.get("double_extension")),
        "html_forms": _count_items(extra_flags.get("html_forms")),
        "clickable_images": _count_items(extra_flags.get("clickable_images")),
        "social_engineering": _count_items(extra_flags.get("social_engineering")),
        "brand_lookalike": _count_items(extra_flags.get("brand_lookalike")),
    }

    detail: Dict[str, Dict[str, Union[int, float]]] = {}
    raw_score = 0.0

    for category, weight in CUSTOM_SCORES.items():
        count = counts.get(category, 0)
        subtotal = count * weight
        raw_score += subtotal
        detail[category] = {
            "count": count,
            "weight": weight,
            "subtotal": subtotal,
        }

    theoretical_max = sum(CUSTOM_SCORES.values()) * 1.2
    normalized_score = 0.0

    if theoretical_max > 0:
        normalized_score = min(100.0, (raw_score / theoretical_max) * 100.0)

    if _has_high_risk_override(normalized, counts):
        normalized_score = 99.0
        verdict = "malicious"
    else:
        verdict = _verdict_from_score(normalized_score)

    return {
        "score": round(normalized_score, 2),
        "verdict": verdict,
        "detail": detail,
    }


# -----------------------------------------------------
# 6. Public Scoring API
# -----------------------------------------------------

def run_scoring_pipeline(detection_output: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes incoming detection results and feeds them into the main scorer.
    """
    normalized = {
        "suspicious_links": detection_output.get("suspicious_links") or [],
        "header_issues": detection_output.get("header_issues") or [],
        "risky_attachments": detection_output.get("risky_attachments") or [],
        "extra_flags": detection_output.get("extra_flags") or {},
        **detection_output,
    }
    return compute_custom_score(normalized)


__all__ = ["CUSTOM_SCORES", "compute_custom_score", "run_scoring_pipeline"]
