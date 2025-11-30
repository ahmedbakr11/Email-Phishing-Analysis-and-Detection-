from typing import Any, Dict, List, Union

# Detection outputs can be lists (multiple hits) or scalar flags
FindingValue = Union[List, Dict, float, int, str, None]

# Base weights for detection categories (higher = riskier). These are aligned
# directly to the detectors defined in detection.py and to the keys used in
# the final detection output / extra_flags.
CUSTOM_SCORES: Dict[str, int] = {
    "suspicious_links": 3,
    "header_issues": 2,
    "risky_attachments": 5,
    "anchor_redirect": 4,
    "typosquatting": 4,
    "display_spoof": 5,
    "header_forgery_spf": 3,
    "header_forgery_dkim": 4,
    "header_forgery_dmarc": 2,
    "double_extension": 6,
    "html_forms": 4,
    "clickable_images": 3,
    "social_engineering": 4,
}


def _count_items(value: Any) -> int:
    """Count items in collections or treat truthy scalars as a single hit."""
    if not value:
        return 0
    if isinstance(value, (list, tuple, set)):
        return len(value)
    if isinstance(value, dict):
        return 1
    return 1


def _verdict_from_score(normalized: float) -> str:
    """Translate normalized score into a verdict label."""
    if normalized >= 75:
        return "malicious"
    if normalized >= 55:
        return "high-risk"
    if normalized >= 30:
        return "medium"
    return "low"


def compute_custom_score(detections: Dict[str, Any]) -> Dict[str, Any]:
    normalized_detections = {
        "suspicious_links": detections.get("suspicious_links") or [],
        "header_issues": detections.get("header_issues") or [],
        "risky_attachments": detections.get("risky_attachments") or [],
        "extra_flags": detections.get("extra_flags") or {},
        **detections,
    }

    extra_flags = normalized_detections["extra_flags"]

    counts: Dict[str, int] = {
        "suspicious_links": _count_items(normalized_detections.get("suspicious_links")),
        "header_issues": _count_items(normalized_detections.get("header_issues")),
        "risky_attachments": _count_items(normalized_detections.get("risky_attachments")),
        "anchor_redirect": _count_items(extra_flags.get("anchor_redirect")),
        "typosquatting": _count_items(extra_flags.get("typosquatting")),
        "display_spoof": _count_items(extra_flags.get("display_spoof")),
        "header_forgery_spf": _count_items([item for item in extra_flags.get("header_forgery", []) if item.get("method") == "SPF"]),
        "header_forgery_dkim": _count_items([item for item in extra_flags.get("header_forgery", []) if item.get("method") == "DKIM"]),
        "header_forgery_dmarc": _count_items([item for item in extra_flags.get("header_forgery", []) if item.get("method") == "DMARC"]),
        "double_extension": _count_items(extra_flags.get("double_extension")),
        "html_forms": _count_items(extra_flags.get("html_forms")),
        "clickable_images": _count_items(extra_flags.get("clickable_images")),
        "social_engineering": _count_items(extra_flags.get("social_engineering")),
    }

    detail: Dict[str, Dict[str, Union[int, float]]] = {}
    raw_score = 0.0
    for category, weight in CUSTOM_SCORES.items():
        count = counts.get(category, 0)
        subtotal = count * weight
        raw_score += subtotal
        detail[category] = {"count": count, "weight": weight, "subtotal": subtotal}

    theoretical_max = sum(weight * 5 for weight in CUSTOM_SCORES.values()) + 10.0
    normalized = 0.0
    if theoretical_max > 0:
        normalized = min(100.0, (raw_score / theoretical_max) * 100.0)

    verdict = _verdict_from_score(normalized)

    return {
        "score": round(normalized, 2),
        "verdict": verdict,
        "detail": detail,
    }


def run_scoring_pipeline(detection_output: Dict[str, Any]) -> Dict[str, Any]:
    normalized_input = {
        "suspicious_links": detection_output.get("suspicious_links") or [],
        "header_issues": detection_output.get("header_issues") or [],
        "risky_attachments": detection_output.get("risky_attachments") or [],
        "extra_flags": detection_output.get("extra_flags") or {},
        **detection_output,
    }
    return compute_custom_score(normalized_input)


__all__ = ["CUSTOM_SCORES", "compute_custom_score", "run_scoring_pipeline"]
