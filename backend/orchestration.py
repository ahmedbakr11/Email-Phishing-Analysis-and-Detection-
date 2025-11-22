"""
PHASE 4 - Orchestration of the phishing email analysis pipeline.
Handles: Extraction → Parsing → Detection → Scoring → Structured Output.
"""

from pathlib import Path
from typing import Dict, List, Union

from .extraction import (
    EmailBytes,
    extract_artifacts,
    extract_raw_message,
    load_email_bytes,
    load_generic_labels,
    load_sus_words,
    load_trusted_domains,
)
from .parsing import (
    parse_attachment_metadata,
    parse_authentication_results,
    parse_body_content,
    parse_header_identities,
)
from .detection import (
    detect_anchor_redirect_mismatch,
    detect_attachment_risks,
    detect_brand_lookalike_pairing,
    detect_clickable_images,
    detect_display_name_spoofing,
    detect_double_extension,
    detect_header_forgery,
    detect_header_inconsistencies,
    detect_html_forms,
    detect_social_engineering_language,
    detect_suspicious_links,
    detect_typosquatting,
)
from .calc_score import run_scoring_pipeline


# ---------------------------------------------------------
# 1. REFERENCE FILE PATHS
# ---------------------------------------------------------

REFERENCE_BASE_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent / "refrence files"
)

REFERENCE_DOMAINS_PATH = REFERENCE_BASE_PATH / "trusted domains.txt"
REFERENCE_SUSWORD_PATH = REFERENCE_BASE_PATH / "sus word list.txt"
REFERENCE_GENERIC_LABELS_PATH = REFERENCE_BASE_PATH / "generic anchor labels.txt"


# ---------------------------------------------------------
# 2. CORE ORCHESTRATOR: FULL PIPELINE EXECUTION
# ---------------------------------------------------------

def analyze_phishing_email(
    source: Union[str, Path, EmailBytes]
) -> Dict[str, Union[Dict, List]]:
    """Run extraction → parsing → detection → scoring and return a structured report."""

    # 1) Extract raw bytes & MIME structure
    raw_bytes = load_email_bytes(source)
    headers, parts = extract_raw_message(raw_bytes)

    # 2) Extraction / raw artifacts
    extraction = extract_artifacts(headers, parts)

    # 3) Parse structured fields
    parsed_headers = parse_header_identities(headers)
    auth_headers = parse_authentication_results(headers)
    parsed_body = parse_body_content(parts)
    parsed_attachments = parse_attachment_metadata(parts)

    # 4) Load reference data
    trusted_domains = load_trusted_domains(str(REFERENCE_DOMAINS_PATH))
    generic_labels = load_generic_labels(str(REFERENCE_GENERIC_LABELS_PATH))
    sus_words = load_sus_words(str(REFERENCE_SUSWORD_PATH))

    # 5) Build domain allowlist (trusted + sender)
    sender_domains = [
        d
        for d in (
            parsed_headers.get("from_domain"),
            parsed_headers.get("return_domain"),
            parsed_headers.get("reply_domain"),
        )
        if d
    ]
    allowed_domains = list(dict.fromkeys(trusted_domains + sender_domains))

    # 6) Detection: direct findings
    suspicious_links = detect_suspicious_links(parsed_body["links"], allowed_domains)
    header_issues = detect_header_inconsistencies(parsed_headers)
    risky_attachments = detect_attachment_risks(parsed_attachments)

    # 7) Detection: extra flags
    anchor_redirect = detect_anchor_redirect_mismatch(parsed_body["links"], generic_labels)
    display_spoof = detect_display_name_spoofing(parsed_headers)
    header_forgery = detect_header_forgery(auth_headers)
    double_ext = detect_double_extension(parsed_attachments)
    html_forms = detect_html_forms(parsed_body["html"])
    clickable_images = detect_clickable_images(parsed_body["html"])
    suslang = detect_social_engineering_language(parsed_body["text"], sus_words)
    brand_lookalike = detect_brand_lookalike_pairing(parsed_headers)

    # 8) Detection: typosquatting data aggregation
    typo_inputs = []

    # Collect from raw emails ("user@example.com" → "example.com")
    for email_value in extraction.get("raw_emails", []):
        if "@" in email_value:
            _, _, dom = email_value.partition("@")
            if dom:
                typo_inputs.append(dom.lower())

    # Collect from parsed header domains
    for dom_key in ("from_domain", "return_domain", "reply_domain"):
        dom_val = parsed_headers.get(dom_key)
        if dom_val:
            typo_inputs.append(dom_val)

    typo_domains = detect_typosquatting(typo_inputs)

    # 9) Build unified detection object
    full_detection = {
        "suspicious_links": suspicious_links,
        "header_issues": header_issues,
        "risky_attachments": risky_attachments,
        "extra_flags": {
            "anchor_redirect": anchor_redirect,
            "typosquatting": typo_domains,
            "display_spoof": display_spoof,
            "header_forgery": header_forgery,
            "double_extension": double_ext,
            "html_forms": html_forms,
            "clickable_images": clickable_images,
            "social_engineering": suslang,
            "brand_lookalike": brand_lookalike,
        },
    }

    # 10) Scoring (with fail-safe)
    try:
        score_info = run_scoring_pipeline(full_detection)
    except Exception:
        score_info = {"score": 0.0, "verdict": "low", "detail": {}}

    full_detection["score"] = score_info

    # 11) Final structured report
    return {
        "extraction": extraction,
        "parsing": {
            "headers": parsed_headers,
            "auth": auth_headers,
            "body": parsed_body,
            "attachments": parsed_attachments,
        },
        "detection": full_detection,
    }


# ---------------------------------------------------------
# 3. BACKWARD-COMPAT WRAPPER
# ---------------------------------------------------------

def build_email_profile(
    source: Union[str, Path, EmailBytes]
) -> Dict[str, Union[Dict, List, int]]:
    """Backward-compatible lightweight summary used by text_scan."""
    report = analyze_phishing_email(source)
    headers = report["parsing"]["headers"]

    # Collect unique domains
    domains = [
        headers.get(key)
        for key in ("from_domain", "return_domain", "reply_domain")
        if headers.get(key)
    ]
    domains = list(dict.fromkeys(domains))

    raw_links = report["extraction"].get("raw_links", [])
    attachments = report["extraction"].get("attachments", [])

    return {
        "headers": headers,
        "domains": domains,
        "links": len(raw_links),
        "attachment_count": len(attachments),
        "report": report,
    }


# ---------------------------------------------------------
# 4. EXPORTS
# ---------------------------------------------------------

__all__ = ["analyze_phishing_email", "build_email_profile"]
