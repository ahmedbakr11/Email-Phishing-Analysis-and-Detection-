"""PHASE 4 - Orchestration of the phishing email analysis pipeline."""
from pathlib import Path
from typing import Dict, List, Union

from .detection import (
    detect_anchor_redirect_mismatch,
    detect_attachment_risks,
    detect_brand_impersonation_variants,
    detect_clickable_images,
    detect_display_name_spoofing,
    detect_double_extension,
    detect_header_forgery,
    detect_header_inconsistencies,
    detect_html_forms,
    detect_risky_tlds,
    detect_social_engineering_language,
    detect_suspicious_links,
    detect_typosquatting,
)
from .calc_score import run_scoring_pipeline
from .extraction import (
    EmailBytes,
    extract_artifacts,
    extract_raw_message,
    load_email_bytes,
    load_generic_labels,
    load_impersonated_brands,
    load_malicious_extensions,
    load_risky_tlds,
    load_sus_words,
    load_trusted_domains,
)
from .parsing import (
    parse_attachment_metadata,
    parse_authentication_results,
    parse_body_content,
    parse_header_identities,
)

REFERENCE_BASE_PATH = Path(__file__).resolve().parent / "Word lists"
REFERENCE_DOMAINS_PATH = REFERENCE_BASE_PATH / "trusted_domains.txt"
REFERENCE_SUSWORD_PATH = REFERENCE_BASE_PATH / "social_engineering_phrases.txt"
REFERENCE_GENERIC_LABELS_PATH = REFERENCE_BASE_PATH / "anchor_phrases.txt"
REFERENCE_IMPERSONATED_BRANDS_PATH = REFERENCE_BASE_PATH / "impersonated_brand_keywords.txt"
REFERENCE_RISKY_TLDS_PATH = REFERENCE_BASE_PATH / "risky_top_level_domains.txt"
REFERENCE_MALICIOUS_EXT_PATH = REFERENCE_BASE_PATH / "malicious_attachment_extensions.txt"


def analyze_phishing_email(source: Union[str, Path, EmailBytes]) -> Dict[str, Union[Dict, List]]:
    """Run extraction -> parsing -> detection pipeline and return a structured report."""
    raw_bytes = load_email_bytes(source)
    headers, parts = extract_raw_message(raw_bytes)

    extraction = extract_artifacts(headers, parts)
    parsed_headers = parse_header_identities(headers)
    auth_headers = parse_authentication_results(headers)
    parsed_body = parse_body_content(parts)
    parsed_attachments = parse_attachment_metadata(parts)
    trusted_domains = load_trusted_domains(str(REFERENCE_DOMAINS_PATH))
    malicious_exts = load_malicious_extensions(str(REFERENCE_MALICIOUS_EXT_PATH))
    risky_tlds = load_risky_tlds(str(REFERENCE_RISKY_TLDS_PATH))
    brand_variants = load_impersonated_brands(str(REFERENCE_IMPERSONATED_BRANDS_PATH))
    sender_domains = [d for d in (parsed_headers.get("from_domain"), parsed_headers.get("return_domain"), parsed_headers.get("reply_domain")) if d]
    allowed_domains = list(dict.fromkeys(trusted_domains + sender_domains))
    suspicious_links = detect_suspicious_links(parsed_body["links"], allowed_domains)
    header_issues = detect_header_inconsistencies(parsed_headers)
    risky_attachments = detect_attachment_risks(parsed_attachments, malicious_exts)
    generic_labels = load_generic_labels(str(REFERENCE_GENERIC_LABELS_PATH))
    anchor_redirect = detect_anchor_redirect_mismatch(parsed_body["links"], generic_labels)
    risky_tld_links = detect_risky_tlds(parsed_body["links"], risky_tlds)
    brand_impersonation = detect_brand_impersonation_variants(parsed_headers, brand_variants)
    typo_inputs = []
    for email_value in extraction.get("raw_emails", []):
        if "@" in email_value:
            _, _, dom = email_value.partition("@")
            if dom:
                typo_inputs.append(dom.lower())
    for dom_key in ("from_domain", "return_domain", "reply_domain"):
        dom_val = parsed_headers.get(dom_key)
        if dom_val:
            typo_inputs.append(dom_val)
    typo_domains = detect_typosquatting(typo_inputs)
    display_spoof = detect_display_name_spoofing(parsed_headers)
    header_forgery = detect_header_forgery(auth_headers)
    double_ext = detect_double_extension(parsed_attachments)
    html_forms = detect_html_forms(parsed_body["html"])
    clickable_images = detect_clickable_images(parsed_body["html"])
    sus_word = load_sus_words(str(REFERENCE_SUSWORD_PATH))
    suslang = detect_social_engineering_language(parsed_body["text"], sus_word)

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
            "brand_impersonation_variants": brand_impersonation,
            "risky_tlds": risky_tld_links,
        },
    }

    # run scoring
    try:
        score_info = run_scoring_pipeline(full_detection)
    except Exception:
        score_info = {"score": 0.0, "verdict": "low", "detail": {}}
    full_detection["score"] = score_info


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


__all__ = ["analyze_phishing_email"]
