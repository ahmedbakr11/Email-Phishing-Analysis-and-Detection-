from typing import Any, Dict

from .orchestration import analyze_phishing_email


def mail_to_bytes(mail: Any) -> bytes:
    """
    Normalize incoming mail payloads (plain text, bytes, or file-like objects) to bytes.
    """
    if mail is None:
        raise ValueError("mail payload is required")
    if isinstance(mail, bytes):
        return mail
    if isinstance(mail, bytearray):
        return bytes(mail)
    if isinstance(mail, str):
        return mail.encode("utf-8")
    read = getattr(mail, "read", None)
    if callable(read):
        data = read()
        return data.encode("utf-8") if isinstance(data, str) else bytes(data or b"")
    raise TypeError(f"Unsupported mail payload type: {type(mail).__name__}")


def _map_verdict_to_status(verdict: str) -> str:
    mapping = {
        "low": "safe",
        "medium": "suspicious",
        "high-risk": "suspicious",
        "malicious": "malicious",
    }
    return mapping.get((verdict or "").lower(), "Uncertain")


def _build_response(report: Dict[str, Any], include_raw: bool = False) -> Dict[str, Any]:
    parsing = report.get("parsing", {}) or {}
    headers = parsing.get("headers", {}) or {}
    auth = parsing.get("auth", {}) or {}
    detection = report.get("detection", {}) or {}
    extraction = report.get("extraction", {}) or {}
    score_info = detection.get("score", {}) or {}
    verdict_raw = score_info.get("verdict") or "low"
    status = _map_verdict_to_status(verdict_raw)

    response_payload: Dict[str, Any] = {
        "sender": headers.get("from"),
        "subject": auth.get("subject"),
        "verdict": status,
        "status": status,
        "score": score_info.get("score", 0.0),
        "links": len(extraction.get("raw_links", []) or []),
        "attachments": len(extraction.get("attachments", []) or []),
        "findings": {
            "suspicious_links": detection.get("suspicious_links", []) or [],
            "header_issues": detection.get("header_issues", []) or [],
            "risky_attachments": detection.get("risky_attachments", []) or [],
            "extra_flags": detection.get("extra_flags", {}) or {},
        },
    }

    if include_raw:
        response_payload["raw_report"] = report

    return response_payload


def run_full_scan(mail_bytes: bytes, include_raw: bool = False) -> Dict[str, Any]:
    try:
        report = analyze_phishing_email(mail_bytes)
    except Exception as exc:
        return {"error": "analysis_failed", "detail": str(exc), "http_status": 500}

    payload = _build_response(report, include_raw=include_raw)
    payload["http_status"] = 200
    return payload


def text_scan(raw_bytes: Any) -> Dict[str, Any]:
    try:
        mail_bytes = mail_to_bytes(raw_bytes)
    except (TypeError, ValueError) as exc:
        return {"error": "bad input", "detail": str(exc), "http_status": 400}
    return run_full_scan(mail_bytes, include_raw=False)


def eml_scan(eml_bytes: Any) -> Dict[str, Any]:
    try:
        mail_bytes = mail_to_bytes(eml_bytes)
    except (TypeError, ValueError) as exc:
        return {"error": "bad input", "detail": str(exc), "http_status": 400}
    return run_full_scan(mail_bytes, include_raw=True)
