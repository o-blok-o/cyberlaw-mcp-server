"""Deterministic PII, secret, and Uzbekistan/GDPR identifier scanner."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Callable

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 35,
    "high": 25,
    "medium": 15,
    "low": 8,
}

SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


@dataclass(frozen=True)
class Finding:
    """Single detected PII or secret span."""

    kind: str
    value_masked: str
    start: int
    end: int
    severity: str
    rule: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ScanResult:
    """Aggregated scan result with normalized risk score and severity level."""

    findings: list[Finding]
    risk_score: int
    risk_level: str

    def to_dict(self) -> dict[str, object]:
        return {
            "findings": [item.to_dict() for item in self.findings],
            "findings_count": len(self.findings),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
        }


def _luhn_valid(digits: str) -> bool:
    """Return True if a numeric string satisfies the Luhn checksum."""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _mask_value(raw: str, kind: str) -> str:
    """Mask sensitive value while keeping minimal debugging context."""
    if kind == "email" and "@" in raw:
        local, domain = raw.split("@", 1)
        prefix = local[:2] if len(local) >= 2 else local[:1]
        return f"{prefix}***@{domain}"
    if len(raw) <= 6:
        return "*" * len(raw)
    return f"{raw[:3]}***{raw[-3:]}"


def _validate_card(match: re.Match[str], _text: str) -> bool:
    digits = re.sub(r"[\s-]", "", match.group(0))
    return _luhn_valid(digits)


def _validate_ipv4(match: re.Match[str], _text: str) -> bool:
    ip = match.group(0)
    if ip in {"127.0.0.1", "0.0.0.0"}:
        return False
    octets = ip.split(".")
    return len(octets) == 4 and all(0 <= int(part) <= 255 for part in octets)


def _has_context(keywords: tuple[str, ...]) -> Callable[[re.Match[str], str], bool]:
    def _validator(match: re.Match[str], text: str) -> bool:
        window_start = max(0, match.start() - 40)
        window_end = min(len(text), match.end() + 25)
        snippet = text[window_start:window_end].lower()
        return any(kw in snippet for kw in keywords)

    return _validator


_DetectorSpec = tuple[str, str, str, re.Pattern[str], Callable[[re.Match[str], str], bool] | None]

_DETECTORS: list[_DetectorSpec] = [
    (
        "api_key",
        "critical",
        "SECRET-API-KEY",
        re.compile(
            r"\b(?:sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|ghp_[A-Za-z0-9]{30,})\b"
            r"|Bearer\s+[A-Za-z0-9._-]{20,}"
        ),
        None,
    ),
    (
        "jwt",
        "high",
        "SECRET-JWT-TOKEN",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        None,
    ),
    (
        "credit_card",
        "critical",
        "PCI-LUHN-CARD",
        re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
        _validate_card,
    ),
    (
        "pinfl_uz",
        "high",
        "UZ-PINFL-ID",
        re.compile(r"\b[3-6]\d{13}\b"),
        _has_context(("pinfl", "пинфл", "jshshir", "жшшир", "инн", "personal id")),
    ),
    (
        "passport_uz",
        "high",
        "UZ-PASSPORT-ID",
        re.compile(r"\b[A-Z]{2}\s?\d{7}\b"),
        _has_context(("passport", "паспорт", "seriya", "серия", "id:", "документ")),
    ),
    (
        "phone_uz",
        "medium",
        "UZ-PHONE",
        re.compile(r"\+998[\s\-]?\(?\d{2}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b"),
        None,
    ),
    (
        "email",
        "medium",
        "PII-EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        None,
    ),
    (
        "phone_intl",
        "medium",
        "PII-INTL-PHONE",
        re.compile(r"\+(?!998)[1-9]\d{1,2}[\s\-]?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{2,4}\b"),
        None,
    ),
    (
        "ipv4",
        "low",
        "NET-IPV4",
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        _validate_ipv4,
    ),
]


def _compute_risk_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def scan_text(text: str) -> ScanResult:
    """Scan input text for PII, credentials, and Uzbekistan-specific identifiers."""
    candidates: list[tuple[int, int, str, str, str, str]] = []
    for kind, severity, rule, pattern, validator in _DETECTORS:
        for match in pattern.finditer(text):
            if validator is not None and not validator(match, text):
                continue
            raw = match.group(0).strip()
            if not raw:
                continue
            start = match.start()
            end = start + len(raw)
            candidates.append((start, end, kind, severity, rule, raw))

    # Highest severity first, then earliest start, then longest span
    candidates.sort(key=lambda item: (-SEVERITY_ORDER[item[3]], item[0], -(item[1] - item[0])))

    accepted: list[tuple[int, int, str, str, str, str]] = []
    for item in candidates:
        s, e = item[0], item[1]
        if any(not (e <= acc_s or s >= acc_e) for acc_s, acc_e, *_ in accepted):
            continue
        accepted.append(item)

    accepted.sort(key=lambda item: item[0])
    findings = [
        Finding(
            kind=kind,
            value_masked=_mask_value(raw, kind),
            start=start,
            end=end,
            severity=severity,
            rule=rule,
        )
        for start, end, kind, severity, rule, raw in accepted
    ]

    raw_score = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    risk_score = min(100, raw_score)
    return ScanResult(
        findings=findings,
        risk_score=risk_score,
        risk_level=_compute_risk_level(risk_score),
    )


def redact_text(text: str) -> dict[str, object]:
    """Deterministically replace detected PII and secrets with typed placeholders."""
    result = scan_text(text)
    if not result.findings:
        return {
            "redacted_text": text,
            "replacements_count": 0,
            "types_found": [],
            "placeholder_map_summary": {},
        }

    counters: dict[str, int] = {}
    value_to_placeholder: dict[tuple[str, str], str] = {}
    chunks: list[str] = []
    cursor = 0

    for finding in result.findings:
        raw_value = text[finding.start : finding.end]
        key = (finding.kind, raw_value)
        if key not in value_to_placeholder:
            counters[finding.kind] = counters.get(finding.kind, 0) + 1
            value_to_placeholder[key] = f"[{finding.kind.upper()}_{counters[finding.kind]}]"
        placeholder = value_to_placeholder[key]
        chunks.append(text[cursor : finding.start])
        chunks.append(placeholder)
        cursor = finding.end

    chunks.append(text[cursor:])
    return {
        "redacted_text": "".join(chunks),
        "replacements_count": len(result.findings),
        "types_found": sorted(counters.keys()),
        "placeholder_map_summary": counters,
    }
