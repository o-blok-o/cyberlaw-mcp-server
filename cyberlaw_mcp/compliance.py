"""AI prompt compliance auditing and safe document inspection."""

from __future__ import annotations

import re
from pathlib import Path

from cyberlaw_mcp.scanner import redact_text, scan_text

UZ_PERSONAL_DATA_RESOURCE = """# Uzbekistan Personal Data & AI Compliance Checklist

1. **Law on Personal Data (LRU-547)**:
   - Obtain explicit consent before collecting or processing personal identifiers (PINFL, passport, phone, email).
   - Apply data minimization: strip PII before sending user prompts to external LLM APIs.
   - Cross-border transfer (Art. 15): verify recipient jurisdiction safeguards or anonymize payloads locally first.
2. **Credential & Secret Hygiene**:
   - Never embed API keys, JWTs, or payment card numbers in LLM prompts or logs.
3. **Retention & Auditability**:
   - Avoid storing raw unredacted prompts in persistent logs unless encrypted and time-bounded.
"""

OWASP_LLM_RESOURCE = """# OWASP Top 10 for LLM Applications — Quick Guardrails

- **LLM01 Prompt Injection**: Separate untrusted user data from system instructions; flag override attempts.
- **LLM02 Insecure Output Handling**: Validate and sanitize model outputs before rendering or execution.
- **LLM06 Sensitive Information Disclosure**: Run automated PII/secret redaction pre-inference.
- **LLM08 Excessive Agency**: Enforce least-privilege tool schemas and path-sandboxed file access.
"""

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("override_instructions", re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.I)),
    ("system_prompt_leak", re.compile(r"(?:reveal|print|show)\s+(?:your\s+)?system\s+prompt", re.I)),
    ("policy_bypass", re.compile(r"(?:bypass|disable|jailbreak)\s+(?:safety|policy|rules)", re.I)),
    ("override_instructions_ru", re.compile(r"игнорируй\s+(?:все\s+)?предыдущие\s+инструкции", re.I)),
    ("system_prompt_leak_ru", re.compile(r"покажи\s+(?:свой\s+)?системный\s+промпт", re.I)),
]


def audit_prompt_compliance(
    prompt: str,
    jurisdiction: str = "UZ+GDPR",
    stores_logs: bool = False,
) -> dict[str, object]:
    """Audit an AI prompt against PII leakage, prompt injection, and privacy rules."""
    scan = scan_text(prompt)
    injection_signals = [
        name for name, pattern in _INJECTION_PATTERNS if pattern.search(prompt)
    ]

    has_pii = len(scan.findings) > 0
    has_secrets = any(f.kind in {"api_key", "jwt", "credit_card"} for f in scan.findings)

    checks = [
        {
            "check": "no_unredacted_secrets",
            "passed": not has_secrets,
            "detail": "No API keys, JWTs, or payment cards found."
            if not has_secrets
            else "Sensitive credentials or payment card detected.",
        },
        {
            "check": "no_unredacted_pii",
            "passed": not has_pii,
            "detail": "No personal identifiers found."
            if not has_pii
            else f"Detected {len(scan.findings)} PII/identifier span(s).",
        },
        {
            "check": "prompt_injection_guard",
            "passed": len(injection_signals) == 0,
            "detail": "No prompt-injection phrases detected."
            if not injection_signals
            else f"Suspicious instruction-override patterns: {', '.join(injection_signals)}.",
        },
        {
            "check": "cross_border_and_logging",
            "passed": not (stores_logs and has_pii),
            "detail": "Safe logging posture."
            if not (stores_logs and has_pii)
            else f"Storing raw PII in logs violates minimization under {jurisdiction}.",
        },
    ]

    penalty = scan.risk_score + (30 * len(injection_signals)) + (15 if (stores_logs and has_pii) else 0)
    score = max(0, 100 - min(100, penalty))

    if has_secrets or injection_signals or score < 50:
        status = "FAIL"
    elif has_pii or score < 85:
        status = "WARN"
    else:
        status = "PASS"

    recommendations: list[str] = []
    if has_secrets:
        recommendations.append("Revoke exposed credentials and strip secrets before calling external LLMs.")
    if has_pii:
        recommendations.append(
            f"Run redact_pii before sending this payload ({jurisdiction} data minimization / cross-border transfer)."
        )
    if stores_logs and has_pii:
        recommendations.append("Disable raw prompt logging or persist only the redacted prompt.")
    if injection_signals:
        recommendations.append("Isolate untrusted text from system instructions and reject override attempts.")
    if not recommendations:
        recommendations.append("Prompt passes baseline privacy and security checks.")

    redaction_preview = redact_text(prompt) if has_pii else None
    return {
        "status": status,
        "score": score,
        "jurisdiction": jurisdiction,
        "stores_logs": stores_logs,
        "pii_summary": scan.to_dict(),
        "injection_signals": injection_signals,
        "compliance_checks": checks,
        "recommendations": recommendations,
        "redacted_preview": redaction_preview["redacted_text"] if redaction_preview else prompt,
    }


def extract_file_text(file_path: str, allowed_root: Path) -> str:
    """Safely extract text from a file inside allowed_root (blocks path traversal)."""
    root_resolved = allowed_root.resolve()
    raw_path = Path(file_path)
    candidate = raw_path if raw_path.is_absolute() else (root_resolved / raw_path)
    resolved = candidate.resolve()

    if not resolved.is_relative_to(root_resolved):
        raise PermissionError(
            f"Access denied: '{file_path}' escapes allowed root '{root_resolved}'."
        )
    if not resolved.is_file():
        raise FileNotFoundError(f"File not found: '{resolved}'")

    suffix = resolved.suffix.lower()
    if suffix == ".pdf":
        from pypdf import PdfReader

        reader = PdfReader(str(resolved))
        return "\n".join(page.extract_text() or "" for page in reader.pages)

    if suffix in {".txt", ".md", ".json", ".csv", ".py", ".log"}:
        return resolved.read_text(encoding="utf-8", errors="replace")

    raise ValueError(f"Unsupported file extension '{suffix}'.")
