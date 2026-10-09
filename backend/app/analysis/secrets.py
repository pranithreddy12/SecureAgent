"""Defensive secret scanner: find credentials accidentally committed to source so a
developer can rotate and remove them.

This module only *detects and redacts*. It never stores, logs, or transmits a secret
value in full: findings carry a masked preview plus a short non-reversible fingerprint
(for de-duplication), and the file/line where the developer can fix it. This mirrors
established tools such as gitleaks and detect-secrets, used defensively on code you own
or are authorized to audit.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Detectors. Each rule finds the *shape* of a committed credential. Patterns are
# intentionally high-signal to keep false positives low.
# ---------------------------------------------------------------------------

SECRET_KEYWORD = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|"
    r"client[_-]?secret|private[_-]?key|auth|credential)"
)

# key = "value" / key: "value" / "key": "value"  (captures the quoted value)
ASSIGNMENT = re.compile(
    r"""(?P<key>[A-Za-z0-9_.\-]{2,64})\s*[:=]\s*['"](?P<val>[^'"\n]{6,512})['"]"""
)

# Placeholder / reference values that are not real leaked secrets.
_PLACEHOLDER = re.compile(
    r"(?i)^(x+|\*+|\.+|changeme|change_me|your[_-].*|my[_-].*|example.*|sample.*|"
    r"test.*|dummy.*|placeholder.*|none|null|true|false|\d+|redacted|xxx+|"
    r"\$\{.*\}|<.*>|%.*%)$"
)
_ENV_REFERENCE = re.compile(r"(?i)(os\.getenv|os\.environ|process\.env|getenv\(|ENV\[)")


@dataclass(frozen=True)
class SecretRule:
    name: str
    severity: str  # critical|high|medium|low
    pattern: re.Pattern[str]
    confidence: float


# Provider-specific, high-confidence signatures (public key-ID prefixes, not secrets).
PROVIDER_RULES: list[SecretRule] = [
    SecretRule(
        "Private key block",
        "critical",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        0.98,
    ),
    SecretRule("AWS access key id", "high", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0.95),
    SecretRule("Google API key", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 0.9),
    SecretRule(
        "GitHub token",
        "high",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b|github_pat_[0-9A-Za-z_]{22,}"),
        0.95,
    ),
    SecretRule("Slack token", "high", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), 0.9),
    SecretRule(
        "Stripe secret key", "high", re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"), 0.9
    ),
    SecretRule("Twilio key", "high", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), 0.8),
    SecretRule(
        "JSON Web Token",
        "medium",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        0.6,
    ),
]

ENTROPY_MIN_LEN = 20
ENTROPY_THRESHOLD = 3.6  # Shannon bits/char; base64-ish secrets sit well above this


@dataclass(frozen=True)
class SecretFinding:
    rule: str
    severity: str
    confidence: float
    relpath: str
    line: int
    redacted: str
    fingerprint: str  # non-reversible, for de-duplication only

    @property
    def title(self) -> str:
        return f"Hardcoded secret: {self.rule}"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(value: str) -> str:
    """Mask a secret for safe display: keep only the first/last 2 chars and the length."""
    v = value.strip()
    if len(v) <= 8:
        return f"{'•' * len(v)} (len {len(v)})"
    return f"{v[:2]}{'•' * 10}{v[-2:]} (len {len(v)})"


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def _is_placeholder(value: str) -> bool:
    v = value.strip()
    if _PLACEHOLDER.match(v) or _ENV_REFERENCE.search(v):
        return True
    return len(set(v)) <= 2  # e.g. "aaaaaa", "------"


def scan_text(relpath: str, text: str) -> list[SecretFinding]:
    """Return secret findings for one file's text. Pure; no I/O."""
    findings: list[SecretFinding] = []
    seen: set[tuple[str, str]] = set()  # (rule, fingerprint) de-dup within a file

    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > 4000:  # minified / data line: skip to avoid noise and cost
            continue

        for rule in PROVIDER_RULES:
            for m in rule.pattern.finditer(line):
                _add(
                    findings,
                    seen,
                    rule.name,
                    rule.severity,
                    rule.confidence,
                    relpath,
                    lineno,
                    m.group(0),
                )

        # A specific provider match on this line already explains the value, so the generic
        # rule must not report the same secret a second time.
        provider_fps = {
            _fingerprint(m.group(0)) for rule in PROVIDER_RULES for m in rule.pattern.finditer(line)
        }

        # Generic: a secret-named key assigned a non-placeholder, high-entropy value.
        for m in ASSIGNMENT.finditer(line):
            key, val = m.group("key"), m.group("val")
            if not SECRET_KEYWORD.search(key) or _is_placeholder(val):
                continue
            if _fingerprint(val) in provider_fps:
                continue
            if any(c.isspace() for c in val):
                continue  # real credentials are tokens, not phrases (cuts natural-language FPs)
            if len(val) >= ENTROPY_MIN_LEN and shannon_entropy(val) < ENTROPY_THRESHOLD:
                continue  # long but low-entropy (e.g. a sentence) -> probably not a key
            conf = 0.75 if len(val) >= ENTROPY_MIN_LEN else 0.6
            _add(
                findings,
                seen,
                f"Hardcoded credential ({key})",
                "medium",
                conf,
                relpath,
                lineno,
                val,
            )

    return findings


def _add(findings, seen, rule, severity, confidence, relpath, line, value):
    fp = _fingerprint(value)
    if (rule, fp) in seen:
        return
    seen.add((rule, fp))
    findings.append(
        SecretFinding(
            rule=rule,
            severity=severity,
            confidence=confidence,
            relpath=relpath,
            line=line,
            redacted=redact(value),
            fingerprint=fp,
        )
    )
