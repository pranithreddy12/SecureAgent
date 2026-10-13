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

# Key names are matched as *words*, not substrings: `author`, `author_url`, `passport` and
# `tokenizer_name` are not credentials although they contain "auth", "pass" or "token".
_SECRET_WORDS = frozenset(
    {
        "password", "passwd", "pwd", "pass", "passphrase", "secret", "secrets", "token", "tokens",
        "apikey", "credential", "credentials", "cred", "creds", "privatekey", "authorization",
        "auth",
    }
)  # fmt: skip
_SECRET_PAIRS = frozenset(
    {
        ("api", "key"), ("access", "key"), ("private", "key"), ("secret", "key"),
        ("client", "secret"), ("auth", "token"), ("auth", "key"), ("bearer", "token"),
        ("signing", "key"), ("encryption", "key"), ("master", "key"),
    }
)  # fmt: skip
_WORD_SPLIT = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")


def key_looks_secret(key: str) -> bool:
    words = [w.lower() for w in _WORD_SPLIT.findall(key)]
    if any(w in _SECRET_WORDS for w in words):
        return True
    return any(pair in _SECRET_PAIRS for pair in zip(words, words[1:], strict=False))


# key = "value" / key: "value" / "key": "value"  (captures the quoted value)
ASSIGNMENT = re.compile(
    r"""(?P<key>[A-Za-z0-9_.\-]{2,64})\s*[:=]\s*['"](?P<val>[^'"\n]{6,512})['"]"""
)

# Placeholder / reference values that are not real leaked secrets.
_PLACEHOLDER = re.compile(
    r"(?i)^(x+|\*+|\.+|changeme|change_me|your[_-].*|my[_-].*|example.*|sample.*|"
    r"test.*|dummy.*|placeholder.*|none|null|true|false|\d+|redacted|xxx+|"
    r"\$\{.*\}|\{.*\}|<.*>|%.*%|%[sd])$"
)
# Literal option values that share a name with secrets (e.g. fetch `credentials: "same-origin"`,
# OAuth `token_type = "bearer"`); they are configuration words, never credentials.
_BENIGN_VALUES = frozenset(
    {"same-origin", "include", "omit", "bearer", "basic", "cors", "no-cors", "anonymous"}
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
    gitignored: bool = False  # the file is ignored by git: local, not committed

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


_ENV_VAR_NAME = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")  # SECUREAGENT_ADMIN_PASSWORD
# Words that mark a value as a stand-in (whsec_fake, dummy-key, example-token ...).
_FAKE_WORDS = ("fake", "dummy", "example", "placeholder", "changeme", "change-me", "redacted")
_URL_NO_USERINFO = re.compile(r"(?i)^(?:https?|wss?|ftp)://[^/@\s]+(?:/[^\s@]*)?$")
# A client-side build variable (public by design) holding a Google/Firebase web key.
_CLIENT_PUBLIC = re.compile(
    r"(?i)(FIREBASE|NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_)"
)


def _is_placeholder(value: str) -> bool:
    v = value.strip()
    if _PLACEHOLDER.match(v) or _ENV_REFERENCE.search(v) or v.lower() in _BENIGN_VALUES:
        return True
    if _ENV_VAR_NAME.match(v):
        return True  # the *name* of a variable (PASSWORD_ENV = "APP_PASSWORD"), not a value
    if any(w in v.lower() for w in _FAKE_WORDS):
        return True
    if _URL_NO_USERINFO.match(v):
        return True  # a plain URL (author_url, redirect_uri) carries no credential
    return len(set(v)) <= 2  # e.g. "aaaaaa", "------"


# A secret that falls back to a literal when the environment variable is unset:
#   os.environ.get("SECRET_KEY", "dev-only")   os.getenv("JWT_SECRET", "x")   process.env.KEY || "x"
_FALLBACK = re.compile(
    r"""(?x)
    (?:(?:os\.)?(?:environ\.get|getenv)\(\s*["'](?P<k1>[A-Za-z0-9_.-]+)["']\s*,\s*["'](?P<v1>[^"'\s]{4,})["']\s*\)
      |process\.env\.(?P<k2>[A-Za-z0-9_]+)\s*(?:\|\||\?\?)\s*["'](?P<v2>[^"'\s]{4,})["'])
    """
)


def scan_text(relpath: str, text: str) -> list[SecretFinding]:
    """Return secret findings for one file's text. Pure; no I/O."""
    findings: list[SecretFinding] = []
    seen: set[tuple[str, str]] = set()  # (rule, fingerprint) de-dup within a file

    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > 4000:  # minified / data line: skip to avoid noise and cost
            continue

        for rule in PROVIDER_RULES:
            for m in rule.pattern.finditer(line):
                name, severity = rule.name, rule.severity
                if rule.name == "Google API key" and _CLIENT_PUBLIC.search(line):
                    # Firebase/Google *web* keys ship in client bundles by design; restrict them
                    # by HTTP referrer and API, but they are not server secrets.
                    name, severity = "Google API key (client-side)", "low"
                _add(
                    findings,
                    seen,
                    name,
                    severity,
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

        # Fallback literal for a secret-named environment variable: deployed without the variable,
        # the application silently runs with a public, guessable secret.
        prose = relpath.endswith((".md", ".rst", ".txt")) or line.lstrip().startswith(
            ("#", "//", "*", "/*")
        )  # documentation and comments describe the pattern; they are not code that runs
        for m in () if prose else _FALLBACK.finditer(line):
            key = m.group("k1") or m.group("k2")
            val = m.group("v1") or m.group("v2")
            if not key_looks_secret(key) or _fingerprint(val) in provider_fps:
                continue
            fake = _is_placeholder(val)
            _add(
                findings,
                seen,
                f"Hardcoded fallback for secret ({key})",
                "low" if fake else "medium",
                0.5 if fake else 0.7,
                relpath,
                lineno,
                val,
            )

        # Generic: a secret-named key assigned a non-placeholder, high-entropy value.
        for m in ASSIGNMENT.finditer(line):
            key, val = m.group("key"), m.group("val")
            if not key_looks_secret(key) or _is_placeholder(val):
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
