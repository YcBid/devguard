"""Secret detection rules and false-positive filtering for DevGuard.

All checks run 100% locally using regular expressions and basic heuristics.
Matched secret values are never stored or transmitted.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Optional

SEVERITY_LEVELS: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
}


@dataclass(frozen=True)
class Rule:
    """Represents a single secret-detection rule."""

    id: str
    description: str
    severity: str
    pattern: re.Pattern[str]
    remediation: str
    secret_group: int = 0
    check_placeholder: bool = False
    min_entropy: float = 0.0


# Inline comment markers that tell DevGuard to intentionally skip a line.
INLINE_IGNORE_PATTERN: re.Pattern[str] = re.compile(
    r"(?:#|//|/\*|--)\s*(?:devguard:\s*ignore|noqa:\s*devguard|pragma:\s*allowlist\s+secret)",
    re.IGNORECASE,
)

# Common placeholder words and patterns that indicate a dummy value in docs/configs.
PLACEHOLDER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?i)^(?:your[_-]?.*|example[_-]?.*|sample[_-]?.*|dummy[_-]?.*|"
        r"fake[_-]?.*|test[_-]?.*|placeholder.*|changeme.*|change[_-]?this.*|"
        r"replace[_-]?me.*|insert[_-]?.*|todo.*|fixme.*|none|null|undefined|"
        r"true|false|empty|default|secret|password|api[_-]?key|token)$"
    ),
    # Environment variable interpolations like ${API_KEY}, $API_KEY, {{SECRET}}, <API_KEY>
    re.compile(r"^(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^}]+\}\}|<[^>]+>|%[A-Za-z0-9_]+%)$"),
    # Masked strings like ******** or xxxxxxxxxxxxxxxx or ----------------
    re.compile(r"^([*xX#._\-01])\1{7,}$"),
)

# Code patterns on the line that show the value comes from an environment lookup or config call
ENV_LOOKUP_PATTERN: re.Pattern[str] = re.compile(
    r"(?i)(?:os\.environ|os\.getenv|process\.env|dotenv|ENV\[|System\.getenv|viper\.Get|config\.get\s*\()",
)


def shannon_entropy(text: str) -> float:
    """Calculate the Shannon entropy (randomness) of a string in bits per character."""
    if not text:
        return 0.0
    length = len(text)
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def has_inline_ignore(line: str) -> bool:
    """Return True if the line contains an inline ignore comment for DevGuard."""
    return bool(INLINE_IGNORE_PATTERN.search(line))


def is_likely_false_positive(line: str, candidate_value: str, min_entropy: float = 0.0) -> bool:
    """Check whether a matched generic secret value is actually a safe placeholder or env reference."""
    if ENV_LOOKUP_PATTERN.search(line):
        return True

    cleaned = candidate_value.strip().strip("'\"`;, ")
    if not cleaned:
        return True

    for pattern in PLACEHOLDER_PATTERNS:
        if pattern.search(cleaned):
            return True

    # Also reject if the cleaned value contains obvious placeholder substrings
    lower_val = cleaned.lower()
    obvious_markers = (
        "your_api_key",
        "your-api-key",
        "your_secret",
        "your-secret",
        "your_token",
        "your-token",
        "your_password",
        "your-password",
        "example_key",
        "example_secret",
        "example_token",
        "placeholder",
        "changeme",
        "replace_with",
        "put_your_",
    )
    if any(marker in lower_val for marker in obvious_markers):
        return True

    # Reject values that look like file paths or URLs without credentials
    if cleaned.startswith(("/", "./", "../", "http://", "https://")):
        return True

    if min_entropy > 0.0 and shannon_entropy(cleaned) < min_entropy:
        return True

    return False


RULE_DEFINITIONS: tuple[Rule, ...] = (
    Rule(
        id="private-key",
        description="PEM or OpenSSH private key block header",
        severity="high",
        pattern=re.compile(
            r"-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY(?:\s+BLOCK)?-----"
        ),
        remediation="Remove the private key file from the repository, revoke the key pair, and add *.pem / *.key to .gitignore.",
    ),
    Rule(
        id="aws-access-key",
        description="AWS Access Key ID (AKIA or ASIA prefix)",
        severity="high",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        remediation="Deactivate or rotate the AWS access key in IAM immediately and load credentials via IAM roles or environment variables.",
    ),
    Rule(
        id="aws-secret-key",
        description="AWS Secret Access Key assignment",
        severity="high",
        pattern=re.compile(
            r"(?i)\baws[_-]?(?:secret[_-]?(?:access[_-]?)?key|secret)\b"
            r"\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"
        ),
        remediation="Rotate the AWS Secret Access Key in AWS IAM and store secrets in AWS Secrets Manager or environment variables.",
        secret_group=1,
        check_placeholder=True,
        min_entropy=3.0,
    ),
    Rule(
        id="github-token",
        description="GitHub personal, OAuth, app, or fine-grained access token",
        severity="high",
        pattern=re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,})\b"
        ),
        remediation="Revoke the token in GitHub Settings > Developer settings and use GitHub Actions secrets or environment variables instead.",
    ),
    Rule(
        id="slack-token",
        description="Slack bot, user, workspace, or app token",
        severity="high",
        pattern=re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
        remediation="Revoke the Slack token in your Slack App management dashboard and move it to environment variables.",
    ),
    Rule(
        id="stripe-api-key",
        description="Stripe live secret or restricted API key",
        severity="high",
        pattern=re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b"),
        remediation="Roll the live API key in the Stripe Dashboard immediately and load it from an environment variable.",
    ),
    Rule(
        id="google-api-key",
        description="Google Cloud / Firebase API key",
        severity="high",
        pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        remediation="Regenerate the API key in Google Cloud Console, restrict its API/referrer scope, and load it from the environment.",
    ),
    Rule(
        id="openai-api-key",
        description="OpenAI or compatible sk- API secret key",
        severity="high",
        pattern=re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}\b"),
        remediation="Revoke the API key in your provider dashboard and read OPENAI_API_KEY from environment variables.",
    ),
    Rule(
        id="database-url-credentials",
        description="Database connection URI with embedded username and password",
        severity="high",
        pattern=re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps)"
            r"://[^/\s:@'\"<>]+:([^@\s/'\"<>]{4,})@[^/\s'\"<>]+"
        ),
        remediation="Remove credentials from the connection string and inject the database URL or password via environment variables.",
        secret_group=1,
        check_placeholder=True,
        min_entropy=1.5,
    ),
    Rule(
        id="jwt-token",
        description="JSON Web Token (JWT) with header, payload, and signature",
        severity="medium",
        pattern=re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
        remediation="Do not hardcode signed JWTs in source files; generate short-lived tokens dynamically at runtime or during tests.",
    ),
    Rule(
        id="generic-api-key",
        description="Generic API key, secret key, or access token assignment",
        severity="medium",
        pattern=re.compile(
            r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?token)\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-\/+=]{16,})['\"]?"
        ),
        remediation="Move the API key or token to a local .env file or secret manager and read it via environment variables.",
        secret_group=1,
        check_placeholder=True,
        min_entropy=2.5,
    ),
    Rule(
        id="generic-password",
        description="Hardcoded password or passphrase assignment",
        severity="medium",
        pattern=re.compile(
            r"(?i)\b(?:password|passwd|pwd|db[_-]?pass(?:word)?|admin[_-]?pass(?:word)?)\b"
            r"\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"
        ),
        remediation="Never hardcode passwords in source code; read passwords from environment variables or a secret manager.",
        secret_group=1,
        check_placeholder=True,
        min_entropy=2.2,
    ),
)

# Backward-compatible tuple of (rule_id, compiled_pattern) pairs.
RULES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (rule.id, rule.pattern) for rule in RULE_DEFINITIONS
)

RULE_MAP: dict[str, Rule] = {rule.id: rule for rule in RULE_DEFINITIONS}


def get_rule(rule_id: str) -> Optional[Rule]:
    """Look up a Rule by its identifier."""
    return RULE_MAP.get(rule_id)
